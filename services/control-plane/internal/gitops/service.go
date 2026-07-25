package gitops

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	workspacefiles "github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/files"
	gogit "github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	gittransport "github.com/go-git/go-git/v5/plumbing/transport"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
)

const maxCommandOutput = 4 * 1024 * 1024

type Change struct {
	Path      string `json:"path"`
	Index     byte   `json:"index"`
	Worktree  byte   `json:"worktree"`
	Staged    bool   `json:"staged"`
	Unstaged  bool   `json:"unstaged"`
	Untracked bool   `json:"untracked"`
	Conflict  bool   `json:"conflict"`
}

type Status struct {
	Branch   string   `json:"branch"`
	Ahead    int      `json:"ahead"`
	Behind   int      `json:"behind"`
	Changes  []Change `json:"changes"`
	Dirty    bool     `json:"dirty"`
	Unpushed bool     `json:"unpushed"`
}

type Checkpoint interface {
	Create(context.Context, string) (string, error)
}

type SecretScanner interface {
	Scan(context.Context, string, []string) error
	ScanBytes(...[]byte) error
	ScanTree(context.Context, string, string) error
	ScanReachable(context.Context, string, string, []string) error
	ScanRepositoryReachable(context.Context, *gogit.Repository, plumbing.Hash, []plumbing.Hash) error
}

type CredentialBroker interface {
	Credential(context.Context) ([]byte, func(), error)
}

type Service struct {
	root       string
	gitPath    string
	checkpoint Checkpoint
	scanner    SecretScanner
	remoteURL  string
	mu         sync.Mutex
}

func New(root string, checkpoint Checkpoint, scanner SecretScanner, expectedRepositories ...string) (*Service, error) {
	if len(expectedRepositories) > 1 || (len(expectedRepositories) == 1 && !validGitHubRepository(expectedRepositories[0])) {
		return nil, errors.New("expected GitHub repository is invalid")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	gitPath, err := TrustedExecutable()
	if err != nil {
		return nil, errors.New("git is not installed")
	}
	s := &Service{root: filepath.Clean(abs), gitPath: gitPath, checkpoint: checkpoint, scanner: scanner}
	if len(expectedRepositories) == 1 {
		s.remoteURL = "https://github.com/" + expectedRepositories[0] + ".git"
	}
	top, err := s.run(context.Background(), nil, nil, "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, fmt.Errorf("workspace is not a Git checkout: %w", err)
	}
	resolvedTop, err := filepath.Abs(strings.TrimSpace(string(top)))
	if err != nil || !samePath(resolvedTop, s.root) {
		return nil, errors.New("Git top-level does not match workspace root")
	}
	return s, nil
}

func (s *Service) Status(ctx context.Context) (Status, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	branchBytes, err := s.run(ctx, nil, nil, "branch", "--show-current")
	if err != nil {
		return Status{}, err
	}
	statusBytes, err := s.run(ctx, nil, nil, "status", "--porcelain=v1", "-z", "--untracked-files=all")
	if err != nil {
		return Status{}, err
	}
	status := Status{Branch: strings.TrimSpace(string(branchBytes))}
	items := bytes.Split(statusBytes, []byte{0})
	for i := 0; i < len(items); i++ {
		item := items[i]
		if len(item) < 4 {
			continue
		}
		x, y := item[0], item[1]
		path := string(item[3:])
		if (x == 'R' || x == 'C') && i+1 < len(items) {
			i++
		}
		change := Change{Path: filepath.ToSlash(path), Index: x, Worktree: y}
		change.Untracked = x == '?' && y == '?'
		change.Staged = x != ' ' && x != '?' && x != '!'
		change.Unstaged = y != ' ' && y != '!' || change.Untracked
		change.Conflict = x == 'U' || y == 'U' || (x == 'A' && y == 'A') || (x == 'D' && y == 'D')
		status.Changes = append(status.Changes, change)
	}
	status.Dirty = len(status.Changes) > 0
	if counts, countErr := s.run(ctx, nil, nil, "rev-list", "--left-right", "--count", "@{upstream}...HEAD"); countErr == nil {
		parts := strings.Fields(string(counts))
		if len(parts) == 2 {
			status.Behind, _ = strconv.Atoi(parts[0])
			status.Ahead, _ = strconv.Atoi(parts[1])
		}
	} else {
		// A branch with local commits and no upstream is still unpushed.
		if head, headErr := s.run(ctx, nil, nil, "rev-list", "--count", "HEAD"); headErr == nil {
			status.Ahead, _ = strconv.Atoi(strings.TrimSpace(string(head)))
		}
	}
	status.Unpushed = status.Ahead > 0
	return status, nil
}

func (s *Service) Diff(ctx context.Context, staged bool, path string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	args := []string{"diff", "--no-ext-diff", "--no-textconv", "--no-color", "--unified=3"}
	if staged {
		args = append(args, "--cached")
	}
	if path != "" {
		clean, err := s.cleanPath(path)
		if err != nil {
			return nil, err
		}
		args = append(args, "--", clean)
	}
	return s.run(ctx, nil, nil, args...)
}

func (s *Service) Stage(ctx context.Context, paths []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	clean, err := s.cleanPaths(paths)
	if err != nil {
		return err
	}
	tx, err := s.beginIndexSnapshot(ctx)
	if err != nil {
		return err
	}
	defer tx.close()
	if _, err := s.run(ctx, nil, tx.environment(), append([]string{"add", "--"}, clean...)...); err != nil {
		return err
	}
	treeBytes, err := s.run(ctx, nil, tx.environment(), "write-tree")
	if err != nil {
		return err
	}
	treeID := strings.TrimSpace(string(treeBytes))
	clear(treeBytes)
	if !validGitObjectID([]byte(treeID)) {
		return errors.New("Git produced an invalid staged tree")
	}
	if err := s.validateStagedPaths(ctx, tx.environment()); err != nil {
		return err
	}
	if s.scanner != nil {
		if err := s.scanner.ScanTree(ctx, s.root, treeID); err != nil {
			return fmt.Errorf("secret scan blocked staging: %w", err)
		}
	}
	if err := tx.install(); err != nil {
		return err
	}
	return nil
}

func (s *Service) Unstage(ctx context.Context, paths []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	clean, err := s.cleanPaths(paths)
	if err != nil {
		return err
	}
	_, err = s.run(ctx, nil, nil, append([]string{"restore", "--staged", "--"}, clean...)...)
	return err
}

func (s *Service) Commit(ctx context.Context, message string) (string, error) {
	return s.CommitAs(ctx, message, "", "")
}

func (s *Service) CommitAs(ctx context.Context, message, authorName, authorEmail string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	message = strings.TrimSpace(message)
	if message == "" || len(message) > 16*1024 {
		return "", fmt.Errorf("%w: commit message must be 1-16384 characters", core.ErrInvalid)
	}
	tx, err := s.beginIndexSnapshot(ctx)
	if err != nil {
		return "", err
	}
	defer tx.close()
	args := []string{}
	if authorName != "" || authorEmail != "" {
		if strings.TrimSpace(authorName) == "" || strings.TrimSpace(authorEmail) == "" || len(authorName) > 200 || len(authorEmail) > 320 || strings.ContainsAny(authorName+authorEmail, "\r\n\x00") || !strings.Contains(authorEmail, "@") {
			return "", fmt.Errorf("%w: valid author name and email are required together", core.ErrInvalid)
		}
		args = append(args, "-c", "user.name="+authorName, "-c", "user.email="+authorEmail)
	}
	treeBytes, err := s.run(ctx, nil, tx.environment(), "write-tree")
	if err != nil {
		return "", err
	}
	treeID := strings.TrimSpace(string(treeBytes))
	clear(treeBytes)
	if !validGitObjectID([]byte(treeID)) {
		return "", errors.New("Git produced an invalid commit tree")
	}
	if err := s.validateStagedPaths(ctx, tx.environment()); err != nil {
		return "", err
	}
	headBytes, err := s.run(ctx, nil, nil, "rev-parse", "--verify", "HEAD")
	if err != nil {
		return "", err
	}
	headID := strings.TrimSpace(string(headBytes))
	clear(headBytes)
	if !validGitObjectID([]byte(headID)) {
		return "", errors.New("Git HEAD is invalid")
	}
	headTreeBytes, err := s.run(ctx, nil, nil, "rev-parse", "--verify", "HEAD^{tree}")
	if err != nil {
		return "", err
	}
	headTreeID := strings.TrimSpace(string(headTreeBytes))
	clear(headTreeBytes)
	if treeID == headTreeID {
		return "", fmt.Errorf("%w: no staged changes to commit", core.ErrPrecondition)
	}
	refBytes, err := s.run(ctx, nil, nil, "symbolic-ref", "-q", "HEAD")
	if err != nil {
		return "", fmt.Errorf("%w: detached HEAD requires the terminal", core.ErrPrecondition)
	}
	headRef := strings.TrimSpace(string(refBytes))
	clear(refBytes)
	if !validLocalBranchRef(headRef) {
		return "", errors.New("Git branch ref is invalid")
	}
	if s.scanner != nil {
		metadata := []byte(message + "\n" + authorName + "\n" + authorEmail + "\n" + headRef)
		scanErr := s.scanner.ScanBytes(metadata)
		clear(metadata)
		if scanErr != nil {
			return "", fmt.Errorf("secret scan blocked commit metadata: %w", scanErr)
		}
		if err := s.scanner.ScanTree(ctx, s.root, treeID); err != nil {
			return "", fmt.Errorf("secret scan blocked commit: %w", err)
		}
	}
	args = append(args, "commit-tree", treeID, "-p", headID, "-F", "-")
	commitBytes, err := s.run(ctx, strings.NewReader(message+"\n"), nil, args...)
	if err != nil {
		return "", err
	}
	commitID := strings.TrimSpace(string(commitBytes))
	clear(commitBytes)
	if !validGitObjectID([]byte(commitID)) {
		return "", errors.New("Git produced an invalid commit")
	}
	if s.scanner != nil {
		commitObject, err := s.run(ctx, nil, nil, "cat-file", "commit", commitID)
		if err != nil {
			return "", err
		}
		scanErr := s.scanner.ScanBytes(commitObject)
		clear(commitObject)
		if scanErr != nil {
			return "", fmt.Errorf("secret scan blocked commit metadata: %w", scanErr)
		}
	}
	if _, err := s.run(ctx, nil, nil, "update-ref", headRef, commitID, headID); err != nil {
		return "", fmt.Errorf("%w: Git branch changed during commit", core.ErrConflict)
	}
	return commitID, nil
}

func (s *Service) Pull(ctx context.Context, broker CredentialBroker) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if broker == nil {
		return errors.New("credential broker is required")
	}
	if s.scanner != nil {
		if err := s.scanner.Scan(ctx, s.root, nil); err != nil {
			return fmt.Errorf("secret scan blocked pull: %w", err)
		}
	}
	if s.remoteURL == "" {
		return fmt.Errorf("%w: a trusted remote is required", core.ErrPrecondition)
	}
	if err := ConfigureTrustedHTTPSForURL(s.remoteURL); err != nil {
		return err
	}
	repository, err := gogit.PlainOpenWithOptions(s.root, &gogit.PlainOpenOptions{DetectDotGit: false})
	if err != nil {
		return fmt.Errorf("open repository for authenticated pull: %w", err)
	}
	head, err := repository.Head()
	if err != nil || !head.Name().IsBranch() || !validLocalBranchRef(head.Name().String()) {
		return fmt.Errorf("%w: detached or invalid HEAD requires the terminal", core.ErrPrecondition)
	}
	worktree, err := repository.Worktree()
	if err != nil {
		return fmt.Errorf("open worktree for authenticated pull: %w", err)
	}
	auth, cleanup, err := authenticatedGitCredential(ctx, broker, s.remoteURL)
	if err != nil {
		return err
	}
	err = worktree.PullContext(ctx, &gogit.PullOptions{
		RemoteName: "origin", RemoteURL: s.remoteURL, ReferenceName: head.Name(),
		SingleBranch: true, Auth: auth, Force: false,
	})
	cleanup()
	if errors.Is(err, gogit.NoErrAlreadyUpToDate) {
		return nil
	}
	if errors.Is(err, gogit.ErrNonFastForwardUpdate) || errors.Is(err, gogit.ErrUnstagedChanges) {
		return fmt.Errorf("%w: fast-forward pull is unavailable", core.ErrPrecondition)
	}
	if err != nil {
		return errors.New("authenticated Git pull failed")
	}
	return nil
}

func (s *Service) Push(ctx context.Context, broker CredentialBroker) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if broker == nil {
		return errors.New("credential broker is required")
	}
	if s.remoteURL == "" {
		return fmt.Errorf("%w: a trusted remote is required", core.ErrPrecondition)
	}
	if err := ConfigureTrustedHTTPSForURL(s.remoteURL); err != nil {
		return err
	}
	repository, err := gogit.PlainOpenWithOptions(s.root, &gogit.PlainOpenOptions{DetectDotGit: false})
	if err != nil {
		return fmt.Errorf("open repository for authenticated push: %w", err)
	}
	head, err := repository.Head()
	if err != nil || !head.Name().IsBranch() || !validLocalBranchRef(head.Name().String()) || head.Hash().IsZero() {
		return fmt.Errorf("%w: detached or invalid HEAD requires the terminal", core.ErrPrecondition)
	}
	headRef, tip := head.Name().String(), head.Hash().String()
	if s.scanner != nil {
		refBytes := []byte(headRef)
		scanErr := s.scanner.ScanBytes(refBytes)
		clear(refBytes)
		if scanErr != nil {
			return fmt.Errorf("secret scan blocked push metadata: %w", scanErr)
		}
		remoteHashes, err := s.authenticatedRemoteHashes(ctx, repository, broker)
		if err != nil {
			return fmt.Errorf("secret scan could not establish remote history: %w", err)
		}
		if err := s.scanner.ScanRepositoryReachable(ctx, repository, plumbing.NewHash(tip), remoteHashes); err != nil {
			return fmt.Errorf("secret scan blocked push: %w", err)
		}
	}
	auth, cleanup, err := authenticatedGitCredential(ctx, broker, s.remoteURL)
	if err != nil {
		return err
	}
	err = repository.PushContext(ctx, &gogit.PushOptions{
		RemoteName: "origin", RemoteURL: s.remoteURL, Auth: auth, Force: false,
		RefSpecs: []gitconfig.RefSpec{gitconfig.RefSpec(tip + ":" + headRef)},
	})
	cleanup()
	if err != nil && !errors.Is(err, gogit.NoErrAlreadyUpToDate) {
		return errors.New("authenticated Git push failed")
	}
	branch := strings.TrimPrefix(headRef, "refs/heads/")
	if s.remoteURL != "" {
		if _, err := s.run(ctx, nil, nil, "update-ref", "refs/remotes/origin/"+branch, tip); err != nil {
			return fmt.Errorf("push succeeded but remote tracking could not be recorded: %w", err)
		}
	}
	if _, err := s.run(ctx, nil, nil, "branch", "--set-upstream-to=origin/"+branch, "--", branch); err != nil {
		return fmt.Errorf("push succeeded but upstream tracking could not be recorded: %w", err)
	}
	return nil
}

func authenticatedGitCredential(ctx context.Context, broker CredentialBroker, remoteURL string) (*githttp.BasicAuth, func(), error) {
	if strings.HasPrefix(remoteURL, "file://") {
		// Local bare repositories keep transport tests hermetic. Production
		// remote URLs are constructed internally and are always HTTPS.
		return nil, func() {}, nil
	}
	credential, release, err := broker.Credential(ctx)
	if err != nil {
		return nil, nil, err
	}
	if len(credential) == 0 || len(credential) > 1024 {
		release()
		return nil, nil, errors.New("invalid GitHub installation credential")
	}
	auth := &githttp.BasicAuth{Username: "x-access-token", Password: string(credential)}
	clear(credential)
	cleanup := func() {
		auth.Password = ""
		release()
	}
	return auth, cleanup, nil
}

func (s *Service) authenticatedRemoteHashes(ctx context.Context, repository *gogit.Repository, broker CredentialBroker) ([]plumbing.Hash, error) {
	auth, cleanup, err := authenticatedGitCredential(ctx, broker, s.remoteURL)
	if err != nil {
		return nil, err
	}
	remote := gogit.NewRemote(repository.Storer, &gitconfig.RemoteConfig{
		Name: "codex-mobile-authenticated", URLs: []string{s.remoteURL},
	})
	references, err := remote.ListContext(ctx, &gogit.ListOptions{Auth: auth})
	cleanup()
	if errors.Is(err, gittransport.ErrEmptyRemoteRepository) {
		return []plumbing.Hash{}, nil
	}
	if err != nil {
		return nil, errors.New("authenticated Git reference listing failed")
	}
	if len(references) > maximumScannerObjects {
		return nil, ErrSecretScan
	}
	seen := make(map[plumbing.Hash]struct{}, len(references))
	result := make([]plumbing.Hash, 0, len(references))
	for _, reference := range references {
		hash := reference.Hash()
		if hash.IsZero() {
			continue
		}
		if _, exists := seen[hash]; !exists {
			seen[hash] = struct{}{}
			result = append(result, hash)
		}
	}
	return result, nil
}

func (s *Service) DiscardTracked(ctx context.Context, paths []string, confirmed bool) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !confirmed {
		return "", fmt.Errorf("%w: explicit discard confirmation required", core.ErrPrecondition)
	}
	if s.checkpoint == nil {
		return "", errors.New("checkpoint service is required before discard")
	}
	clean, err := s.cleanPaths(paths)
	if err != nil {
		return "", err
	}
	if _, err := s.run(ctx, nil, nil, append([]string{"ls-files", "--error-unmatch", "--"}, clean...)...); err != nil {
		return "", fmt.Errorf("%w: discard accepts tracked paths only", core.ErrInvalid)
	}
	checkpointID, err := s.checkpoint.Create(ctx, "before-git-discard")
	if err != nil {
		return "", fmt.Errorf("checkpoint before discard: %w", err)
	}
	_, err = s.run(ctx, nil, nil, append([]string{"restore", "--source=HEAD", "--staged", "--worktree", "--"}, clean...)...)
	if err != nil {
		return checkpointID, err
	}
	return checkpointID, nil
}

func (s *Service) cleanPaths(paths []string) ([]string, error) {
	if len(paths) == 0 || len(paths) > 500 {
		return nil, fmt.Errorf("%w: 1-500 paths required", core.ErrInvalid)
	}
	clean := make([]string, 0, len(paths))
	for _, path := range paths {
		item, err := s.cleanPath(path)
		if err != nil {
			return nil, err
		}
		if workspacefiles.Sensitive(item) {
			return nil, fmt.Errorf("%w: sensitive path cannot be changed through native Git", core.ErrForbidden)
		}
		clean = append(clean, item)
	}
	return clean, nil
}

func (s *Service) cleanPath(path string) (string, error) {
	if path == "" || filepath.IsAbs(path) || strings.Contains(path, "\\") || strings.ContainsRune(path, 0) {
		return "", fmt.Errorf("%w: invalid Git path", core.ErrInvalid)
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(path)))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("%w: Git path escapes workspace", core.ErrInvalid)
	}
	return clean, nil
}

func (s *Service) run(ctx context.Context, stdin io.Reader, extraEnv []string, args ...string) ([]byte, error) {
	cmd, cancel, err := newGitCommand(ctx, s.gitPath, s.root, append(gitEnv(), extraEnv...), args...)
	if err != nil {
		return nil, err
	}
	defer cancel()
	if stdin == nil {
		stdin = strings.NewReader("")
	}
	cmd.Stdin = stdin
	var output cappedBuffer
	output.max = maxCommandOutput
	defer func() { clear(output.Bytes()) }()
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Run(); err != nil {
		if errors.Is(output.err, errOutputLimit) {
			return nil, errOutputLimit
		}
		message := strings.ToLower(string(output.Bytes()))
		if strings.Contains(message, "index.lock") || strings.Contains(message, "another git process") {
			return nil, fmt.Errorf("%w: Git index is locked by another operation", core.ErrConflict)
		}
		if args[0] == "pull" && (strings.Contains(message, "not possible to fast-forward") || strings.Contains(message, "would be overwritten")) {
			return nil, fmt.Errorf("%w: fast-forward pull is unavailable", core.ErrPrecondition)
		}
		diagnostic := bytes.Clone(output.Bytes())
		defer clear(diagnostic)
		if redactor, ok := s.scanner.(interface{ Redact([]byte) []byte }); ok {
			redacted := redactor.Redact(diagnostic)
			clear(diagnostic)
			diagnostic = redacted
		}
		return nil, fmt.Errorf("git %s failed: %w: %s", args[0], err, safeError(diagnostic))
	}
	return append([]byte(nil), output.Bytes()...), nil
}

var errOutputLimit = errors.New("Git output limit exceeded")

type cappedBuffer struct {
	bytes.Buffer
	max int
	err error
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.Buffer.Len()+len(p) > b.max {
		b.err = errOutputLimit
		return 0, errOutputLimit
	}
	return b.Buffer.Write(p)
}

func gitEnv() []string {
	env := []string{
		"GIT_ATTR_NOSYSTEM=1", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_TERMINAL_PROMPT=0", "GIT_PAGER=cat", "LC_ALL=C", "LANG=C",
	}
	for _, key := range []string{"HOME", "USERPROFILE", "SystemRoot", "PATH"} {
		if value := os.Getenv(key); value != "" {
			env = append(env, key+"="+value)
		}
	}
	return env
}

func safeError(data []byte) string {
	text := strings.TrimSpace(string(data))
	if len(text) > 2048 {
		text = text[:2048] + "…"
	}
	return text
}

func samePath(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
	}
	return filepath.Clean(a) == filepath.Clean(b)
}
