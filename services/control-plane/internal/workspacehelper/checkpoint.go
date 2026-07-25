package workspacehelper

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	workspacefiles "github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/files"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/gitops"
)

const (
	CheckpointManifestName      = "_codex-mobile/manifest.json"
	MaxCheckpointArchiveBytes   = 5 << 20
	MaxCheckpointExpandedBytes  = 32 << 20
	MaxCheckpointFileBytes      = 4 << 20
	MaxCheckpointEntries        = 5000
	MaxCheckpointManifestBytes  = 64 << 10
	maxCheckpointGitOutputBytes = 4 << 20
	checkpointGitTimeout        = 30 * time.Second
	checkpointGitWaitDelay      = 2 * time.Second
	CheckpointArchiveVersion    = 2
)

type CheckpointExport struct {
	ArchiveBase64    string `json:"archive_base64"`
	ArchiveSHA256    string `json:"archive_sha256"`
	CompressedBytes  int64  `json:"compressed_bytes"`
	ExpandedBytes    int64  `json:"expanded_bytes"`
	FileCount        int    `json:"file_count"`
	OmittedSensitive int    `json:"omitted_sensitive"`
	OmittedUnsafe    int    `json:"omitted_unsafe"`
	Head             string `json:"head,omitempty"`
}

type CheckpointManifest struct {
	Version          int               `json:"version"`
	WorkspaceID      string            `json:"workspace_id"`
	Head             string            `json:"head,omitempty"`
	Entries          []CheckpointEntry `json:"entries"`
	OmittedSensitive int               `json:"omitted_sensitive"`
	OmittedUnsafe    int               `json:"omitted_unsafe"`
}

type CheckpointEntry struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256,omitempty"`
	Size      int64  `json:"size"`
	Mode      uint32 `json:"mode,omitempty"`
	Untracked bool   `json:"untracked,omitempty"`
	Deleted   bool   `json:"deleted,omitempty"`
}

type checkpointCandidate struct {
	path         string
	untracked    bool
	recordAbsent bool
}

func (h *Helper) checkpointExport(ctx context.Context, request *Request) Response {
	if !checkpointWorkspaceIDPattern.MatchString(request.CheckpointWorkspaceID) || (len(request.Paths) != 0 && !request.CheckpointForce) {
		return failure("invalid", "The checkpoint workspace identity was invalid.")
	}
	status, head, err := checkpointStatus(ctx, h.root)
	if err != nil {
		return fromError(err)
	}
	if !status.Dirty && !status.Unpushed && !request.CheckpointForce {
		return Response{Version: Version, OK: true, GitStatus: &status}
	}

	archive, manifest, err := buildCheckpointArchive(ctx, h.root, request.CheckpointWorkspaceID, head, request.Paths)
	if err != nil {
		return fromError(err)
	}
	digest := sha256.Sum256(archive)
	export := &CheckpointExport{
		ArchiveBase64: base64.StdEncoding.EncodeToString(archive),
		ArchiveSHA256: hex.EncodeToString(digest[:]), CompressedBytes: int64(len(archive)),
		OmittedSensitive: manifest.OmittedSensitive, OmittedUnsafe: manifest.OmittedUnsafe,
		Head: head,
	}
	for _, entry := range manifest.Entries {
		if !entry.Deleted {
			export.FileCount++
			export.ExpandedBytes += entry.Size
		}
	}
	return Response{Version: Version, OK: true, GitStatus: &status, Checkpoint: export}
}

func checkpointStatus(ctx context.Context, root string) (gitops.Status, string, error) {
	statusBytes, err := runCheckpointGit(ctx, root, "status", "--porcelain=v1", "-z", "--untracked-files=all")
	if err != nil {
		return gitops.Status{}, "", err
	}
	branchBytes, err := runCheckpointGit(ctx, root, "branch", "--show-current")
	if err != nil {
		return gitops.Status{}, "", err
	}
	status := gitops.Status{Branch: strings.TrimSpace(string(branchBytes)), Dirty: len(statusBytes) != 0}
	if counts, countErr := runCheckpointGit(ctx, root, "rev-list", "--left-right", "--count", "@{upstream}...HEAD"); countErr == nil {
		parts := strings.Fields(string(counts))
		if len(parts) == 2 {
			status.Behind, _ = strconv.Atoi(parts[0])
			status.Ahead, _ = strconv.Atoi(parts[1])
		}
	} else if count, countErr := runCheckpointGit(ctx, root, "rev-list", "--count", "HEAD", "--not", "--remotes"); countErr == nil {
		status.Ahead, _ = strconv.Atoi(strings.TrimSpace(string(count)))
	}
	status.Unpushed = status.Ahead > 0
	headBytes, err := runCheckpointGit(ctx, root, "rev-parse", "--verify", "HEAD")
	if err != nil {
		// An unborn repository can still contain untracked work. It has no HEAD,
		// which is represented honestly by an empty manifest field.
		if status.Dirty {
			return status, "", nil
		}
		return gitops.Status{}, "", err
	}
	head := strings.TrimSpace(string(headBytes))
	if len(head) != 40 && len(head) != 64 {
		return gitops.Status{}, "", errors.New("Git returned an invalid HEAD")
	}
	return status, head, nil
}

func buildCheckpointArchive(ctx context.Context, root, workspaceID, head string, explicitPaths ...[]string) ([]byte, CheckpointManifest, error) {
	candidates := make([]checkpointCandidate, 0)
	if len(explicitPaths) != 0 && len(explicitPaths[0]) != 0 {
		paths := explicitPaths[0]
		if len(paths) > MaxCheckpointEntries {
			return nil, CheckpointManifest{}, fmt.Errorf("checkpoint exceeds %d entries", MaxCheckpointEntries)
		}
		seen := make(map[string]bool, len(paths))
		folded := make(map[string]bool, len(paths))
		for _, requested := range paths {
			path, err := cleanCheckpointPath(requested)
			foldedPath := strings.ToLower(path)
			if err != nil || path != requested || workspacefiles.Sensitive(path) || seen[path] || folded[foldedPath] || restoreHierarchyConflict(folded, foldedPath) {
				return nil, CheckpointManifest{}, errors.New("explicit checkpoint path is unsafe")
			}
			seen[path], folded[foldedPath] = true, true
			candidates = append(candidates, checkpointCandidate{path: path, recordAbsent: true})
		}
	} else {
		tracked, err := checkpointChangedTrackedPaths(ctx, root, head)
		if err != nil {
			return nil, CheckpointManifest{}, err
		}
		untracked, err := checkpointPaths(ctx, root, true)
		if err != nil {
			return nil, CheckpointManifest{}, err
		}
		if len(tracked)+len(untracked) > MaxCheckpointEntries {
			return nil, CheckpointManifest{}, fmt.Errorf("checkpoint exceeds %d entries", MaxCheckpointEntries)
		}
		candidates = make([]checkpointCandidate, 0, len(tracked)+len(untracked))
		for _, path := range tracked {
			candidates = append(candidates, checkpointCandidate{path: path})
		}
		for _, path := range untracked {
			candidates = append(candidates, checkpointCandidate{path: path, untracked: true})
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].path < candidates[j].path })

	rootHandle, err := os.OpenRoot(root)
	if err != nil {
		return nil, CheckpointManifest{}, err
	}
	defer rootHandle.Close()

	manifest := CheckpointManifest{Version: CheckpointArchiveVersion, WorkspaceID: workspaceID, Head: head, Entries: make([]CheckpointEntry, 0, len(candidates))}
	var archiveBuffer boundedCheckpointBuffer
	archiveBuffer.limit = MaxCheckpointArchiveBytes
	archive := zip.NewWriter(&archiveBuffer)
	expanded := int64(0)
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			_ = archive.Close()
			return nil, CheckpointManifest{}, err
		}
		path, err := cleanCheckpointPath(candidate.path)
		if err != nil {
			manifest.OmittedUnsafe++
			continue
		}
		if workspacefiles.Sensitive(path) {
			manifest.OmittedSensitive++
			continue
		}
		entry, content, err := readCheckpointFile(rootHandle, path, candidate.untracked)
		if errors.Is(err, os.ErrNotExist) {
			if !candidate.untracked || candidate.recordAbsent {
				manifest.Entries = append(manifest.Entries, CheckpointEntry{Path: path, Deleted: true})
			}
			continue
		}
		if errors.Is(err, errCheckpointFileLimit) {
			_ = archive.Close()
			return nil, CheckpointManifest{}, err
		}
		if errors.Is(err, errCheckpointUnsafePath) {
			manifest.OmittedUnsafe++
			continue
		}
		if err != nil {
			_ = archive.Close()
			return nil, CheckpointManifest{}, fmt.Errorf("read checkpoint file: %w", err)
		}
		if expanded+entry.Size > MaxCheckpointExpandedBytes {
			_ = archive.Close()
			return nil, CheckpointManifest{}, fmt.Errorf("checkpoint exceeds %d expanded bytes", MaxCheckpointExpandedBytes)
		}
		expanded += entry.Size
		header := &zip.FileHeader{Name: "files/" + path, Method: zip.Deflate}
		header.SetMode(fs.FileMode(entry.Mode))
		writer, err := archive.CreateHeader(header)
		if err != nil {
			_ = archive.Close()
			return nil, CheckpointManifest{}, checkpointArchiveError(err, archiveBuffer.err)
		}
		if _, err := writer.Write(content); err != nil {
			_ = archive.Close()
			return nil, CheckpointManifest{}, checkpointArchiveError(err, archiveBuffer.err)
		}
		manifest.Entries = append(manifest.Entries, entry)
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		_ = archive.Close()
		return nil, CheckpointManifest{}, err
	}
	if len(manifestBytes) > MaxCheckpointManifestBytes {
		_ = archive.Close()
		return nil, CheckpointManifest{}, errors.New("checkpoint manifest exceeded size limit")
	}
	manifestHeader := &zip.FileHeader{Name: CheckpointManifestName, Method: zip.Deflate}
	manifestHeader.SetMode(0o600)
	writer, err := archive.CreateHeader(manifestHeader)
	if err == nil {
		_, err = writer.Write(manifestBytes)
	}
	if err != nil {
		_ = archive.Close()
		return nil, CheckpointManifest{}, checkpointArchiveError(err, archiveBuffer.err)
	}
	if err := archive.Close(); err != nil {
		return nil, CheckpointManifest{}, checkpointArchiveError(err, archiveBuffer.err)
	}
	if archiveBuffer.err != nil {
		return nil, CheckpointManifest{}, archiveBuffer.err
	}
	return append([]byte(nil), archiveBuffer.Bytes()...), manifest, nil
}

func checkpointPaths(ctx context.Context, root string, untracked bool) ([]string, error) {
	args := []string{"ls-files", "-z"}
	if untracked {
		args = append(args, "--others", "--exclude-standard")
	} else {
		args = append(args, "--cached")
	}
	output, err := runCheckpointGit(ctx, root, args...)
	if err != nil {
		return nil, err
	}
	items := bytes.Split(output, []byte{0})
	result := make([]string, 0, len(items))
	for _, item := range items {
		if len(item) == 0 {
			continue
		}
		if len(result) >= MaxCheckpointEntries {
			return nil, fmt.Errorf("checkpoint exceeds %d entries", MaxCheckpointEntries)
		}
		result = append(result, string(item))
	}
	return result, nil
}

func checkpointChangedTrackedPaths(ctx context.Context, root, head string) ([]string, error) {
	commands := make([][]string, 0, 3)
	if head == "" {
		commands = append(commands, []string{"ls-files", "-z", "--cached"})
	} else {
		commands = append(commands,
			[]string{"diff", "--no-ext-diff", "--no-textconv", "--name-only", "-z", "HEAD"},
			[]string{"diff", "--no-ext-diff", "--no-textconv", "--cached", "--name-only", "-z", "HEAD"},
		)
		if _, err := runCheckpointGit(ctx, root, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"); err == nil {
			commands = append(commands, []string{"diff", "--no-ext-diff", "--name-only", "-z", "@{upstream}...HEAD"})
		} else {
			commands = append(commands, []string{"log", "--format=", "--name-only", "-z", "HEAD", "--not", "--remotes"})
		}
	}
	seen := make(map[string]bool)
	for _, command := range commands {
		output, err := runCheckpointGit(ctx, root, command...)
		if err != nil {
			return nil, err
		}
		for _, item := range bytes.Split(output, []byte{0}) {
			if len(item) == 0 {
				continue
			}
			seen[string(item)] = true
			if len(seen) > MaxCheckpointEntries {
				return nil, fmt.Errorf("checkpoint exceeds %d entries", MaxCheckpointEntries)
			}
		}
	}
	result := make([]string, 0, len(seen))
	for path := range seen {
		result = append(result, path)
	}
	sort.Strings(result)
	return result, nil
}

func readCheckpointFile(root *os.Root, path string, untracked bool) (CheckpointEntry, []byte, error) {
	info, err := lstatCheckpointPath(root, path)
	if err != nil {
		return CheckpointEntry{}, nil, err
	}
	if info.Size() > MaxCheckpointFileBytes {
		return CheckpointEntry{}, nil, fmt.Errorf("%w: %s", errCheckpointFileLimit, path)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 0 {
		return CheckpointEntry{}, nil, errCheckpointUnsafePath
	}
	file, err := root.Open(filepath.FromSlash(path))
	if err != nil {
		return CheckpointEntry{}, nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return CheckpointEntry{}, nil, errors.New("checkpoint file changed while opening")
	}
	content, err := io.ReadAll(io.LimitReader(file, MaxCheckpointFileBytes+1))
	if err != nil {
		return CheckpointEntry{}, nil, err
	}
	if len(content) > MaxCheckpointFileBytes || int64(len(content)) != opened.Size() {
		return CheckpointEntry{}, nil, fmt.Errorf("%w: %s", errCheckpointFileLimit, path)
	}
	digest := sha256.Sum256(content)
	mode := uint32(opened.Mode().Perm() & 0o777)
	return CheckpointEntry{
		Path: path, SHA256: hex.EncodeToString(digest[:]), Size: int64(len(content)),
		Mode: mode, Untracked: untracked,
	}, content, nil
}

var errCheckpointFileLimit = errors.New("checkpoint file exceeds size limit")
var errCheckpointUnsafePath = errors.New("checkpoint path is not a regular non-symlink file")
var checkpointWorkspaceIDPattern = regexp.MustCompile(`^ws_[a-z2-7]{16,64}$`)

func lstatCheckpointPath(root *os.Root, path string) (os.FileInfo, error) {
	parts := strings.Split(filepath.FromSlash(path), string(filepath.Separator))
	current := ""
	var info os.FileInfo
	for _, part := range parts {
		if part == "" || part == "." {
			return nil, errors.New("invalid checkpoint path component")
		}
		current = filepath.Join(current, part)
		value, err := root.Lstat(current)
		if err != nil {
			return nil, err
		}
		if value.Mode()&os.ModeSymlink != 0 {
			return nil, errCheckpointUnsafePath
		}
		info = value
	}
	return info, nil
}

func cleanCheckpointPath(path string) (string, error) {
	if path == "" || len(path) > 4096 || strings.ContainsRune(path, 0) || strings.Contains(path, "\\") || filepath.IsAbs(path) {
		return "", errors.New("invalid checkpoint path")
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(path)))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, ".git/") || clean == ".git" {
		return "", errors.New("checkpoint path escapes the repository")
	}
	return clean, nil
}

func runCheckpointGit(ctx context.Context, root string, args ...string) ([]byte, error) {
	gitPath, err := gitops.TrustedExecutable()
	if err != nil {
		return nil, errors.New("git is not installed")
	}
	if !filepath.IsAbs(root) {
		return nil, errors.New("checkpoint workspace root is invalid")
	}
	root = filepath.Clean(root)
	hooksDir, err := os.MkdirTemp(filepath.Dir(root), ".codex-mobile-disabled-hooks-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(hooksDir)
	cmd, cancel, err := newCheckpointGitCommand(ctx, gitPath, root, hooksDir, args...)
	if err != nil {
		return nil, err
	}
	defer cancel()
	var output boundedCheckpointBuffer
	output.limit = maxCheckpointGitOutputBytes
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Run(); err != nil {
		if output.err != nil {
			return nil, output.err
		}
		return nil, errors.New("checkpoint Git inspection failed")
	}
	return append([]byte(nil), output.Bytes()...), nil
}

func boundedCheckpointGitContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, checkpointGitTimeout)
}

func newCheckpointGitCommand(parent context.Context, executable, root, hooksDir string, args ...string) (*exec.Cmd, context.CancelFunc, error) {
	if parent == nil || !filepath.IsAbs(executable) || !filepath.IsAbs(root) || !filepath.IsAbs(hooksDir) {
		return nil, nil, errors.New("invalid checkpoint Git subprocess boundary")
	}
	root, hooksDir = filepath.Clean(root), filepath.Clean(hooksDir)
	commandContext, cancel := boundedCheckpointGitContext(parent)
	fixed := []string{
		"--no-pager", "-C", root,
		"-c", "core.fsmonitor=false",
		"-c", "core.hooksPath=" + hooksDir,
		"-c", "diff.external=",
	}
	command := exec.CommandContext(commandContext, executable, append(fixed, args...)...)
	command.Dir = root
	command.Env = checkpointGitEnvironment()
	command.Stdin = strings.NewReader("")
	command.WaitDelay = checkpointGitWaitDelay
	return command, cancel, nil
}

func checkpointGitEnvironment() []string {
	env := []string{
		"GIT_ATTR_NOSYSTEM=1", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0", "GIT_PAGER=cat", "LC_ALL=C", "LANG=C",
	}
	for _, key := range []string{"HOME", "USERPROFILE", "SystemRoot", "PATH"} {
		if value := os.Getenv(key); value != "" {
			env = append(env, key+"="+value)
		}
	}
	if runtime.GOOS == "windows" {
		if value := os.Getenv("WINDIR"); value != "" {
			env = append(env, "WINDIR="+value)
		}
	}
	return env
}

type boundedCheckpointBuffer struct {
	bytes.Buffer
	limit int
	err   error
}

func (b *boundedCheckpointBuffer) Write(p []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	if len(p) > b.limit-b.Len() {
		b.err = errors.New("checkpoint output exceeded size limit")
		return 0, b.err
	}
	return b.Buffer.Write(p)
}

func checkpointArchiveError(operation, bounded error) error {
	if bounded != nil {
		return bounded
	}
	return operation
}

func (h *Helper) checkpointRestoreFile(request *Request) Response {
	path, err := cleanCheckpointPath(request.Path)
	if err != nil || workspacefiles.Sensitive(path) || request.CheckpointMode > 0o777 {
		return failure("invalid", "The checkpoint restore request was invalid.")
	}
	if base64.StdEncoding.DecodedLen(len(request.Content)) > MaxCheckpointFileBytes {
		return failure("invalid", "The checkpoint restore request was invalid.")
	}
	content, err := base64.StdEncoding.DecodeString(request.Content)
	if err != nil || len(content) > MaxCheckpointFileBytes {
		return failure("invalid", "The checkpoint restore request was invalid.")
	}
	digest := sha256.Sum256(content)
	if !strings.EqualFold(request.CheckpointContentSHA256, hex.EncodeToString(digest[:])) {
		return failure("invalid", "The checkpoint restore request was invalid.")
	}
	mode := fs.FileMode(request.CheckpointMode)
	if mode == 0 {
		mode = 0o600
	}
	if err := restoreCheckpointFile(h.root, path, content, mode); err != nil {
		return fromError(err)
	}
	return Response{Version: Version, OK: true}
}

func restoreCheckpointFile(rootPath, path string, content []byte, mode fs.FileMode) error {
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return err
	}
	defer root.Close()
	parent := filepath.Dir(filepath.FromSlash(path))
	if parent != "." {
		if err := root.MkdirAll(parent, 0o700); err != nil {
			return err
		}
		if _, err := lstatCheckpointPath(root, filepath.ToSlash(parent)); err != nil {
			return err
		}
	}
	temporary := filepath.Join(parent, fmt.Sprintf(".codex-mobile-restore-%x", sha256.Sum256([]byte(path))))
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode.Perm())
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		_ = file.Close()
		if !committed {
			_ = root.Remove(temporary)
		}
	}()
	if _, err := file.Write(content); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := root.Rename(temporary, filepath.FromSlash(path)); err != nil {
		return err
	}
	committed = true
	return nil
}
