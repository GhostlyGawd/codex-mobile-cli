package gitops

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type testCheckpoint struct{ calls int }

func (c *testCheckpoint) Create(context.Context, string) (string, error) {
	c.calls++
	return "checkpoint-1", nil
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = gitEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return string(out)
}

func repo(t *testing.T) (*Service, string, *testCheckpoint) {
	t.Helper()
	root := t.TempDir()
	git(t, root, "init", "--initial-branch=main")
	git(t, root, "config", "user.email", "codex-mobile@example.invalid")
	git(t, root, "config", "user.name", "Codex Mobile Test")
	if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("one\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, root, "add", "file.txt")
	git(t, root, "commit", "-m", "initial")
	checkpoint := &testCheckpoint{}
	s, err := New(root, checkpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s, root, checkpoint
}

func TestStatusStageCommitAndDiff(t *testing.T) {
	t.Parallel()
	s, root, _ := repo(t)
	if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("two\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	status, err := s.Status(context.Background())
	if err != nil || !status.Dirty || len(status.Changes) != 1 || !status.Changes[0].Unstaged {
		t.Fatalf("status = %#v, %v", status, err)
	}
	diff, err := s.Diff(context.Background(), false, "file.txt")
	if err != nil || len(diff) == 0 {
		t.Fatalf("diff = %q, %v", diff, err)
	}
	if err := s.Stage(context.Background(), []string{"file.txt"}); err != nil {
		t.Fatal(err)
	}
	sha, err := s.Commit(context.Background(), "change file")
	if err != nil || len(sha) != 40 {
		t.Fatalf("commit = %q, %v", sha, err)
	}
}

func TestExpectedGitHubRepositoryUsesFixedRemoteURL(t *testing.T) {
	_, root, _ := repo(t)
	service, err := New(root, nil, nil, "octo/repo")
	if err != nil {
		t.Fatal(err)
	}
	if service.remoteURL != "https://github.com/octo/repo.git" {
		t.Fatalf("fixed remote URL = %q", service.remoteURL)
	}
	if _, err := New(root, nil, nil, "https://attacker.invalid/repo"); err == nil {
		t.Fatal("untrusted repository URL was accepted")
	}
}

func TestDiscardRequiresConfirmationAndCheckpoint(t *testing.T) {
	t.Parallel()
	s, root, checkpoint := repo(t)
	_ = os.WriteFile(filepath.Join(root, "file.txt"), []byte("changed\n"), 0o644)
	if _, err := s.DiscardTracked(context.Background(), []string{"file.txt"}, false); err == nil {
		t.Fatal("discard without confirmation succeeded")
	}
	id, err := s.DiscardTracked(context.Background(), []string{"file.txt"}, true)
	if err != nil || id != "checkpoint-1" || checkpoint.calls != 1 {
		t.Fatalf("discard = %q, %v, calls=%d", id, err, checkpoint.calls)
	}
	content, _ := os.ReadFile(filepath.Join(root, "file.txt"))
	if string(content) != "one\n" {
		t.Fatalf("discarded content = %q", content)
	}
}

func TestDiscardRestoresStagedAndWorktreeStateToHEADAndRejectsUntrackedPaths(t *testing.T) {
	t.Parallel()
	s, root, checkpoint := repo(t)
	if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("staged\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, root, "add", "file.txt")
	if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("worktree after stage\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	id, err := s.DiscardTracked(context.Background(), []string{"file.txt"}, true)
	if err != nil || id != "checkpoint-1" || checkpoint.calls != 1 {
		t.Fatalf("staged discard = %q, %v, calls=%d", id, err, checkpoint.calls)
	}
	content, err := os.ReadFile(filepath.Join(root, "file.txt"))
	if err != nil || string(content) != "one\n" {
		t.Fatalf("discarded content = %q, %v", content, err)
	}
	if status := strings.TrimSpace(git(t, root, "status", "--porcelain")); status != "" {
		t.Fatalf("discard retained staged or worktree delta: %q", status)
	}
	if err := os.WriteFile(filepath.Join(root, "untracked.txt"), []byte("untracked\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DiscardTracked(context.Background(), []string{"untracked.txt"}, true); err == nil || checkpoint.calls != 1 {
		t.Fatalf("untracked discard was not rejected before checkpoint: %v calls=%d", err, checkpoint.calls)
	}
}

func TestGitPathsCannotEscapeOrStageSensitiveFile(t *testing.T) {
	t.Parallel()
	s, root, _ := repo(t)
	_ = os.WriteFile(filepath.Join(root, ".env"), []byte("SECRET=x"), 0o600)
	if err := s.Stage(context.Background(), []string{"../outside"}); err == nil {
		t.Fatal("traversal staged")
	}
	if err := s.Stage(context.Background(), []string{".env"}); err == nil {
		t.Fatal("sensitive file staged through native API")
	}
	if err := os.Mkdir(filepath.Join(root, "config"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "config", ".env.local"), []byte("SECRET=x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Stage(context.Background(), []string{"config"}); err == nil {
		t.Fatal("directory staging included a nested sensitive file")
	}
}

type testCredentialBroker struct{}

func (testCredentialBroker) Credential(context.Context) ([]byte, func(), error) {
	value := []byte("test-installation-token")
	return value, func() { clear(value) }, nil
}

func fileRemoteURL(path string) string {
	slashPath := filepath.ToSlash(path)
	if filepath.VolumeName(path) != "" {
		slashPath = "/" + strings.TrimPrefix(slashPath, "/")
	}
	return (&url.URL{Scheme: "file", Path: slashPath}).String()
}

func TestFileRemoteURLHasAnEmptyAuthority(t *testing.T) {
	remote := fileRemoteURL(t.TempDir())
	parsed, err := url.Parse(remote)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "file" || parsed.Host != "" || !strings.HasPrefix(remote, "file://") {
		t.Fatalf("unsafe local remote URL %q", remote)
	}
}

func TestGrantedValueScannerBlocksRawBase64AndURLEncodedContent(t *testing.T) {
	secret := []byte(strings.Repeat("p@ss word/token:123456", 6))
	forms := []string{
		string(secret),
		base64.StdEncoding.EncodeToString(secret),
		string(wrapEncoded([]byte(base64.StdEncoding.EncodeToString(secret)), 64, []byte{'\r', '\n'})),
		base64.RawURLEncoding.EncodeToString(secret),
		url.QueryEscape(string(secret)),
		string(lowerPercentHex([]byte(url.QueryEscape(string(secret))))),
		url.PathEscape(string(secret)),
	}
	for index, form := range forms {
		t.Run(string(rune('a'+index)), func(t *testing.T) {
			s, root, _ := repo(t)
			scanner, err := NewValueSecretScanner(secret)
			if err != nil {
				t.Fatal(err)
			}
			defer scanner.Close()
			s.scanner = scanner
			if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("prefix "+form+" suffix\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			err = s.Stage(context.Background(), []string{"file.txt"})
			if err == nil || !strings.Contains(err.Error(), "secret scan blocked staging") || strings.Contains(err.Error(), form) {
				t.Fatalf("encoded granted value was not generically blocked: %v", err)
			}
		})
	}
}

func TestGrantedValueScannerRedactsEveryDerivedDiagnosticForm(t *testing.T) {
	secret := []byte("diagnostic-secret/value-123")
	scanner, err := NewValueSecretScanner(secret)
	if err != nil {
		t.Fatal(err)
	}
	defer scanner.Close()
	forms := encodedSecretForms(secret)
	defer func() {
		for _, form := range forms {
			clear(form)
		}
	}()
	diagnostic := bytes.Join(forms, []byte(" | "))
	redacted := scanner.Redact(diagnostic)
	defer clear(redacted)
	for _, form := range forms {
		if len(form) >= minimumScannableSecretBytes && bytes.Contains(redacted, form) {
			t.Fatal("derived granted value remained in redacted diagnostic")
		}
	}
}

func TestGrantedValueScannerBlocksFilenameCommitMetadataAndEarlierPushedHistory(t *testing.T) {
	secret := []byte("runtime-secret-history-123")
	s, root, _ := repo(t)
	remote := filepath.Join(t.TempDir(), "remote.git")
	git(t, filepath.Dir(remote), "init", "--bare", remote)
	s.remoteURL = fileRemoteURL(remote)
	git(t, root, "remote", "add", "origin", remote)
	git(t, root, "push", "--set-upstream", "origin", "main")
	initial := strings.TrimSpace(git(t, root, "rev-parse", "HEAD"))
	scanner, err := NewValueSecretScanner(secret)
	if err != nil {
		t.Fatal(err)
	}
	defer scanner.Close()
	s.scanner = scanner

	secretPath := string(secret)
	if err := os.WriteFile(filepath.Join(root, secretPath), []byte("ordinary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Stage(context.Background(), []string{secretPath}); err == nil || !strings.Contains(err.Error(), "secret scan blocked staging") {
		t.Fatalf("secret-bearing filename stage = %v", err)
	}
	if err := os.Remove(filepath.Join(root, secretPath)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("metadata fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.Stage(context.Background(), []string{"file.txt"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitAs(context.Background(), "contains "+string(secret), "Owner", "owner@example.test"); err == nil || !strings.Contains(err.Error(), "commit metadata") {
		t.Fatalf("secret-bearing commit message = %v", err)
	}

	if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("token="+string(secret)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, root, "add", "file.txt")
	git(t, root, "commit", "-m", "terminal-created unsafe history")
	if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("secret removed from tip\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, root, "add", "file.txt")
	git(t, root, "commit", "-m", "terminal removed unsafe content")
	if err := s.Push(context.Background(), testCredentialBroker{}); err == nil || !strings.Contains(err.Error(), "secret scan blocked push") || strings.Contains(err.Error(), string(secret)) {
		t.Fatalf("secret-bearing earlier history push = %v", err)
	}
	if remoteTip := strings.TrimSpace(git(t, remote, "rev-parse", "refs/heads/main")); remoteTip != initial {
		t.Fatalf("blocked push changed remote from %s to %s", initial, remoteTip)
	}
}

func TestGrantedValueScannerPushesExactSafeTipAndRecordsUpstream(t *testing.T) {
	s, root, _ := repo(t)
	remote := filepath.Join(t.TempDir(), "remote.git")
	git(t, filepath.Dir(remote), "init", "--bare", remote)
	s.remoteURL = fileRemoteURL(remote)
	git(t, root, "remote", "add", "origin", remote)
	scanner, err := NewValueSecretScanner([]byte("unrelated-granted-secret-123"))
	if err != nil {
		t.Fatal(err)
	}
	defer scanner.Close()
	s.scanner = scanner
	if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("safe pushed content\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.Stage(context.Background(), []string{"file.txt"}); err != nil {
		t.Fatal(err)
	}
	commitID, err := s.Commit(context.Background(), "safe native commit")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Push(context.Background(), testCredentialBroker{}); err != nil {
		t.Fatalf("safe exact-tip push failed: %v", err)
	}
	if remoteTip := strings.TrimSpace(git(t, remote, "rev-parse", "refs/heads/main")); remoteTip != commitID {
		t.Fatalf("remote tip = %s, want %s", remoteTip, commitID)
	}
	if upstream := strings.TrimSpace(git(t, root, "rev-parse", "--abbrev-ref", "@{upstream}")); upstream != "origin/main" {
		t.Fatalf("upstream = %q, want origin/main", upstream)
	}
}

func TestGrantedValueScannerBlocksCommitAndPushButAllowsOrdinaryContent(t *testing.T) {
	secret := []byte("runtime-secret-value-123")
	s, root, _ := repo(t)
	remote := filepath.Join(t.TempDir(), "remote.git")
	git(t, filepath.Dir(remote), "init", "--bare", remote)
	s.remoteURL = fileRemoteURL(remote)
	scanner, err := NewValueSecretScanner(secret)
	if err != nil {
		t.Fatal(err)
	}
	defer scanner.Close()
	s.scanner = scanner
	if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("ordinary source content\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.Stage(context.Background(), []string{"file.txt"}); err != nil {
		t.Fatalf("ordinary content was blocked: %v", err)
	}
	if _, err := s.Commit(context.Background(), "ordinary change"); err != nil {
		t.Fatalf("ordinary commit was blocked: %v", err)
	}

	if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("token="+string(secret)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, root, "add", "file.txt")
	if _, err := s.Commit(context.Background(), "unsafe change"); err == nil || !strings.Contains(err.Error(), "secret scan blocked commit") || strings.Contains(err.Error(), string(secret)) {
		t.Fatalf("unsafe commit result = %v", err)
	}
	git(t, root, "commit", "-m", "bypass native API for push scanner test")
	if err := s.Push(context.Background(), testCredentialBroker{}); err == nil || !strings.Contains(err.Error(), "secret scan blocked push") || strings.Contains(err.Error(), string(secret)) {
		t.Fatalf("unsafe push result = %v", err)
	}
}

func TestGrantedValueScannerExcludesDangerouslyShortValuesAndBoundsInputs(t *testing.T) {
	s, root, _ := repo(t)
	scanner, err := NewValueSecretScanner([]byte("short"))
	if err != nil {
		t.Fatal(err)
	}
	defer scanner.Close()
	s.scanner = scanner
	if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("ordinary short words remain usable\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.Stage(context.Background(), []string{"file.txt"}); err != nil {
		t.Fatalf("short excluded value blocked ordinary content: %v", err)
	}
	values := make([][]byte, maximumScannerSecrets+1)
	for index := range values {
		values[index] = []byte("bounded-secret-value")
	}
	if _, err := NewValueSecretScanner(values...); err == nil {
		t.Fatal("scanner accepted too many granted values")
	}
}
