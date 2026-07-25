package files

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
)

func newService(t *testing.T) (*Service, string) {
	t.Helper()
	root := t.TempDir()
	s, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("close service: %v", err)
		}
	})
	return s, root
}

func TestSaveUsesETagCompareAndSwap(t *testing.T) {
	t.Parallel()
	s, _ := newService(t)
	created, err := s.Save("src/main.txt", []byte("one"), "")
	if err == nil {
		t.Fatal("save should fail when parent directory does not exist")
	}
	if err := os.MkdirAll(filepath.Join(s.root, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	created, err = s.Save("src/main.txt", []byte("one"), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Save("src/main.txt", []byte("two"), `"sha256-stale"`); !errors.Is(err, core.ErrPrecondition) {
		t.Fatalf("expected ETag precondition, got %v", err)
	}
	updated, err := s.Save("src/main.txt", []byte("two"), created.ETag)
	if err != nil || string(updated.Content) != "two" || updated.ETag == created.ETag {
		t.Fatalf("updated = %#v, %v", updated, err)
	}
}

func TestTraversalAndSensitivePathsRejected(t *testing.T) {
	t.Parallel()
	s, root := newService(t)
	hostilePaths := []string{"../escape", "nested/../../escape", "/absolute", "nested\\..\\escape", "bad\x00name"}
	if runtime.GOOS == "windows" {
		hostilePaths = append(hostilePaths, "C:/drive-relative")
	}
	for _, hostile := range hostilePaths {
		if _, err := s.Save(hostile, []byte("x"), ""); !errors.Is(err, core.ErrInvalid) {
			t.Fatalf("path %q error = %v", hostile, err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("TOKEN=secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read(".env"); !errors.Is(err, core.ErrForbidden) {
		t.Fatalf("sensitive read error = %v", err)
	}
}

func TestSymlinkEscapeRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation commonly requires elevated Windows privilege")
	}
	t.Parallel()
	s, root := newService(t)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read("link/secret.txt"); !errors.Is(err, core.ErrForbidden) {
		t.Fatalf("symlink error = %v", err)
	}
}

func TestTreeMarksSensitiveAndSkipsGit(t *testing.T) {
	t.Parallel()
	s, root := newService(t)
	_ = os.MkdirAll(filepath.Join(root, ".git"), 0o755)
	_ = os.WriteFile(filepath.Join(root, ".git", "config"), []byte("secret"), 0o600)
	_ = os.WriteFile(filepath.Join(root, "code.txt"), []byte("hello"), 0o644)
	_ = os.WriteFile(filepath.Join(root, "private.pem"), []byte("key"), 0o600)
	entries, err := s.Tree()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %#v", entries)
	}
	for _, entry := range entries {
		if entry.Path == "private.pem" && !entry.Sensitive {
			t.Fatal("private key not marked sensitive")
		}
	}
}

func TestSearchUsesFixedStringAndExcludesSecrets(t *testing.T) {
	t.Parallel()
	s, root := newService(t)
	_ = os.WriteFile(filepath.Join(root, "code.txt"), []byte("needle.*literal\n"), 0o644)
	_ = os.WriteFile(filepath.Join(root, ".env"), []byte("needle.*literal\n"), 0o600)
	matches, err := s.Search(context.Background(), "needle.*literal", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].Path != "code.txt" {
		t.Fatalf("matches = %#v", matches)
	}
}

func TestSaveRejectsTerminalEditAtCommitBoundary(t *testing.T) {
	t.Parallel()
	s, root := newService(t)
	target := filepath.Join(root, "main.txt")
	if err := os.WriteFile(target, []byte("initial"), 0o644); err != nil {
		t.Fatal(err)
	}
	initial, err := s.Read("main.txt")
	if err != nil {
		t.Fatal(err)
	}
	s.saveHooks.afterFinalValidation = func() {
		if err := os.WriteFile(target, []byte("terminal edit"), 0o644); err != nil {
			t.Errorf("terminal edit: %v", err)
		}
	}
	if _, err := s.Save("main.txt", []byte("mobile edit"), initial.ETag); !errors.Is(err, core.ErrPrecondition) {
		t.Fatalf("expected commit-boundary precondition, got %v", err)
	}
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "terminal edit" {
		t.Fatalf("concurrent terminal edit was overwritten: %q", content)
	}
}

func TestCreateDoesNotReplaceConcurrentTerminalFile(t *testing.T) {
	t.Parallel()
	s, root := newService(t)
	target := filepath.Join(root, "new.txt")
	s.saveHooks.beforeFinalValidation = func() {
		if err := os.WriteFile(target, []byte("terminal create"), 0o644); err != nil {
			t.Errorf("terminal create: %v", err)
		}
	}
	if _, err := s.Save("new.txt", []byte("mobile create"), ""); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("expected create conflict, got %v", err)
	}
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "terminal create" {
		t.Fatalf("concurrent terminal file was overwritten: %q", content)
	}
}

func TestConcurrentSavesAllowExactlyOneWinner(t *testing.T) {
	t.Parallel()
	s, root := newService(t)
	target := filepath.Join(root, "main.txt")
	if err := os.WriteFile(target, []byte("initial"), 0o644); err != nil {
		t.Fatal(err)
	}
	initial, err := s.Read("main.txt")
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	errorsByWriter := make(chan error, 2)
	for _, value := range []string{"writer one", "writer two"} {
		value := value
		go func() {
			<-start
			_, err := s.Save("main.txt", []byte(value), initial.ETag)
			errorsByWriter <- err
		}()
	}
	close(start)
	var successes, preconditions int
	for range 2 {
		err := <-errorsByWriter
		switch {
		case err == nil:
			successes++
		case errors.Is(err, core.ErrPrecondition):
			preconditions++
		default:
			t.Fatalf("unexpected concurrent save error: %v", err)
		}
	}
	if successes != 1 || preconditions != 1 {
		t.Fatalf("successes=%d preconditions=%d", successes, preconditions)
	}
}

func TestSearchCancellationAndResourceLimits(t *testing.T) {
	t.Parallel()
	s, root := newService(t)
	if err := os.WriteFile(filepath.Join(root, "large.txt"), []byte("needle in a bounded file"), 0o644); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Search(canceled, "needle", 10); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled search error = %v", err)
	}
	s.maxSearchScan = 4
	if _, err := s.Search(context.Background(), "needle", 10); err == nil || err.Error() != "search input limit exceeded" {
		t.Fatalf("scan limit error = %v", err)
	}
	s.maxSearchScan = DefaultSearchScan
	s.maxSearchBytes = 8
	if _, err := s.Search(context.Background(), "needle", 10); err == nil || err.Error() != "search output limit exceeded" {
		t.Fatalf("output limit error = %v", err)
	}
}
