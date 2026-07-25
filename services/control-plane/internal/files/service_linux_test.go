//go:build linux

package files

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
)

func TestLinuxSaveUsesPinnedParentAfterSymlinkSwap(t *testing.T) {
	s, root := newService(t)
	originalDirectory := filepath.Join(root, "src")
	if err := os.Mkdir(originalDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(originalDirectory, "main.txt")
	if err := os.WriteFile(target, []byte("initial"), 0o644); err != nil {
		t.Fatal(err)
	}
	initial, err := s.Read("src/main.txt")
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	outsideTarget := filepath.Join(outside, "main.txt")
	if err := os.WriteFile(outsideTarget, []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	movedDirectory := filepath.Join(root, "src-before-swap")
	s.saveHooks.beforeFinalValidation = func() {
		if err := os.Rename(originalDirectory, movedDirectory); err != nil {
			t.Errorf("rename parent: %v", err)
			return
		}
		if err := os.Symlink(outside, originalDirectory); err != nil {
			t.Errorf("replace parent with symlink: %v", err)
		}
	}
	updated, err := s.Save("src/main.txt", []byte("mobile"), initial.ETag)
	if err != nil {
		t.Fatalf("save through pinned parent: %v", err)
	}
	if string(updated.Content) != "mobile" {
		t.Fatalf("updated content = %q", updated.Content)
	}
	outsideContent, err := os.ReadFile(outsideTarget)
	if err != nil {
		t.Fatal(err)
	}
	if string(outsideContent) != "outside" {
		t.Fatalf("outside file was overwritten: %q", outsideContent)
	}
	movedContent, err := os.ReadFile(filepath.Join(movedDirectory, "main.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(movedContent) != "mobile" {
		t.Fatalf("pinned target content = %q", movedContent)
	}
	if _, err := s.Read("src/main.txt"); !errors.Is(err, core.ErrForbidden) {
		t.Fatalf("subsequent symlink read error = %v", err)
	}
}

func TestLinuxPinnedRootSurvivesPathReplacement(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "workspace")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "identity.txt"), []byte("pinned"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	moved := filepath.Join(parent, "workspace-moved")
	if err := os.Rename(root, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "identity.txt"), []byte("replacement"), 0o644); err != nil {
		t.Fatal(err)
	}
	file, err := s.Read("identity.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(file.Content) != "pinned" {
		t.Fatalf("read replacement root content: %q", file.Content)
	}
}

func TestLinuxTreeNeverTraversesSymlinkDirectory(t *testing.T) {
	s, root := newService(t)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	entries, err := s.Tree()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Path != "linked" || !entries[0].Sensitive || entries[0].Directory {
		t.Fatalf("tree entries = %#v", entries)
	}
}

func TestLinuxCommitBoundaryCASAcrossServiceInstances(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "main.txt")
	if err := os.WriteFile(target, []byte("initial"), 0o644); err != nil {
		t.Fatal(err)
	}
	first, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	initial, err := first.Read("main.txt")
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{}, 2)
	release := make(chan struct{})
	boundary := func() {
		ready <- struct{}{}
		<-release
	}
	first.saveHooks.afterFinalValidation = boundary
	second.saveHooks.afterFinalValidation = boundary
	results := make(chan error, 2)
	go func() {
		_, err := first.Save("main.txt", []byte("first"), initial.ETag)
		results <- err
	}()
	go func() {
		_, err := second.Save("main.txt", []byte("second"), initial.ETag)
		results <- err
	}()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for range 2 {
		select {
		case <-ready:
		case <-timer.C:
			close(release)
			t.Fatal("saves did not reach the commit boundary")
		}
	}
	close(release)
	var successes, conflicts int
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			successes++
		case errors.Is(err, core.ErrPrecondition):
			conflicts++
		default:
			t.Fatalf("unexpected save result: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d conflicts=%d", successes, conflicts)
	}
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "first" && string(content) != "second" {
		t.Fatalf("final content = %q", content)
	}
}
