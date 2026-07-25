package workspacehelper

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/attachments"
)

func TestAttachmentOperationStagesOnTemporaryNoexecBoundary(t *testing.T) {
	root := filepath.Join(t.TempDir(), "repository")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	temporary := t.TempDir()
	helper, err := NewWithTemporaryRoot(root, temporary)
	if err != nil {
		t.Fatal(err)
	}
	request := &Request{
		Version: Version, Operation: OpAttachmentStage,
		Attachments: []attachments.Upload{{MediaType: "text/plain", Content: []byte("look at this")}},
	}
	response := helper.execute(context.Background(), request)
	if !response.OK || len(response.Attachments) != 1 {
		t.Fatalf("unexpected helper response: %#v", response)
	}
	staged := filepath.FromSlash(response.Attachments[0].Path)
	wantRoot := filepath.Join(temporary, "codex-mobile-attachments") + string(filepath.Separator)
	if len(staged) <= len(wantRoot) || staged[:len(wantRoot)] != wantRoot {
		t.Fatalf("attachment escaped temporary staging root: %q", staged)
	}
	if _, err := os.Stat(filepath.Join(root, filepath.Base(staged))); !os.IsNotExist(err) {
		t.Fatal("attachment was staged inside the repository")
	}
	info, err := os.Stat(staged)
	if err != nil {
		t.Fatal(err)
	}
	if (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) || info.Mode()&0o111 != 0 {
		t.Fatalf("attachment mode was not private and non-executable: %o", info.Mode().Perm())
	}
}

func TestAttachmentOperationRejectsMIMETypeSpoof(t *testing.T) {
	helper, err := NewWithTemporaryRoot(t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	response := helper.execute(context.Background(), &Request{
		Version: Version, Operation: OpAttachmentStage,
		Attachments: []attachments.Upload{{MediaType: "image/png", Content: []byte("#!/bin/sh")}},
	})
	if response.OK || response.ErrorCode != "invalid" {
		t.Fatalf("spoofed image was accepted: %#v", response)
	}
}

func TestScrubSensitiveRequestWipesAttachments(t *testing.T) {
	content := []byte("private attachment")
	request := &Request{Attachments: []attachments.Upload{{MediaType: "text/plain", Content: content}}}
	scrubSensitiveRequest(request)
	if request.Attachments != nil {
		t.Fatal("attachment slice was retained")
	}
	for _, value := range content {
		if value != 0 {
			t.Fatal("attachment plaintext was retained")
		}
	}
}
