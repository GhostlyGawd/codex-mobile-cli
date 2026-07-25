package attachments

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestStageUsesRandomPrivatePathsOutsideRepository(t *testing.T) {
	root := filepath.Join(t.TempDir(), "noexec-attachments")
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	random := bytes.NewReader(bytes.Repeat([]byte{0x4a}, 128))
	stager, err := NewStager(root, random, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("hello from the owner\n")
	items, err := stager.Stage(context.Background(), []Upload{{MediaType: "text/plain", Content: content}})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].MediaType != "text/plain" || items[0].SizeBytes != len(content) || !items[0].ExpiresAt.Equal(now.Add(StagingTTL)) {
		t.Fatalf("unexpected staged metadata: %#v", items)
	}
	if !strings.HasPrefix(filepath.Clean(items[0].Path), filepath.Clean(root)+string(filepath.Separator)) || strings.Contains(items[0].Path, "hello") {
		t.Fatalf("staged path was not randomized beneath the isolated root: %q", items[0].Path)
	}
	info, err := os.Stat(filepath.FromSlash(items[0].Path))
	if err != nil {
		t.Fatal(err)
	}
	if (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) || info.Mode()&0o111 != 0 {
		t.Fatalf("staged file was executable or not private: %o", info.Mode().Perm())
	}
	stored, err := os.ReadFile(filepath.FromSlash(items[0].Path))
	if err != nil || !bytes.Equal(stored, content) {
		t.Fatalf("stored attachment mismatch: %q %v", stored, err)
	}
	if _, err := os.Stat(filepath.Join(root, "repository")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("stager unexpectedly created a repository path")
	}
}

func TestValidateRejectsSpoofingAndLimits(t *testing.T) {
	png := append([]byte("\x89PNG\r\n\x1a\n"), []byte("pixels")...)
	tests := []struct {
		name    string
		uploads []Upload
	}{
		{"empty", nil},
		{"too many", []Upload{{MediaType: "image/png", Content: png}, {MediaType: "image/png", Content: png}, {MediaType: "image/png", Content: png}, {MediaType: "image/png", Content: png}, {MediaType: "image/png", Content: png}}},
		{"spoofed image", []Upload{{MediaType: "image/png", Content: []byte("not a png")}}},
		{"executable type", []Upload{{MediaType: "application/x-executable", Content: []byte("MZ")}}},
		{"nul text", []Upload{{MediaType: "text/plain", Content: []byte("a\x00b")}}},
		{"oversize file", []Upload{{MediaType: "text/plain", Content: bytes.Repeat([]byte("a"), MaximumFileBytes+1)}}},
		{"oversize total", []Upload{{MediaType: "text/plain", Content: bytes.Repeat([]byte("a"), MaximumFileBytes)}, {MediaType: "text/plain", Content: bytes.Repeat([]byte("b"), MaximumTotalBytes-MaximumFileBytes+1)}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := Validate(test.uploads); err == nil {
				t.Fatal("expected validation failure")
			}
		})
	}
}

func TestCleanupExpiredIsBoundedToRandomStageDirectories(t *testing.T) {
	root := filepath.Join(t.TempDir(), "attachments")
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	stager, err := NewStager(root, bytes.NewReader(bytes.Repeat([]byte{0x37}, 128)), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "stage-1-abcdefghijklmnop"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "keep-owner-file"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := stager.CleanupExpired(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "stage-1-abcdefghijklmnop")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired stage survived: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "keep-owner-file")); err != nil {
		t.Fatalf("unrecognized directory was removed: %v", err)
	}
}

func TestExpiryParserAcceptsBase64URLHyphens(t *testing.T) {
	value, ok := expiryFromStageName("stage-1784205000-abc-def_ghijklmnop")
	if !ok || value.Unix() != 1784205000 {
		t.Fatalf("base64url stage name did not parse: %v %v", value, ok)
	}
}

func TestStageCancellationDoesNotLeavePartialBatch(t *testing.T) {
	root := filepath.Join(t.TempDir(), "attachments")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stager, err := NewStager(root, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = stager.Stage(ctx, []Upload{{MediaType: "text/plain", Content: []byte("owner input")}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	if entries, readErr := os.ReadDir(root); readErr == nil && len(entries) != 0 {
		t.Fatalf("canceled stage left files: %#v", entries)
	}
}
