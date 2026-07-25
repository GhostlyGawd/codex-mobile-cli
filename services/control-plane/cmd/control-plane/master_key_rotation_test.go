package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/config"
)

func TestReadNewMasterKeyFileDoesNotModifyRawOrEncodedFile(t *testing.T) {
	for _, test := range []struct {
		name    string
		content []byte
	}{
		{name: "raw", content: bytes.Repeat([]byte{0x73}, 32)},
		{name: "base64", content: []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x74}, 32)) + "\n")},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "new-master-key")
			if err := os.WriteFile(path, test.content, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o600); err != nil {
				t.Fatal(err)
			}
			key, err := readNewMasterKeyFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if len(key) != 32 {
				t.Fatalf("decoded key length = %d", len(key))
			}
			clear(key)
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, test.content) {
				t.Fatal("new key file was modified")
			}
		})
	}
}

func TestRewrapMasterKeyRequiresExactConfirmationAndDifferentKey(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := rewrapMasterKey(context.Background(), config.Config{}, nil, logger); err == nil {
		t.Fatal("missing destructive confirmation was accepted")
	}
	path := filepath.Join(t.TempDir(), "same-master-key")
	key := bytes.Repeat([]byte{0x75}, 32)
	if err := os.WriteFile(path, key, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rewrapMasterKey(context.Background(), config.Config{MasterKey: bytes.Clone(key)}, []string{path, rewrapMasterKeyConfirmation}, logger); err == nil {
		t.Fatal("identical replacement key was accepted")
	}
}
