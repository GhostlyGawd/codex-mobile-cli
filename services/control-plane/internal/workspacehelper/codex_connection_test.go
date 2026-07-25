package workspacehelper

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCodexConnectionStatusAndRevokeRemoveCredentialMaterial(t *testing.T) {
	root := filepath.Join(t.TempDir(), "workspace", "repository")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	temporaryRoot := t.TempDir()
	manager, err := newCodexAuthManager(root, temporaryRoot, bytes.NewReader(bytes.Repeat([]byte{0x46}, 512)))
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x29}, CodexAuthKeyBytes)
	if err := manager.configure(key); err != nil {
		t.Fatal(err)
	}
	session, err := manager.beginDeviceLogin()
	if err != nil {
		if errors.Is(err, errCodexAuthUnavailable) && os.PathSeparator == '\\' {
			t.Skip("Windows does not provide the production Linux private-file locking semantics")
		}
		t.Fatal(err)
	}
	if err := atomicPrivateFile(manager.paths.runtimeAuth, testChatGPTAuth); err != nil {
		t.Fatal(err)
	}
	if err := session.close(); err != nil {
		t.Fatal(err)
	}
	if state, err := manager.status(); err != nil || state != "connected" {
		t.Fatalf("status = %q, %v", state, err)
	}

	helper, err := NewWithTemporaryRoot(root, temporaryRoot)
	if err != nil {
		t.Fatal(err)
	}
	killed := []string{}
	helper.killCodexTmux = func(_ context.Context, tabID string) error {
		killed = append(killed, tabID)
		return nil
	}
	const tabID = "11111111-1111-4111-8111-111111111111"
	response := helper.execute(context.Background(), &Request{
		Version: Version, Operation: OpCodexAuthRevoke, Confirmed: true,
		CodexTerminalTabIDs: []string{tabID},
	})
	if !response.OK || response.CodexAuthState != "disconnected" || len(killed) != 1 || killed[0] != tabID {
		t.Fatalf("revoke response = %#v, killed = %#v", response, killed)
	}
	if state, err := manager.status(); err != nil || state != "disconnected" {
		t.Fatalf("status after revoke = %q, %v", state, err)
	}
	for _, path := range []string{manager.paths.runtimeAuth, manager.paths.encryptedAuth, manager.paths.key, manager.paths.persistentAuth} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("credential path remains after revoke: %s (%v)", path, err)
		}
	}
}

func TestCodexConnectionOperationsRejectBroadOrAmbiguousRequests(t *testing.T) {
	helper, err := NewWithTemporaryRoot(t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	helper.killCodexTmux = func(context.Context, string) error { return nil }
	const tabID = "11111111-1111-4111-8111-111111111111"
	for _, request := range []Request{
		{Version: Version, Operation: OpCodexAuthStatus, Confirmed: true},
		{Version: Version, Operation: OpCodexAuthStatus, GitHubToken: "secret"},
		{Version: Version, Operation: OpCodexAuthRevoke, CodexTerminalTabIDs: []string{tabID}},
		{Version: Version, Operation: OpCodexAuthRevoke, Confirmed: true, CodexTerminalTabIDs: []string{tabID, tabID}},
		{Version: Version, Operation: OpCodexAuthRevoke, Confirmed: true, CodexTerminalTabIDs: []string{"invalid"}},
	} {
		response := helper.execute(context.Background(), &request)
		if response.OK || response.ErrorCode != "invalid" {
			t.Fatalf("broad connection request accepted: %#v -> %#v", request, response)
		}
	}
}
