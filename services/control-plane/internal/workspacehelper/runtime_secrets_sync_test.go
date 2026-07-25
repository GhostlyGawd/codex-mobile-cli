package workspacehelper

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRuntimeSecretsSyncReplacesAuthoritativeGrantSet(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	temporaryRoot := t.TempDir()
	helper, err := NewWithTemporaryRoot(root, temporaryRoot)
	if err != nil {
		t.Fatal(err)
	}

	first := []byte("first-runtime-value")
	response := call(t, helper, Request{
		Version: Version, Operation: OpRuntimeSecretsSync,
		GrantedSecrets: map[string][]byte{"DEPLOY_TOKEN": first},
	})
	if !response.OK {
		t.Fatalf("initial runtime secret sync failed: %#v", response)
	}
	loaded, err := loadRuntimeSecrets(temporaryRoot)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loaded["DEPLOY_TOKEN"], first) {
		t.Fatalf("initial authoritative grants were not materialized: %#v", loaded)
	}
	wipeRuntimeSecrets(loaded)

	response = call(t, helper, Request{
		Version: Version, Operation: OpRuntimeSecretsSync,
		GrantedSecrets: map[string][]byte{"SIGNING_TOKEN": []byte("replacement-runtime-value")},
	})
	if !response.OK {
		t.Fatalf("replacement runtime secret sync failed: %#v", response)
	}
	loaded, err = loadRuntimeSecrets(temporaryRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer wipeRuntimeSecrets(loaded)
	if _, stale := loaded["DEPLOY_TOKEN"]; stale || string(loaded["SIGNING_TOKEN"]) != "replacement-runtime-value" {
		t.Fatalf("runtime grant replacement retained stale values: %#v", loaded)
	}

	info, err := os.Stat(runtimeSecretsPath(temporaryRoot))
	unsafePermissions := err == nil && os.PathSeparator != '\\' && info.Mode().Perm()&0o077 != 0
	if err != nil || !info.Mode().IsRegular() || unsafePermissions {
		t.Fatalf("runtime grant file permissions are unsafe: mode=%v err=%v", info, err)
	}
}

func TestRuntimeSecretsSyncRejectsBroadOrHostileRequests(t *testing.T) {
	t.Parallel()
	temporaryRoot := t.TempDir()
	helper, err := NewWithTemporaryRoot(t.TempDir(), temporaryRoot)
	if err != nil {
		t.Fatal(err)
	}

	tooBroad := callRaw(t, helper, Request{
		Version: Version, Operation: OpRuntimeSecretsSync,
		GrantedSecrets: map[string][]byte{"SAFE_NAME": []byte("bounded-value")},
		Repository:     "owner/repository",
	})
	if tooBroad.OK || tooBroad.ErrorCode != "invalid" {
		t.Fatalf("runtime sync accepted unrelated authority: %#v", tooBroad)
	}
	reserved := callRaw(t, helper, Request{
		Version: Version, Operation: OpRuntimeSecretsSync,
		GrantedSecrets: map[string][]byte{"PATH": []byte("/hostile")},
	})
	if reserved.OK || reserved.ErrorCode != "invalid" {
		t.Fatalf("runtime sync accepted a reserved environment name: %#v", reserved)
	}

	outside := filepath.Join(t.TempDir(), "outside.json")
	outsideContent := []byte("must-not-change")
	if err := os.WriteFile(outside, outsideContent, 0o600); err != nil {
		t.Fatal(err)
	}
	runtimeDir := filepath.Dir(runtimeSecretsPath(temporaryRoot))
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, runtimeSecretsPath(temporaryRoot)); err != nil {
		if os.IsPermission(err) {
			t.Skipf("symlinks unavailable: %v", err)
		}
		t.Fatal(err)
	}
	blocked := callRaw(t, helper, Request{
		Version: Version, Operation: OpRuntimeSecretsSync,
		GrantedSecrets: map[string][]byte{"SAFE_NAME": []byte("bounded-value")},
	})
	if blocked.OK || blocked.ErrorCode != "precondition" {
		t.Fatalf("runtime sync followed a hostile secret-state symlink: %#v", blocked)
	}
	actual, err := os.ReadFile(outside)
	if err != nil || !bytes.Equal(actual, outsideContent) {
		t.Fatalf("runtime sync modified the symlink target: %q err=%v", actual, err)
	}
}
