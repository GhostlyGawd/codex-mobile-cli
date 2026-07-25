package postgres

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/vault"
)

type fakeMasterKeyRotationTx struct {
	passkeys []rotationPasskeyRow
	secrets  []rotationSecretRow
	apns     []rotationAPNSRow

	failUpdateAt int
	updateCalls  int
	pending      map[string][]byte
	durable      map[string][]byte
	audit        MasterKeyRotationSummary
	committed    bool
	rolledBack   bool
}

func (f *fakeMasterKeyRotationTx) LoadPasskeys(context.Context) ([]rotationPasskeyRow, error) {
	return f.passkeys, nil
}

func (f *fakeMasterKeyRotationTx) LoadEncryptedSecrets(context.Context) ([]rotationSecretRow, error) {
	return f.secrets, nil
}

func (f *fakeMasterKeyRotationTx) LoadAPNSTokens(context.Context) ([]rotationAPNSRow, error) {
	return f.apns, nil
}

func (f *fakeMasterKeyRotationTx) update(key string, envelope []byte) error {
	f.updateCalls++
	if f.failUpdateAt > 0 && f.updateCalls == f.failUpdateAt {
		return errors.New("injected transactional update failure")
	}
	if f.pending == nil {
		f.pending = make(map[string][]byte)
	}
	f.pending[key] = bytes.Clone(envelope)
	return nil
}

func (f *fakeMasterKeyRotationTx) UpdatePasskey(_ context.Context, row rotationPasskeyRow, envelope []byte) error {
	return f.update("passkey:"+row.RPID, envelope)
}

func (f *fakeMasterKeyRotationTx) UpdateEncryptedSecret(_ context.Context, row rotationSecretRow, envelope []byte, _ [32]byte, _ time.Time) error {
	return f.update("secret:"+row.ID, envelope)
}

func (f *fakeMasterKeyRotationTx) UpdateAPNSToken(_ context.Context, row rotationAPNSRow, envelope []byte, _ time.Time) error {
	return f.update("apns:"+row.ID, envelope)
}

func (f *fakeMasterKeyRotationTx) InsertAudit(_ context.Context, summary MasterKeyRotationSummary, _ time.Time) error {
	f.audit = summary
	return nil
}

func (f *fakeMasterKeyRotationTx) Commit(context.Context) error {
	f.durable = make(map[string][]byte, len(f.pending))
	for key, value := range f.pending {
		f.durable[key] = bytes.Clone(value)
	}
	f.committed = true
	return nil
}

func (f *fakeMasterKeyRotationTx) Rollback(context.Context) error {
	for key, value := range f.pending {
		clear(value)
		delete(f.pending, key)
	}
	f.rolledBack = true
	return nil
}

func encryptedRotationFixture(t *testing.T, cipher *vault.Vault, plaintext, aad []byte) []byte {
	t.Helper()
	envelope, err := cipher.Encrypt(plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := envelope.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func verifyRotatedFixture(t *testing.T, cipher *vault.Vault, encoded, aad, expected []byte) {
	t.Helper()
	envelope, err := vault.Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := cipher.Decrypt(envelope, aad)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plaintext)
	if !bytes.Equal(plaintext, expected) {
		t.Fatal("rotated plaintext did not authenticate under the new key")
	}
}

func TestMasterKeyRotationRewrapsEveryAADFamilyBeforeCommit(t *testing.T) {
	oldMaster := bytes.Repeat([]byte{0x11}, 32)
	newMaster := bytes.Repeat([]byte{0x22}, 32)
	current, _ := vault.New(oldMaster)
	next, _ := vault.New(newMaster)
	repositoryID, workspaceID := "repository-1", "workspace-1"
	userSize := len("user-secret-value")

	passkey := rotationPasskeyRow{RPID: "codex.example", CredentialID: []byte("credential-1"), OwnerID: "owner-1", DeviceID: "device-1"}
	passkey.Envelope = encryptedRotationFixture(t, current, []byte("passkey-record"), passkeyAAD(passkey.RPID, passkey.OwnerID, passkey.DeviceID, passkey.CredentialID))
	userSecret := rotationSecretRow{ID: "user-secret-1", OwnerID: "owner-1", Name: "TOKEN", AADVersion: 1, PlaintextSize: &userSize}
	userSecret.Envelope = encryptedRotationFixture(t, current, []byte("user-secret-value"), userSecretAAD(userSecret.OwnerID, nil, userSecret.ID, userSecret.Name))
	repositorySecret := rotationSecretRow{ID: "repository-secret-1", OwnerID: "owner-1", RepositoryID: &repositoryID, Name: "REPOSITORY_TOKEN", AADVersion: 1, PlaintextSize: &userSize}
	repositorySecret.Envelope = encryptedRotationFixture(t, current, []byte("user-secret-value"), userSecretAAD(repositorySecret.OwnerID, &repositoryID, repositorySecret.ID, repositorySecret.Name))
	environment := rotationSecretRow{ID: "env-1", OwnerID: "owner-1", RepositoryID: &repositoryID, WorkspaceID: &workspaceID, Name: workspaceEnvironmentName(workspaceID, "PRIVATE_VALUE"), AADVersion: 1}
	environment.Envelope = encryptedRotationFixture(t, current, []byte("environment-value"), workspaceEnvironmentAAD(environment.OwnerID, repositoryID, workspaceID, "PRIVATE_VALUE"))
	prompt := rotationSecretRow{ID: "prompt-1", OwnerID: "owner-1", RepositoryID: &repositoryID, WorkspaceID: &workspaceID, Name: workspaceInitialPromptName(workspaceID), AADVersion: 1}
	prompt.Envelope = encryptedRotationFixture(t, current, []byte("soft-deleted prompt"), workspaceInitialPromptAAD(prompt.OwnerID, repositoryID, workspaceID))
	auth := rotationSecretRow{ID: "auth-1", OwnerID: "owner-1", RepositoryID: &repositoryID, WorkspaceID: &workspaceID, Name: workspaceCodexAuthKeyName(workspaceID), AADVersion: 1}
	auth.Envelope = encryptedRotationFixture(t, current, bytes.Repeat([]byte{0x31}, 32), workspaceCodexAuthKeyAAD(auth.OwnerID, repositoryID, workspaceID))
	apns := rotationAPNSRow{ID: "apns-1", OwnerID: "owner-1", DeviceID: "device-1", Provider: "apns", Environment: "production"}
	apns.Envelope = encryptedRotationFixture(t, current, []byte(strings.Repeat("ab", 32)), notificationAAD(apns.OwnerID, apns.DeviceID, apns.Environment))

	tx := &fakeMasterKeyRotationTx{passkeys: []rotationPasskeyRow{passkey}, secrets: []rotationSecretRow{userSecret, repositorySecret, environment, prompt, auth}, apns: []rotationAPNSRow{apns}}
	summary, err := executeMasterKeyRotation(context.Background(), tx, current, next, newMaster, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if !tx.committed || tx.rolledBack || summary != (MasterKeyRotationSummary{Passkeys: 1, EncryptedSecrets: 5, APNSTokens: 1}) || tx.audit != summary {
		t.Fatalf("rotation state = committed=%v rolled_back=%v summary=%+v audit=%+v", tx.committed, tx.rolledBack, summary, tx.audit)
	}
	verifyRotatedFixture(t, next, tx.durable["passkey:codex.example"], passkeyAAD(passkey.RPID, passkey.OwnerID, passkey.DeviceID, []byte("credential-1")), []byte("passkey-record"))
	verifyRotatedFixture(t, next, tx.durable["secret:user-secret-1"], userSecretAAD("owner-1", nil, "user-secret-1", "TOKEN"), []byte("user-secret-value"))
	verifyRotatedFixture(t, next, tx.durable["secret:repository-secret-1"], userSecretAAD("owner-1", &repositoryID, "repository-secret-1", "REPOSITORY_TOKEN"), []byte("user-secret-value"))
	verifyRotatedFixture(t, next, tx.durable["secret:env-1"], workspaceEnvironmentAAD("owner-1", repositoryID, workspaceID, "PRIVATE_VALUE"), []byte("environment-value"))
	verifyRotatedFixture(t, next, tx.durable["secret:prompt-1"], workspaceInitialPromptAAD("owner-1", repositoryID, workspaceID), []byte("soft-deleted prompt"))
	verifyRotatedFixture(t, next, tx.durable["secret:auth-1"], workspaceCodexAuthKeyAAD("owner-1", repositoryID, workspaceID), bytes.Repeat([]byte{0x31}, 32))
	verifyRotatedFixture(t, next, tx.durable["apns:apns-1"], notificationAAD("owner-1", "device-1", "production"), []byte(strings.Repeat("ab", 32)))
}

func TestMasterKeyRotationTamperAndUnknownRowsAbortBeforeUpdates(t *testing.T) {
	oldMaster := bytes.Repeat([]byte{0x41}, 32)
	newMaster := bytes.Repeat([]byte{0x42}, 32)
	current, _ := vault.New(oldMaster)
	next, _ := vault.New(newMaster)
	secretSize := len("never-disclose-this")

	tests := []struct {
		name string
		row  rotationSecretRow
	}{
		{
			name: "tampered envelope",
			row: rotationSecretRow{ID: "tampered-row", OwnerID: "owner-1", Name: "TOKEN", AADVersion: 1,
				PlaintextSize: &secretSize, Envelope: []byte(`{"v":1,"wk":"tampered"}`)},
		},
		{
			name: "unknown legacy row",
			row: rotationSecretRow{ID: "legacy-row", OwnerID: "owner-1", Name: "legacy-secret", AADVersion: 1,
				Envelope: []byte("never-disclose-this")},
		},
		{
			name: "unsupported aad version",
			row: rotationSecretRow{ID: "aad-v2-row", OwnerID: "owner-1", Name: "TOKEN", AADVersion: 2,
				PlaintextSize: &secretSize, Envelope: []byte("never-disclose-this")},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tx := &fakeMasterKeyRotationTx{secrets: []rotationSecretRow{test.row}}
			_, err := executeMasterKeyRotation(context.Background(), tx, current, next, newMaster, time.Now().UTC())
			if err == nil || tx.committed || !tx.rolledBack || tx.updateCalls != 0 {
				t.Fatalf("unsafe row rotation = err=%v committed=%v rolled_back=%v updates=%d", err, tx.committed, tx.rolledBack, tx.updateCalls)
			}
			if !strings.Contains(err.Error(), test.row.ID) || strings.Contains(err.Error(), "never-disclose-this") {
				t.Fatalf("rotation error must identify metadata only: %q", err)
			}
		})
	}
}

func TestMasterKeyRotationRollsBackPartialApplyFailure(t *testing.T) {
	oldMaster := bytes.Repeat([]byte{0x51}, 32)
	newMaster := bytes.Repeat([]byte{0x52}, 32)
	current, _ := vault.New(oldMaster)
	next, _ := vault.New(newMaster)
	size := len("first-secret")
	first := rotationSecretRow{ID: "first", OwnerID: "owner-1", Name: "FIRST", AADVersion: 1, PlaintextSize: &size}
	first.Envelope = encryptedRotationFixture(t, current, []byte("first-secret"), userSecretAAD(first.OwnerID, nil, first.ID, first.Name))
	second := rotationSecretRow{ID: "second", OwnerID: "owner-1", Name: "SECOND", AADVersion: 1, PlaintextSize: &size}
	second.Envelope = encryptedRotationFixture(t, current, []byte("first-secret"), userSecretAAD(second.OwnerID, nil, second.ID, second.Name))
	tx := &fakeMasterKeyRotationTx{secrets: []rotationSecretRow{first, second}, failUpdateAt: 2}
	if _, err := executeMasterKeyRotation(context.Background(), tx, current, next, newMaster, time.Now().UTC()); err == nil {
		t.Fatal("injected update failure committed")
	}
	if tx.committed || !tx.rolledBack || len(tx.durable) != 0 || len(tx.pending) != 0 {
		t.Fatalf("partial rotation escaped rollback: committed=%v rolled_back=%v durable=%d pending=%d", tx.committed, tx.rolledBack, len(tx.durable), len(tx.pending))
	}
}
