package postgres

import (
	"bytes"
	"testing"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/passkeys"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/vault"
	"github.com/go-webauthn/webauthn/webauthn"
)

func TestPasskeyCredentialEnvelopeRoundTripAndAADBinding(t *testing.T) {
	master := bytes.Repeat([]byte{0x42}, 32)
	cipher, err := vault.NewWithRandom(master, bytes.NewReader(bytes.Repeat([]byte{0x24}, 256)))
	if err != nil {
		t.Fatal(err)
	}
	store := &PasskeyStore{cipher: cipher}
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	record := passkeys.CredentialRecord{
		RPID: "codex.example.test", OwnerID: "owner-1", DeviceID: "device-1", DeviceName: "Phone",
		Credential: webauthn.Credential{
			ID: []byte("credential-id"), PublicKey: []byte("public-key-material"),
			Authenticator: webauthn.Authenticator{SignCount: 7},
		},
		CreatedAt: now,
	}
	ciphertext, err := store.encryptCredential(record)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, record.Credential.PublicKey) {
		t.Fatal("credential public key was stored in readable form")
	}
	decoded, err := store.decryptCredential(record, record.Credential.ID, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.ID, record.Credential.ID) || decoded.Authenticator.SignCount != 7 {
		t.Fatalf("credential did not round-trip: %#v", decoded)
	}
	tampered := record
	tampered.OwnerID = "owner-2"
	if _, err := store.decryptCredential(tampered, record.Credential.ID, ciphertext); err == nil {
		t.Fatal("credential decrypted under a different owner AAD")
	}
}
