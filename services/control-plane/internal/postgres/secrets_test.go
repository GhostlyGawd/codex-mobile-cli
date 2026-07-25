package postgres

import (
	"bytes"
	"errors"
	"testing"

	secretmodel "github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/secrets"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/vault"
)

func TestUserSecretEncryptionUsesStableScopeBoundAAD(t *testing.T) {
	t.Parallel()
	cipher, err := vault.NewWithRandom(bytes.Repeat([]byte{0x11}, 32), bytes.NewReader(bytes.Repeat([]byte{0x22}, 256)))
	if err != nil {
		t.Fatal(err)
	}
	store := &ApplicationStore{cipher: cipher}
	repositoryID := "repo-1"
	metadata := secretmodel.Metadata{ID: "secret-1", OwnerID: "owner-1", RepositoryID: &repositoryID, Name: "TOKEN"}
	plaintext := []byte("not-readable-at-rest")
	encoded, _, err := store.encryptUserSecret(metadata, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, plaintext) {
		t.Fatal("plaintext remained in serialized envelope")
	}
	envelope, err := vault.Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cipher.Decrypt(envelope, userSecretAAD(metadata.OwnerID, metadata.RepositoryID, metadata.ID, metadata.Name))
	if err != nil || !bytes.Equal(decoded, plaintext) {
		t.Fatalf("decrypt = %q, %v", decoded, err)
	}
	if _, err := cipher.Decrypt(envelope, userSecretAAD(metadata.OwnerID, nil, metadata.ID, metadata.Name)); !errors.Is(err, vault.ErrAuthentication) {
		t.Fatalf("repository secret decrypted as global: %v", err)
	}
}
