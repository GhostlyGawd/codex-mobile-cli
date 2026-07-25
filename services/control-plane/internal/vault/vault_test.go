package vault

import (
	"bytes"
	"errors"
	"testing"
)

func TestEnvelopeRoundTripAndAADBinding(t *testing.T) {
	t.Parallel()
	master := bytes.Repeat([]byte{1}, 32)
	v, err := New(master)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := v.Encrypt([]byte("top secret"), []byte("owner/secret-id"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := v.Decrypt(envelope, []byte("owner/secret-id"))
	if err != nil || string(plaintext) != "top secret" {
		t.Fatalf("decrypt = %q, %v", plaintext, err)
	}
	if _, err := v.Decrypt(envelope, []byte("another-owner/secret-id")); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("expected AAD authentication failure, got %v", err)
	}
}

func TestTamperingRejected(t *testing.T) {
	t.Parallel()
	v, _ := New(bytes.Repeat([]byte{2}, 32))
	envelope, _ := v.Encrypt([]byte("secret"), []byte("scope"))
	tampered := []byte(envelope.Ciphertext)
	if tampered[0] == 'A' {
		tampered[0] = 'B'
	} else {
		tampered[0] = 'A'
	}
	envelope.Ciphertext = string(tampered)
	if _, err := v.Decrypt(envelope, []byte("scope")); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("expected tamper rejection, got %v", err)
	}
}

func TestMasterKeyRotationRewrapsWithoutChangingCiphertext(t *testing.T) {
	t.Parallel()
	oldKey := bytes.Repeat([]byte{3}, 32)
	newKey := bytes.Repeat([]byte{4}, 32)
	oldVault, _ := New(oldKey)
	envelope, _ := oldVault.Encrypt([]byte("rotatable"), []byte("scope"))
	oldCiphertext := envelope.Ciphertext
	rewrapped, err := oldVault.Rewrap(envelope, []byte("scope"), newKey)
	if err != nil {
		t.Fatal(err)
	}
	if rewrapped.Ciphertext != oldCiphertext {
		t.Fatal("data ciphertext changed during key rewrap")
	}
	newVault, _ := New(newKey)
	plain, err := newVault.Decrypt(rewrapped, []byte("scope"))
	if err != nil || string(plain) != "rotatable" {
		t.Fatalf("new-key decrypt = %q, %v", plain, err)
	}
	if _, err := oldVault.Decrypt(rewrapped, []byte("scope")); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("old key unexpectedly decrypts rewrapped envelope: %v", err)
	}
}

func TestEnvelopeSerialization(t *testing.T) {
	t.Parallel()
	v, _ := New(bytes.Repeat([]byte{5}, 32))
	envelope, _ := v.Encrypt(nil, []byte("scope"))
	b, err := envelope.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(b)
	if err != nil || parsed.Version != version {
		t.Fatalf("parse = %#v, %v", parsed, err)
	}
}

func TestDestroyWipesOwnedMasterKey(t *testing.T) {
	v, _ := New(bytes.Repeat([]byte{6}, 32))
	v.Destroy()
	if len(v.master) != 0 {
		t.Fatal("destroy retained the owned master-key buffer")
	}
	if _, err := v.Encrypt([]byte("secret"), []byte("scope")); err == nil {
		t.Fatal("destroyed vault remained usable")
	}
}
