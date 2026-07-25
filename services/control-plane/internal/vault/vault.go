package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	version      = 1
	keySize      = 32
	nonceSize    = 12
	maxPlaintext = 1024 * 1024
)

var ErrAuthentication = errors.New("vault authentication failed")

type Envelope struct {
	Version    int    `json:"v"`
	WrappedKey string `json:"wk"`
	KeyNonce   string `json:"kn"`
	Ciphertext string `json:"ct"`
	DataNonce  string `json:"dn"`
}

type Vault struct {
	master []byte
	random io.Reader
}

// Destroy wipes this Vault's owned master-key buffer. The caller must ensure
// no concurrent encryption operation is using the Vault.
func (v *Vault) Destroy() {
	if v == nil {
		return
	}
	wipe(v.master)
	v.master = nil
}

func New(master []byte) (*Vault, error) {
	return NewWithRandom(master, rand.Reader)
}

func NewWithRandom(master []byte, random io.Reader) (*Vault, error) {
	if len(master) != keySize {
		return nil, fmt.Errorf("master key must be %d bytes", keySize)
	}
	if random == nil {
		return nil, errors.New("random source is required")
	}
	return &Vault{master: append([]byte(nil), master...), random: random}, nil
}

func (v *Vault) Encrypt(plaintext, aad []byte) (Envelope, error) {
	if len(plaintext) > maxPlaintext {
		return Envelope{}, fmt.Errorf("secret exceeds %d bytes", maxPlaintext)
	}
	dataKey := make([]byte, keySize)
	if _, err := io.ReadFull(v.random, dataKey); err != nil {
		return Envelope{}, fmt.Errorf("generate data key: %w", err)
	}
	defer wipe(dataKey)
	dataNonce, ciphertext, err := seal(dataKey, plaintext, dataAAD(aad), v.random)
	if err != nil {
		return Envelope{}, err
	}
	keyNonce, wrapped, err := seal(v.master, dataKey, keyAAD(aad), v.random)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{
		Version:    version,
		WrappedKey: encode(wrapped),
		KeyNonce:   encode(keyNonce),
		Ciphertext: encode(ciphertext),
		DataNonce:  encode(dataNonce),
	}, nil
}

func (v *Vault) Decrypt(envelope Envelope, aad []byte) ([]byte, error) {
	dataKey, err := v.unwrap(envelope, aad)
	if err != nil {
		return nil, err
	}
	defer wipe(dataKey)
	dataNonce, err := decode(envelope.DataNonce)
	if err != nil {
		return nil, ErrAuthentication
	}
	ciphertext, err := decode(envelope.Ciphertext)
	if err != nil {
		return nil, ErrAuthentication
	}
	plaintext, err := open(dataKey, dataNonce, ciphertext, dataAAD(aad))
	if err != nil {
		return nil, ErrAuthentication
	}
	return plaintext, nil
}

func (v *Vault) Rewrap(envelope Envelope, aad, newMaster []byte) (Envelope, error) {
	if len(newMaster) != keySize {
		return Envelope{}, fmt.Errorf("new master key must be %d bytes", keySize)
	}
	dataKey, err := v.unwrap(envelope, aad)
	if err != nil {
		return Envelope{}, err
	}
	defer wipe(dataKey)
	nonce, wrapped, err := seal(newMaster, dataKey, keyAAD(aad), v.random)
	if err != nil {
		return Envelope{}, err
	}
	envelope.KeyNonce = encode(nonce)
	envelope.WrappedKey = encode(wrapped)
	return envelope, nil
}

func (v *Vault) unwrap(envelope Envelope, aad []byte) ([]byte, error) {
	if envelope.Version != version {
		return nil, ErrAuthentication
	}
	nonce, err := decode(envelope.KeyNonce)
	if err != nil {
		return nil, ErrAuthentication
	}
	wrapped, err := decode(envelope.WrappedKey)
	if err != nil {
		return nil, ErrAuthentication
	}
	key, err := open(v.master, nonce, wrapped, keyAAD(aad))
	if err != nil || len(key) != keySize {
		wipe(key)
		return nil, ErrAuthentication
	}
	return key, nil
}

func (e Envelope) Marshal() ([]byte, error) { return json.Marshal(e) }

func Parse(data []byte) (Envelope, error) {
	var envelope Envelope
	if len(data) > 4*maxPlaintext {
		return Envelope{}, errors.New("envelope too large")
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return Envelope{}, fmt.Errorf("parse envelope: %w", err)
	}
	return envelope, nil
}

func seal(key, plaintext, aad []byte, random io.Reader) ([]byte, []byte, error) {
	aead, err := aead(key)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(random, nonce); err != nil {
		return nil, nil, fmt.Errorf("generate nonce: %w", err)
	}
	return nonce, aead.Seal(nil, nonce, plaintext, aad), nil
}

func open(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, err := aead(key)
	if err != nil || len(nonce) != nonceSize {
		return nil, ErrAuthentication
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}

func aead(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func encode(b []byte) string          { return base64.RawURLEncoding.EncodeToString(b) }
func decode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
func dataAAD(aad []byte) []byte       { return append([]byte("codex-mobile:v1:data:"), aad...) }
func keyAAD(aad []byte) []byte        { return append([]byte("codex-mobile:v1:key:"), aad...) }

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
