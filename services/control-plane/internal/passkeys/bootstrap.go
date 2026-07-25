package passkeys

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"sync"
	"time"
)

var ErrInvalidBootstrap = errors.New("invalid or expired bootstrap credential")

// BootstrapRecord contains only the keyed hash of a short-lived bootstrap
// credential. The plaintext is returned once to the audited console command
// and is never persisted.
type BootstrapRecord struct {
	ID              string
	TokenHash       [32]byte
	RecoveryOwnerID string
	CreatedAt       time.Time
	ExpiresAt       time.Time
}

// BootstrapStore makes bootstrap credentials usable across control-plane
// processes. Replace and Consume must be atomic within their implementation.
type BootstrapStore interface {
	Replace(context.Context, BootstrapRecord) error
	IsValid(context.Context, [32]byte, time.Time) (bool, error)
	RecoveryOwner(context.Context, [32]byte, time.Time) (string, error)
	Consume(context.Context, [32]byte, time.Time) error
	Disable(context.Context, time.Time) error
	Available(context.Context, time.Time) (bool, error)
}

type BootstrapManager struct {
	pepper []byte
	random io.Reader
	now    func() time.Time
	ttl    time.Duration
	store  BootstrapStore
}

func NewBootstrapManager(pepper []byte, ttl time.Duration) (*BootstrapManager, error) {
	return NewBootstrapManagerWithStoreAndDependencies(
		pepper, ttl, NewMemoryBootstrapStore(), rand.Reader,
		func() time.Time { return time.Now().UTC() },
	)
}

func NewBootstrapManagerWithStore(pepper []byte, ttl time.Duration, store BootstrapStore) (*BootstrapManager, error) {
	return NewBootstrapManagerWithStoreAndDependencies(
		pepper, ttl, store, rand.Reader,
		func() time.Time { return time.Now().UTC() },
	)
}

func NewBootstrapManagerWithDependencies(pepper []byte, ttl time.Duration, random io.Reader, now func() time.Time) (*BootstrapManager, error) {
	return NewBootstrapManagerWithStoreAndDependencies(pepper, ttl, NewMemoryBootstrapStore(), random, now)
}

func NewBootstrapManagerWithStoreAndDependencies(pepper []byte, ttl time.Duration, store BootstrapStore, random io.Reader, now func() time.Time) (*BootstrapManager, error) {
	if len(pepper) < 32 || ttl <= 0 || ttl > time.Hour || store == nil || random == nil || now == nil {
		return nil, errors.New("invalid bootstrap manager configuration")
	}
	return &BootstrapManager{
		pepper: append([]byte(nil), pepper...), ttl: ttl, store: store,
		random: random, now: now,
	}, nil
}

// Generate returns the only plaintext copy of a new bootstrap credential. It
// is intended for an audited console command and invalidates any prior token.
func (m *BootstrapManager) Generate() (string, time.Time, error) {
	return m.GenerateContext(context.Background())
}

func (m *BootstrapManager) GenerateContext(ctx context.Context) (string, time.Time, error) {
	if ctx == nil {
		return "", time.Time{}, errors.New("bootstrap context is required")
	}
	token, record, err := m.newRecord("")
	if err != nil {
		return "", time.Time{}, err
	}
	if err := m.store.Replace(ctx, record); err != nil {
		return "", time.Time{}, err
	}
	return token, record.ExpiresAt, nil
}

// NewRecoveryRecord creates the only plaintext copy of a recovery credential
// without persisting it. The PostgreSQL recovery transaction must atomically
// revoke the prior enrollment and insert this record before it is printed.
func (m *BootstrapManager) NewRecoveryRecord(ownerID string) (string, BootstrapRecord, error) {
	if ownerID == "" {
		return "", BootstrapRecord{}, errors.New("recovery owner is required")
	}
	return m.newRecord(ownerID)
}

func (m *BootstrapManager) newRecord(recoveryOwnerID string) (string, BootstrapRecord, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(m.random, b); err != nil {
		return "", BootstrapRecord{}, err
	}
	defer func() {
		for index := range b {
			b[index] = 0
		}
	}()
	token := "bt_" + base64.RawURLEncoding.EncodeToString(b)
	hash := m.tokenHash(token)
	created := m.now()
	return token, BootstrapRecord{
		ID: "bootstrap_" + hex.EncodeToString(hash[:16]), TokenHash: hash,
		RecoveryOwnerID: recoveryOwnerID, CreatedAt: created, ExpiresAt: created.Add(m.ttl),
	}, nil
}

func (m *BootstrapManager) Validate(token string) error {
	return m.ValidateContext(context.Background(), token)
}

func (m *BootstrapManager) ValidateContext(ctx context.Context, token string) error {
	if ctx == nil || !validBootstrapToken(token) {
		return ErrInvalidBootstrap
	}
	valid, err := m.store.IsValid(ctx, m.tokenHash(token), m.now())
	if err != nil {
		return err
	}
	if !valid {
		return ErrInvalidBootstrap
	}
	return nil
}

func (m *BootstrapManager) recoveryOwnerContext(ctx context.Context, token string) (string, error) {
	if ctx == nil || !validBootstrapToken(token) {
		return "", ErrInvalidBootstrap
	}
	return m.store.RecoveryOwner(ctx, m.tokenHash(token), m.now())
}

func (m *BootstrapManager) Consume(token string) error {
	return m.ConsumeContext(context.Background(), token)
}

func (m *BootstrapManager) ConsumeContext(ctx context.Context, token string) error {
	if ctx == nil || !validBootstrapToken(token) {
		return ErrInvalidBootstrap
	}
	if err := m.store.Consume(ctx, m.tokenHash(token), m.now()); err != nil {
		return err
	}
	return nil
}

func (m *BootstrapManager) Disable() error {
	return m.DisableContext(context.Background())
}

func (m *BootstrapManager) DisableContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("bootstrap context is required")
	}
	return m.store.Disable(ctx, m.now())
}

func (m *BootstrapManager) Available(ctx context.Context) (bool, error) {
	if ctx == nil {
		return false, errors.New("bootstrap context is required")
	}
	return m.store.Available(ctx, m.now())
}

func (m *BootstrapManager) tokenHash(token string) [32]byte {
	h := hmac.New(sha256.New, m.pepper)
	h.Write([]byte("codex-mobile:bootstrap:v1:"))
	h.Write([]byte(token))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func validBootstrapToken(token string) bool {
	if !strings.HasPrefix(token, "bt_") || len(token) > 128 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, "bt_"))
	return err == nil && len(decoded) == 32
}

// MemoryBootstrapStore is used by unit tests and local in-process
// development. Production uses the PostgreSQL implementation.
type MemoryBootstrapStore struct {
	mu       sync.Mutex
	record   BootstrapRecord
	active   bool
	consumed bool
}

func NewMemoryBootstrapStore() *MemoryBootstrapStore { return &MemoryBootstrapStore{} }

func (s *MemoryBootstrapStore) Replace(_ context.Context, record BootstrapRecord) error {
	if record.ID == "" || record.CreatedAt.IsZero() || !record.ExpiresAt.After(record.CreatedAt) {
		return errors.New("invalid bootstrap record")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.record, s.active, s.consumed = record, true, false
	return nil
}

func (s *MemoryBootstrapStore) IsValid(_ context.Context, hash [32]byte, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.matches(hash, now), nil
}

func (s *MemoryBootstrapStore) RecoveryOwner(_ context.Context, hash [32]byte, now time.Time) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.matches(hash, now) {
		return "", ErrInvalidBootstrap
	}
	return s.record.RecoveryOwnerID, nil
}

func (s *MemoryBootstrapStore) Consume(_ context.Context, hash [32]byte, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.matches(hash, now) {
		return ErrInvalidBootstrap
	}
	s.active, s.consumed = false, true
	return nil
}

func (s *MemoryBootstrapStore) Disable(_ context.Context, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active, s.consumed = false, true
	s.record.TokenHash = [32]byte{}
	return nil
}

func (s *MemoryBootstrapStore) Available(_ context.Context, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active && !s.consumed && now.Before(s.record.ExpiresAt), nil
}

func (s *MemoryBootstrapStore) matches(hash [32]byte, now time.Time) bool {
	return s.active && !s.consumed && now.Before(s.record.ExpiresAt) &&
		subtle.ConstantTimeCompare(s.record.TokenHash[:], hash[:]) == 1
}

var _ BootstrapStore = (*MemoryBootstrapStore)(nil)
