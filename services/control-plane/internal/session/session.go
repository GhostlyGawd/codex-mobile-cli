package session

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

var ErrReplay = errors.New("refresh credential replay detected")

type Kind string

const (
	Access  Kind = "access"
	Refresh Kind = "refresh"
)

type Record struct {
	ID        string
	FamilyID  string
	OwnerID   string
	DeviceID  string
	Kind      Kind
	Hash      [32]byte
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    *time.Time
	RevokedAt *time.Time
}

type Principal struct {
	OwnerID  string
	DeviceID string
	FamilyID string
}

type Pair struct {
	AccessToken      string    `json:"access_token"`
	AccessExpiresAt  time.Time `json:"access_expires_at"`
	RefreshToken     string    `json:"refresh_token"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
	DeviceID         string    `json:"device_id"`
}

type Device struct {
	ID         string
	OwnerID    string
	Name       string
	Platform   string
	CreatedAt  time.Time
	LastSeenAt time.Time
}

type Store interface {
	CreatePair(context.Context, Record, Record) error
	Get(context.Context, string) (Record, error)
	ValidatePrincipal(context.Context, Principal) error
	Rotate(context.Context, string, [32]byte, time.Time, Record, Record) error
	RevokeFamily(context.Context, string, time.Time) error
	ListDevices(context.Context, string) ([]Device, error)
	RevokeDevice(context.Context, string, string, time.Time) error
}

type Clock interface{ Now() time.Time }

type realClock struct{}

func (realClock) Now() time.Time { return time.Now().UTC() }

type Manager struct {
	store      Store
	pepper     []byte
	random     io.Reader
	clock      Clock
	accessTTL  time.Duration
	refreshTTL time.Duration
}

func New(store Store, pepper []byte, accessTTL, refreshTTL time.Duration) (*Manager, error) {
	return NewWithDependencies(store, pepper, accessTTL, refreshTTL, rand.Reader, realClock{})
}

func NewWithDependencies(store Store, pepper []byte, accessTTL, refreshTTL time.Duration, random io.Reader, clock Clock) (*Manager, error) {
	if store == nil || len(pepper) < 32 || random == nil || clock == nil {
		return nil, errors.New("store, >=32-byte pepper, random source, and clock are required")
	}
	if accessTTL <= 0 || accessTTL > time.Hour || refreshTTL <= accessTTL {
		return nil, errors.New("invalid session lifetimes")
	}
	return &Manager{store: store, pepper: append([]byte(nil), pepper...), random: random, clock: clock, accessTTL: accessTTL, refreshTTL: refreshTTL}, nil
}

func (m *Manager) Issue(ctx context.Context, ownerID, deviceID string) (Pair, error) {
	if ownerID == "" || deviceID == "" {
		return Pair{}, errors.New("owner and device are required")
	}
	familyID, err := randomPart(m.random, 16)
	if err != nil {
		return Pair{}, err
	}
	return m.issue(ctx, ownerID, deviceID, familyID, false, "", [32]byte{})
}

func (m *Manager) Authenticate(ctx context.Context, token string) (Principal, error) {
	id, secret, err := parseToken(token, Access)
	if err != nil {
		return Principal{}, err
	}
	record, err := m.store.Get(ctx, id)
	if err != nil || record.Kind != Access || record.UsedAt != nil || record.RevokedAt != nil || !m.clock.Now().Before(record.ExpiresAt) {
		return Principal{}, errors.New("invalid access credential")
	}
	presentedHash := m.hash(Access, id, secret)
	if subtle.ConstantTimeCompare(record.Hash[:], presentedHash[:]) != 1 {
		return Principal{}, errors.New("invalid access credential")
	}
	return Principal{OwnerID: record.OwnerID, DeviceID: record.DeviceID, FamilyID: record.FamilyID}, nil
}

// RefreshPrincipal verifies a refresh credential and returns only its bounded
// owner/device/family identity. It deliberately accepts an already-used token
// so the application can acquire the matching terminal admission gate before
// Rotate atomically records replay and sweeps secondary terminal credentials.
func (m *Manager) RefreshPrincipal(ctx context.Context, token string) (Principal, error) {
	record, _, err := m.refreshRecord(ctx, token)
	if err != nil {
		return Principal{}, err
	}
	return Principal{OwnerID: record.OwnerID, DeviceID: record.DeviceID, FamilyID: record.FamilyID}, nil
}

// ValidatePrincipal re-checks the durable family and device revocation state
// for an already authenticated request. It is intentionally token-free: the
// access credential remains confined to the HTTP authentication boundary.
// Callers use this immediately before issuing a secondary credential whose
// lifetime could otherwise cross a concurrent session revocation.
func (m *Manager) ValidatePrincipal(ctx context.Context, principal Principal) error {
	if principal.OwnerID == "" || principal.DeviceID == "" || principal.FamilyID == "" {
		return errors.New("session principal is incomplete")
	}
	return m.store.ValidatePrincipal(ctx, principal)
}

func (m *Manager) Rotate(ctx context.Context, token string) (Pair, error) {
	record, hash, err := m.refreshRecord(ctx, token)
	if err != nil {
		return Pair{}, err
	}
	if record.UsedAt != nil {
		if err := m.store.RevokeFamily(ctx, record.FamilyID, m.clock.Now()); err != nil {
			return Pair{}, fmt.Errorf("revoke replayed refresh family: %w", err)
		}
		return Pair{}, ErrReplay
	}
	return m.issue(ctx, record.OwnerID, record.DeviceID, record.FamilyID, true, record.ID, hash)
}

func (m *Manager) refreshRecord(ctx context.Context, token string) (Record, [32]byte, error) {
	id, secret, err := parseToken(token, Refresh)
	if err != nil {
		return Record{}, [32]byte{}, err
	}
	hash := m.hash(Refresh, id, secret)
	record, err := m.store.Get(ctx, id)
	if err != nil || record.Kind != Refresh || record.RevokedAt != nil || !m.clock.Now().Before(record.ExpiresAt) {
		return Record{}, [32]byte{}, errors.New("invalid refresh credential")
	}
	if subtle.ConstantTimeCompare(record.Hash[:], hash[:]) != 1 {
		return Record{}, [32]byte{}, errors.New("invalid refresh credential")
	}
	return record, hash, nil
}

func (m *Manager) RevokeFamily(ctx context.Context, familyID string) error {
	return m.store.RevokeFamily(ctx, familyID, m.clock.Now())
}

func (m *Manager) ListDevices(ctx context.Context, ownerID string) ([]Device, error) {
	if ownerID == "" {
		return nil, errors.New("owner is required")
	}
	return m.store.ListDevices(ctx, ownerID)
}

func (m *Manager) RevokeDevice(ctx context.Context, ownerID, deviceID string) error {
	if ownerID == "" || deviceID == "" {
		return errors.New("owner and device are required")
	}
	return m.store.RevokeDevice(ctx, ownerID, deviceID, m.clock.Now())
}

func (m *Manager) issue(ctx context.Context, ownerID, deviceID, familyID string, rotate bool, previousID string, previousHash [32]byte) (Pair, error) {
	now := m.clock.Now()
	accessToken, accessRecord, err := m.makeRecord(ownerID, deviceID, familyID, Access, now, now.Add(m.accessTTL))
	if err != nil {
		return Pair{}, err
	}
	refreshToken, refreshRecord, err := m.makeRecord(ownerID, deviceID, familyID, Refresh, now, now.Add(m.refreshTTL))
	if err != nil {
		return Pair{}, err
	}
	if rotate {
		err = m.store.Rotate(ctx, previousID, previousHash, now, accessRecord, refreshRecord)
	} else {
		err = m.store.CreatePair(ctx, accessRecord, refreshRecord)
	}
	if err != nil {
		return Pair{}, err
	}
	return Pair{AccessToken: accessToken, AccessExpiresAt: accessRecord.ExpiresAt, RefreshToken: refreshToken, RefreshExpiresAt: refreshRecord.ExpiresAt, DeviceID: deviceID}, nil
}

func (m *Manager) makeRecord(ownerID, deviceID, familyID string, kind Kind, createdAt, expiresAt time.Time) (string, Record, error) {
	id, err := randomPart(m.random, 16)
	if err != nil {
		return "", Record{}, err
	}
	secret, err := randomPart(m.random, 32)
	if err != nil {
		return "", Record{}, err
	}
	token := "cm_" + string(kind) + "_" + id + "." + secret
	return token, Record{ID: id, FamilyID: familyID, OwnerID: ownerID, DeviceID: deviceID, Kind: kind, Hash: m.hash(kind, id, secret), CreatedAt: createdAt, ExpiresAt: expiresAt}, nil
}

func (m *Manager) hash(kind Kind, id, secret string) [32]byte {
	h := hmac.New(sha256.New, m.pepper)
	h.Write([]byte("codex-mobile:session:v1:"))
	h.Write([]byte(kind))
	h.Write([]byte{0})
	h.Write([]byte(id))
	h.Write([]byte{0})
	h.Write([]byte(secret))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func parseToken(token string, expected Kind) (string, string, error) {
	prefix := "cm_" + string(expected) + "_"
	if !strings.HasPrefix(token, prefix) || len(token) > 256 {
		return "", "", errors.New("malformed credential")
	}
	parts := strings.Split(strings.TrimPrefix(token, prefix), ".")
	if len(parts) != 2 || len(parts[0]) < 16 || len(parts[1]) < 32 {
		return "", "", errors.New("malformed credential")
	}
	if _, err := base64.RawURLEncoding.DecodeString(parts[0]); err != nil {
		return "", "", errors.New("malformed credential")
	}
	if _, err := base64.RawURLEncoding.DecodeString(parts[1]); err != nil {
		return "", "", errors.New("malformed credential")
	}
	return parts[0], parts[1], nil
}

func randomPart(random io.Reader, bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := io.ReadFull(random, b); err != nil {
		return "", fmt.Errorf("random credential: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

type MemoryStore struct {
	mu      sync.Mutex
	records map[string]Record
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{records: make(map[string]Record)} }

func (s *MemoryStore) CreatePair(_ context.Context, access, refresh Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.records[access.ID]; exists {
		return errors.New("credential ID collision")
	}
	if _, exists := s.records[refresh.ID]; exists {
		return errors.New("credential ID collision")
	}
	s.records[access.ID] = access
	s.records[refresh.ID] = refresh
	return nil
}

func (s *MemoryStore) Get(_ context.Context, id string) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[id]
	if !ok {
		return Record{}, errors.New("credential not found")
	}
	return record, nil
}

func (s *MemoryStore) ValidatePrincipal(_ context.Context, principal Principal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	found := false
	for _, record := range s.records {
		if record.FamilyID != principal.FamilyID {
			continue
		}
		found = true
		if record.OwnerID != principal.OwnerID || record.DeviceID != principal.DeviceID || record.RevokedAt != nil {
			return errors.New("invalid session principal")
		}
	}
	if !found {
		return errors.New("invalid session principal")
	}
	return nil
}

func (s *MemoryStore) Rotate(_ context.Context, previousID string, previousHash [32]byte, now time.Time, access, refresh Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, ok := s.records[previousID]
	if !ok || previous.Kind != Refresh || previous.RevokedAt != nil || subtle.ConstantTimeCompare(previous.Hash[:], previousHash[:]) != 1 {
		return errors.New("invalid refresh credential")
	}
	if previous.UsedAt != nil {
		s.revokeFamilyLocked(previous.FamilyID, now)
		return ErrReplay
	}
	previous.UsedAt = &now
	s.records[previousID] = previous
	s.records[access.ID] = access
	s.records[refresh.ID] = refresh
	return nil
}

func (s *MemoryStore) RevokeFamily(_ context.Context, familyID string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revokeFamilyLocked(familyID, now)
	return nil
}

func (s *MemoryStore) ListDevices(context.Context, string) ([]Device, error) { return []Device{}, nil }

func (s *MemoryStore) RevokeDevice(_ context.Context, _ string, deviceID string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, record := range s.records {
		if record.DeviceID == deviceID && record.RevokedAt == nil {
			record.RevokedAt = &now
			s.records[id] = record
		}
	}
	return nil
}

func (s *MemoryStore) revokeFamilyLocked(familyID string, now time.Time) {
	for id, record := range s.records {
		if record.FamilyID == familyID && record.RevokedAt == nil {
			record.RevokedAt = &now
			s.records[id] = record
		}
	}
}
