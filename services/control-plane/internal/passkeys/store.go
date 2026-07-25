package passkeys

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/go-webauthn/webauthn/webauthn"
)

type Owner struct {
	ID          string
	Handle      []byte
	Name        string
	DisplayName string
	Credentials []webauthn.Credential
}

func (u Owner) WebAuthnID() []byte          { return append([]byte(nil), u.Handle...) }
func (u Owner) WebAuthnName() string        { return u.Name }
func (u Owner) WebAuthnDisplayName() string { return u.DisplayName }
func (u Owner) WebAuthnCredentials() []webauthn.Credential {
	return append([]webauthn.Credential(nil), u.Credentials...)
}

type CredentialRecord struct {
	RPID               string
	OwnerID            string
	DeviceID           string
	DeviceName         string
	DeviceInstanceHash [32]byte
	Credential         webauthn.Credential
	CreatedAt          time.Time
	LastUsedAt         *time.Time
}

type Device struct {
	ID           string
	OwnerID      string
	Name         string
	Platform     string
	InstanceHash [32]byte
	CreatedAt    time.Time
	LastSeenAt   time.Time
}

// RecoveryProof carries only the keyed bootstrap hash. Production stores must
// validate and consume it in the same transaction that creates the recovered
// credential, preventing expiry/replacement races between WebAuthn validation
// and persistence.
type RecoveryProof struct {
	TokenHash [32]byte
	At        time.Time
}

type CredentialMetadata struct {
	CredentialID []byte
	DeviceID     string
	DeviceName   string
	CreatedAt    time.Time
	LastUsedAt   *time.Time
}

type Store interface {
	HasOwner(context.Context) (bool, error)
	// KnownDeviceInstanceHashes returns a bounded set of historical instance
	// hashes, including revoked devices: revocation ends sessions but a valid
	// passkey may reauthenticate that same private app installation.
	KnownDeviceInstanceHashes(context.Context, int) ([][32]byte, error)
	CreateOwnerWithCredential(context.Context, Owner, CredentialRecord) error
	OwnerForRecovery(context.Context, string, string) (Owner, error)
	CreateCredentialForRecoveredOwner(context.Context, Owner, CredentialRecord, RecoveryProof) error
	OwnerForAdditionalCredential(context.Context, string, string, string, [32]byte) (Owner, error)
	CreateAdditionalCredential(context.Context, Owner, CredentialRecord) error
	ListCredentialMetadata(context.Context, string, string) ([]CredentialMetadata, error)
	RevokeCredential(context.Context, string, string, []byte) error
	OwnerByHandle(context.Context, string, []byte) (Owner, error)
	OwnerByID(context.Context, string, string) (Owner, error)
	SaveCredential(context.Context, CredentialRecord) error
	CredentialRecord(context.Context, string, []byte) (CredentialRecord, error)
	ResolveDevice(context.Context, Device) (Device, error)
}

type MemoryStore struct {
	mu          sync.Mutex
	owners      map[string]Owner
	handleIndex map[string]string
	credentials map[string]CredentialRecord
	devices     map[string]Device
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		owners: make(map[string]Owner), handleIndex: make(map[string]string),
		credentials: make(map[string]CredentialRecord), devices: make(map[string]Device),
	}
}

func (s *MemoryStore) HasOwner(context.Context) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.owners) > 0, nil
}

func (s *MemoryStore) KnownDeviceInstanceHashes(_ context.Context, limit int) ([][32]byte, error) {
	if limit < 1 {
		return nil, fmt.Errorf("known device instance limit: %w", core.ErrInvalid)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	values := make([][32]byte, 0, min(limit, len(s.devices)))
	seen := make(map[[32]byte]struct{}, len(s.devices))
	for _, device := range s.devices {
		if _, exists := seen[device.InstanceHash]; exists {
			continue
		}
		seen[device.InstanceHash] = struct{}{}
		values = append(values, device.InstanceHash)
		if len(values) == limit {
			break
		}
	}
	return values, nil
}

func (s *MemoryStore) CreateOwnerWithCredential(_ context.Context, owner Owner, record CredentialRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.owners) > 0 || owner.ID == "" || len(owner.Handle) != 64 || record.OwnerID != owner.ID || len(record.Credential.ID) < 1 || len(record.Credential.ID) > 1024 {
		return errors.New("owner or credential conflict")
	}
	owner.Credentials = []webauthn.Credential{record.Credential}
	s.owners[owner.ID] = owner
	s.handleIndex[index(record.RPID, owner.Handle)] = owner.ID
	s.credentials[index(record.RPID, record.Credential.ID)] = record
	s.devices[record.DeviceID] = Device{
		ID: record.DeviceID, OwnerID: owner.ID, Name: record.DeviceName, Platform: "ios",
		InstanceHash: record.DeviceInstanceHash, CreatedAt: record.CreatedAt, LastSeenAt: record.CreatedAt,
	}
	return nil
}

func (s *MemoryStore) OwnerForRecovery(_ context.Context, rpid, ownerID string) (Owner, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	owner, ok := s.owners[ownerID]
	if !ok || owner.ID == "" || len(owner.Handle) != 64 {
		return Owner{}, errors.New("recovery owner not found")
	}
	for _, record := range s.credentials {
		if record.OwnerID == ownerID && record.RPID == rpid {
			return Owner{}, errors.New("owner still has a passkey")
		}
	}
	owner.Credentials = nil
	return owner, nil
}

func (s *MemoryStore) CreateCredentialForRecoveredOwner(_ context.Context, owner Owner, record CredentialRecord, proof RecoveryProof) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.owners[owner.ID]
	if !ok || len(stored.Handle) != 64 || record.OwnerID != owner.ID || len(record.Credential.ID) < 1 || len(record.Credential.ID) > 1024 || proof.TokenHash == ([32]byte{}) || proof.At.IsZero() {
		return errors.New("recovery owner or credential conflict")
	}
	for _, existing := range s.credentials {
		if existing.OwnerID == owner.ID && existing.RPID == record.RPID {
			return errors.New("owner already has a passkey")
		}
	}
	stored.Credentials = []webauthn.Credential{record.Credential}
	s.owners[owner.ID] = stored
	s.handleIndex[index(record.RPID, stored.Handle)] = owner.ID
	s.credentials[index(record.RPID, record.Credential.ID)] = record
	s.devices[record.DeviceID] = Device{
		ID: record.DeviceID, OwnerID: owner.ID, Name: record.DeviceName, Platform: "ios",
		InstanceHash: record.DeviceInstanceHash, CreatedAt: record.CreatedAt, LastSeenAt: record.CreatedAt,
	}
	return nil
}

func (s *MemoryStore) OwnerForAdditionalCredential(_ context.Context, rpid, ownerID, deviceID string, instanceHash [32]byte) (Owner, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	owner, ok := s.owners[ownerID]
	device, deviceOK := s.devices[deviceID]
	if !ok || !deviceOK || device.OwnerID != ownerID || !bytes.Equal(device.InstanceHash[:], instanceHash[:]) {
		return Owner{}, core.ErrNotFound
	}
	owner = s.ownerLocked(ownerID)
	owner.Credentials = nil
	for _, record := range s.credentials {
		if record.OwnerID == ownerID && record.RPID == rpid {
			owner.Credentials = append(owner.Credentials, record.Credential)
		}
	}
	if len(owner.Credentials) == 0 {
		return Owner{}, core.ErrNotFound
	}
	return owner, nil
}

func (s *MemoryStore) CreateAdditionalCredential(_ context.Context, owner Owner, record CredentialRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.owners[owner.ID]
	device, deviceOK := s.devices[record.DeviceID]
	if !ok || !deviceOK || device.OwnerID != owner.ID || record.OwnerID != owner.ID ||
		!bytes.Equal(device.InstanceHash[:], record.DeviceInstanceHash[:]) || len(record.Credential.ID) < 1 || len(record.Credential.ID) > 1024 {
		return core.ErrNotFound
	}
	count := 0
	for _, existing := range s.credentials {
		if existing.OwnerID == owner.ID && existing.RPID == record.RPID {
			count++
		}
	}
	if count < 1 {
		return core.ErrPrecondition
	}
	if count >= 20 {
		return core.ErrCapacity
	}
	key := index(record.RPID, record.Credential.ID)
	if _, exists := s.credentials[key]; exists {
		return core.ErrConflict
	}
	s.credentials[key] = record
	stored.Credentials = append(stored.Credentials, record.Credential)
	s.owners[owner.ID] = stored
	return nil
}

func (s *MemoryStore) ListCredentialMetadata(_ context.Context, rpid, ownerID string) ([]CredentialMetadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.owners[ownerID]; !ok {
		return nil, core.ErrNotFound
	}
	values := make([]CredentialMetadata, 0)
	for _, record := range s.credentials {
		if record.OwnerID != ownerID || record.RPID != rpid {
			continue
		}
		values = append(values, CredentialMetadata{
			CredentialID: append([]byte(nil), record.Credential.ID...), DeviceID: record.DeviceID,
			DeviceName: record.DeviceName, CreatedAt: record.CreatedAt, LastUsedAt: record.LastUsedAt,
		})
	}
	sort.Slice(values, func(left, right int) bool {
		if values[left].CreatedAt.Equal(values[right].CreatedAt) {
			return bytes.Compare(values[left].CredentialID, values[right].CredentialID) < 0
		}
		return values[left].CreatedAt.Before(values[right].CreatedAt)
	})
	return values, nil
}

func (s *MemoryStore) RevokeCredential(_ context.Context, rpid, ownerID string, credentialID []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	owner, ok := s.owners[ownerID]
	if !ok {
		return core.ErrNotFound
	}
	key := index(rpid, credentialID)
	record, exists := s.credentials[key]
	if !exists {
		return nil
	}
	if record.OwnerID != ownerID {
		return core.ErrNotFound
	}
	count := 0
	for _, existing := range s.credentials {
		if existing.OwnerID == ownerID && existing.RPID == rpid {
			count++
		}
	}
	if count <= 1 {
		return core.ErrPrecondition
	}
	delete(s.credentials, key)
	filtered := owner.Credentials[:0]
	for _, credential := range owner.Credentials {
		if !bytes.Equal(credential.ID, credentialID) {
			filtered = append(filtered, credential)
		}
	}
	owner.Credentials = filtered
	s.owners[ownerID] = owner
	return nil
}

func (s *MemoryStore) OwnerByHandle(_ context.Context, rpid string, handle []byte) (Owner, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.handleIndex[index(rpid, handle)]
	if !ok {
		return Owner{}, errors.New("owner not found")
	}
	return s.ownerLocked(id), nil
}

func (s *MemoryStore) OwnerByID(_ context.Context, rpid, id string) (Owner, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	owner, ok := s.owners[id]
	if !ok || s.handleIndex[index(rpid, owner.Handle)] != id {
		return Owner{}, errors.New("owner not found")
	}
	return s.ownerLocked(id), nil
}

func (s *MemoryStore) SaveCredential(_ context.Context, record CredentialRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	owner, ok := s.owners[record.OwnerID]
	if !ok {
		return errors.New("owner not found")
	}
	key := index(record.RPID, record.Credential.ID)
	prior, ok := s.credentials[key]
	if !ok || prior.OwnerID != record.OwnerID {
		return errors.New("credential not found")
	}
	s.credentials[key] = record
	for i := range owner.Credentials {
		if bytes.Equal(owner.Credentials[i].ID, record.Credential.ID) {
			owner.Credentials[i] = record.Credential
		}
	}
	s.owners[owner.ID] = owner
	return nil
}

func (s *MemoryStore) CredentialRecord(_ context.Context, rpid string, credentialID []byte) (CredentialRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.credentials[index(rpid, credentialID)]
	if !ok {
		return CredentialRecord{}, errors.New("credential not found")
	}
	return record, nil
}

func (s *MemoryStore) ResolveDevice(_ context.Context, candidate Device) (Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if candidate.ID == "" || candidate.OwnerID == "" || candidate.Name == "" || candidate.Platform != "ios" ||
		candidate.CreatedAt.IsZero() || candidate.LastSeenAt.IsZero() {
		return Device{}, errors.New("invalid device")
	}
	if _, ok := s.owners[candidate.OwnerID]; !ok {
		return Device{}, errors.New("owner not found")
	}
	for id, existing := range s.devices {
		if existing.OwnerID == candidate.OwnerID && bytes.Equal(existing.InstanceHash[:], candidate.InstanceHash[:]) {
			existing.Name = candidate.Name
			existing.LastSeenAt = candidate.LastSeenAt
			s.devices[id] = existing
			return existing, nil
		}
	}
	s.devices[candidate.ID] = candidate
	return candidate, nil
}

func (s *MemoryStore) ownerLocked(id string) Owner {
	owner := s.owners[id]
	owner.Handle = append([]byte(nil), owner.Handle...)
	owner.Credentials = append([]webauthn.Credential(nil), owner.Credentials...)
	return owner
}

func index(rpid string, raw []byte) string {
	return rpid + ":" + base64.RawURLEncoding.EncodeToString(raw)
}
