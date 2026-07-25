package passkeys

import (
	"context"
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
	"unicode"
	"unicode/utf8"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type ceremonyKind string

const (
	ceremonyBootstrap  ceremonyKind = "bootstrap_registration"
	ceremonyAdditional ceremonyKind = "authenticated_registration"
	ceremonyLogin      ceremonyKind = "login"
	maximumCeremonies               = 4096
	ceremonyTTL                     = 5 * time.Minute
)

type ceremony struct {
	ID             string
	Kind           ceremonyKind
	Owner          Owner
	DeviceID       string
	Device         DeviceBinding
	DeviceHash     [32]byte
	BootstrapToken string
	RecoveryOwner  string
	KnownDevice    bool
	Session        webauthn.SessionData
	ExpiresAt      time.Time
}

type Service struct {
	rpid       string
	web        *webauthn.WebAuthn
	store      Store
	bootstrap  *BootstrapManager
	random     io.Reader
	now        func() time.Time
	knownMu    sync.Mutex
	knownReady bool
	knownRetry time.Time
	knownErr   error
	known      map[[32]byte]struct{}
	mu         sync.Mutex
	ceremonies map[string]ceremony
	admission  loginAdmissionState
}

type RegistrationStart struct {
	CeremonyID string                       `json:"ceremony_id"`
	Options    *protocol.CredentialCreation `json:"options"`
}

type LoginStart struct {
	CeremonyID string                        `json:"ceremony_id"`
	Options    *protocol.CredentialAssertion `json:"options"`
}

type LoginResult struct {
	OwnerID  string
	DeviceID string
}

// DeviceBinding identifies one app installation without exposing the server's
// device ID. InstanceID is a canonical base64url encoding of 256 random bits
// stored in this-device-only Keychain storage by the native client.
type DeviceBinding struct {
	InstanceID string
	Name       string
}

func NewService(rpid, displayName string, origins []string, store Store, bootstrap *BootstrapManager) (*Service, error) {
	if store == nil || bootstrap == nil {
		return nil, errors.New("passkey store and bootstrap manager are required")
	}
	web, err := webauthn.New(&webauthn.Config{
		RPID:                  rpid,
		RPDisplayName:         displayName,
		RPOrigins:             append([]string(nil), origins...),
		RPAllowCrossOrigin:    false,
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		},
	})
	if err != nil {
		return nil, err
	}
	return &Service{
		rpid: rpid, web: web, store: store, bootstrap: bootstrap,
		random: rand.Reader, now: func() time.Time { return time.Now().UTC() },
		known: make(map[[32]byte]struct{}), ceremonies: make(map[string]ceremony),
		admission: newLoginAdmissionState(),
	}, nil
}

func (s *Service) BeginBootstrapRegistration(ctx context.Context, token string, device DeviceBinding) (RegistrationStart, error) {
	if err := s.bootstrap.ValidateContext(ctx, token); err != nil {
		return RegistrationStart{}, err
	}
	recoveryOwnerID, err := s.bootstrap.recoveryOwnerContext(ctx, token)
	if err != nil {
		return RegistrationStart{}, err
	}
	hasOwner, err := s.store.HasOwner(ctx)
	if err != nil {
		return RegistrationStart{}, err
	}
	if hasOwner && recoveryOwnerID == "" {
		if err := s.bootstrap.DisableContext(ctx); err != nil {
			return RegistrationStart{}, err
		}
		return RegistrationStart{}, errors.New("bootstrap is disabled after owner enrollment")
	}
	if !hasOwner && recoveryOwnerID != "" {
		return RegistrationStart{}, ErrInvalidBootstrap
	}
	deviceHash, err := validateDeviceBinding(device)
	if err != nil {
		return RegistrationStart{}, err
	}
	var owner Owner
	if recoveryOwnerID != "" {
		owner, err = s.store.OwnerForRecovery(ctx, s.rpid, recoveryOwnerID)
		if err != nil {
			return RegistrationStart{}, errors.New("passkey recovery is not available")
		}
	}
	deviceID, err := randomID(s.random, 16)
	if err != nil {
		return RegistrationStart{}, err
	}
	if recoveryOwnerID == "" {
		ownerID, err := randomID(s.random, 16)
		if err != nil {
			return RegistrationStart{}, err
		}
		handle := make([]byte, 64)
		if _, err := io.ReadFull(s.random, handle); err != nil {
			return RegistrationStart{}, err
		}
		owner = Owner{ID: ownerID, Handle: handle, Name: "owner", DisplayName: "Codex Mobile Owner"}
	}
	options, session, err := s.web.BeginRegistration(
		owner,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		}),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
	)
	if err != nil {
		return RegistrationStart{}, err
	}
	id, err := randomID(s.random, 16)
	if err != nil {
		return RegistrationStart{}, err
	}
	if err := s.saveCeremony(ceremony{ID: id, Kind: ceremonyBootstrap, Owner: owner, DeviceID: deviceID, Device: device, DeviceHash: deviceHash, BootstrapToken: token, RecoveryOwner: recoveryOwnerID, Session: *session}); err != nil {
		return RegistrationStart{}, err
	}
	return RegistrationStart{CeremonyID: id, Options: options}, nil
}

func (s *Service) FinishBootstrapRegistration(ctx context.Context, ceremonyID, token string, device DeviceBinding, response []byte) (LoginResult, error) {
	ceremony, err := s.consume(ceremonyID, ceremonyBootstrap)
	if err != nil {
		return LoginResult{}, err
	}
	if token == "" {
		token = ceremony.BootstrapToken
	}
	if err := verifyDeviceBinding(ceremony, device); err != nil {
		return LoginResult{}, err
	}
	if err := s.bootstrap.ValidateContext(ctx, token); err != nil {
		return LoginResult{}, err
	}
	recoveryOwnerID, err := s.bootstrap.recoveryOwnerContext(ctx, token)
	if err != nil || recoveryOwnerID != ceremony.RecoveryOwner {
		return LoginResult{}, ErrInvalidBootstrap
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return LoginResult{}, fmt.Errorf("parse passkey registration: %w", err)
	}
	credential, err := s.web.CreateCredential(ceremony.Owner, ceremony.Session, parsed)
	if err != nil {
		return LoginResult{}, fmt.Errorf("verify passkey registration: %w", err)
	}
	record := CredentialRecord{
		RPID: s.rpid, OwnerID: ceremony.Owner.ID, DeviceID: ceremony.DeviceID,
		DeviceName: ceremony.Device.Name, DeviceInstanceHash: ceremony.DeviceHash,
		Credential: *credential, CreatedAt: s.now(),
	}
	if ceremony.RecoveryOwner != "" {
		if err := s.store.CreateCredentialForRecoveredOwner(ctx, ceremony.Owner, record, RecoveryProof{
			TokenHash: s.bootstrap.tokenHash(token), At: s.now(),
		}); err != nil {
			return LoginResult{}, err
		}
	} else {
		if err := s.store.CreateOwnerWithCredential(ctx, ceremony.Owner, record); err != nil {
			return LoginResult{}, err
		}
	}
	if ceremony.RecoveryOwner == "" {
		if err := s.bootstrap.ConsumeContext(ctx, token); err != nil {
			// Credential creation is authoritative. Best-effort disable prevents an
			// already successful first-owner enrollment from appearing
			// to fail solely because the final token marker could not be updated.
			_ = s.bootstrap.DisableContext(ctx)
		}
	}
	s.rememberKnownDevice(ceremony.DeviceHash)
	return LoginResult{OwnerID: ceremony.Owner.ID, DeviceID: ceremony.DeviceID}, nil
}

func (s *Service) BeginLogin(ctx context.Context, device DeviceBinding) (LoginStart, error) {
	deviceHash, err := validateDeviceBinding(device)
	if err != nil {
		return LoginStart{}, err
	}
	known, err := s.knownDevice(ctx, deviceHash)
	if err != nil {
		return LoginStart{}, err
	}
	reservation, err := s.reserveLogin(deviceHash, known)
	if err != nil {
		return LoginStart{}, err
	}
	committed := false
	defer func() {
		if !committed {
			s.cancelLogin(reservation)
		}
	}()
	options, session, err := s.web.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return LoginStart{}, err
	}
	id, err := randomID(s.random, 16)
	if err != nil {
		return LoginStart{}, err
	}
	if err := s.commitLogin(reservation, ceremony{ID: id, Kind: ceremonyLogin, Device: device, DeviceHash: deviceHash, KnownDevice: known, Session: *session}); err != nil {
		return LoginStart{}, err
	}
	committed = true
	return LoginStart{CeremonyID: id, Options: options}, nil
}

func (s *Service) BeginAdditionalRegistration(ctx context.Context, ownerID, deviceID string, device DeviceBinding) (RegistrationStart, error) {
	if ownerID == "" || deviceID == "" {
		return RegistrationStart{}, fmt.Errorf("authenticated passkey principal: %w", core.ErrInvalid)
	}
	deviceHash, err := validateDeviceBinding(device)
	if err != nil {
		return RegistrationStart{}, err
	}
	owner, err := s.store.OwnerForAdditionalCredential(ctx, s.rpid, ownerID, deviceID, deviceHash)
	if err != nil {
		return RegistrationStart{}, fmt.Errorf("authenticated passkey registration: %w", err)
	}
	options, session, err := s.web.BeginRegistration(
		owner,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		}),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
		webauthn.WithExclusions(webauthn.Credentials(owner.WebAuthnCredentials()).CredentialDescriptors()),
	)
	if err != nil {
		return RegistrationStart{}, err
	}
	id, err := randomID(s.random, 16)
	if err != nil {
		return RegistrationStart{}, err
	}
	if err := s.saveCeremony(ceremony{
		ID: id, Kind: ceremonyAdditional, Owner: owner, DeviceID: deviceID,
		Device: device, DeviceHash: deviceHash, Session: *session,
	}); err != nil {
		return RegistrationStart{}, err
	}
	return RegistrationStart{CeremonyID: id, Options: options}, nil
}

func (s *Service) FinishAdditionalRegistration(
	ctx context.Context,
	ceremonyID, ownerID, deviceID string,
	device DeviceBinding,
	response []byte,
) (CredentialMetadata, error) {
	ceremony, err := s.consume(ceremonyID, ceremonyAdditional)
	if err != nil {
		return CredentialMetadata{}, err
	}
	if ceremony.Owner.ID != ownerID || ceremony.DeviceID != deviceID {
		return CredentialMetadata{}, fmt.Errorf("passkey ceremony principal changed: %w", core.ErrForbidden)
	}
	if err := verifyDeviceBinding(ceremony, device); err != nil {
		return CredentialMetadata{}, fmt.Errorf("authenticated passkey device: %w", core.ErrForbidden)
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return CredentialMetadata{}, fmt.Errorf("authenticated passkey response: %w", core.ErrInvalid)
	}
	credential, err := s.web.CreateCredential(ceremony.Owner, ceremony.Session, parsed)
	if err != nil {
		return CredentialMetadata{}, fmt.Errorf("authenticated passkey verification: %w", core.ErrInvalid)
	}
	now := s.now()
	record := CredentialRecord{
		RPID: s.rpid, OwnerID: ownerID, DeviceID: deviceID, DeviceName: ceremony.Device.Name,
		DeviceInstanceHash: ceremony.DeviceHash, Credential: *credential, CreatedAt: now,
	}
	if err := s.store.CreateAdditionalCredential(ctx, ceremony.Owner, record); err != nil {
		return CredentialMetadata{}, err
	}
	return CredentialMetadata{
		CredentialID: append([]byte(nil), credential.ID...), DeviceID: deviceID,
		DeviceName: ceremony.Device.Name, CreatedAt: now,
	}, nil
}

func (s *Service) ListCredentials(ctx context.Context, ownerID string) ([]CredentialMetadata, error) {
	if ownerID == "" {
		return nil, fmt.Errorf("passkey owner: %w", core.ErrInvalid)
	}
	return s.store.ListCredentialMetadata(ctx, s.rpid, ownerID)
}

func (s *Service) RevokeCredential(ctx context.Context, ownerID, credentialID string) error {
	if ownerID == "" {
		return fmt.Errorf("passkey owner: %w", core.ErrInvalid)
	}
	raw, err := base64.RawURLEncoding.DecodeString(credentialID)
	if err != nil || len(raw) < 1 || len(raw) > 1024 || base64.RawURLEncoding.EncodeToString(raw) != credentialID {
		return fmt.Errorf("passkey credential identity: %w", core.ErrInvalid)
	}
	return s.store.RevokeCredential(ctx, s.rpid, ownerID, raw)
}

func (s *Service) FinishLogin(ctx context.Context, ceremonyID string, device DeviceBinding, response []byte) (LoginResult, error) {
	ceremony, err := s.consume(ceremonyID, ceremonyLogin)
	if err != nil {
		return LoginResult{}, err
	}
	if err := verifyDeviceBinding(ceremony, device); err != nil {
		return LoginResult{}, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return LoginResult{}, fmt.Errorf("parse passkey assertion: %w", err)
	}
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		owner, err := s.store.OwnerByHandle(ctx, s.rpid, userHandle)
		if err != nil {
			return nil, errors.New("unknown credential")
		}
		return owner, nil
	}
	user, credential, err := s.web.ValidatePasskeyLogin(handler, ceremony.Session, parsed)
	if err != nil {
		return LoginResult{}, fmt.Errorf("verify passkey assertion: %w", err)
	}
	owner, ok := user.(Owner)
	if !ok {
		return LoginResult{}, errors.New("passkey owner type mismatch")
	}
	record, err := s.store.CredentialRecord(ctx, s.rpid, credential.ID)
	if err != nil || record.OwnerID != owner.ID {
		return LoginResult{}, errors.New("credential ownership mismatch")
	}
	now := s.now()
	record.LastUsedAt = &now
	record.Credential = *credential
	if err := s.store.SaveCredential(ctx, record); err != nil {
		return LoginResult{}, err
	}
	deviceID, err := randomID(s.random, 16)
	if err != nil {
		return LoginResult{}, err
	}
	resolved, err := s.store.ResolveDevice(ctx, Device{
		ID: deviceID, OwnerID: owner.ID, Name: ceremony.Device.Name, Platform: "ios",
		InstanceHash: ceremony.DeviceHash, CreatedAt: now, LastSeenAt: now,
	})
	if err != nil {
		return LoginResult{}, err
	}
	s.rememberKnownDevice(ceremony.DeviceHash)
	return LoginResult{OwnerID: owner.ID, DeviceID: resolved.ID}, nil
}

func validateDeviceBinding(device DeviceBinding) ([32]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(device.InstanceID)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != device.InstanceID {
		return [32]byte{}, errors.New("device instance identity must be canonical 256-bit base64url")
	}
	if device.Name == "" || device.Name != strings.TrimSpace(device.Name) || len(device.Name) > 120 ||
		!utf8.ValidString(device.Name) {
		return [32]byte{}, errors.New("device name is required and must be bounded")
	}
	for _, character := range device.Name {
		if unicode.IsControl(character) {
			return [32]byte{}, errors.New("device name contains control characters")
		}
	}
	return sha256.Sum256(decoded), nil
}

func verifyDeviceBinding(ceremony ceremony, device DeviceBinding) error {
	hash, err := validateDeviceBinding(device)
	if err != nil || subtle.ConstantTimeCompare(hash[:], ceremony.DeviceHash[:]) != 1 || device.Name != ceremony.Device.Name {
		return errors.New("device identity does not match passkey ceremony")
	}
	return nil
}

func (s *Service) consume(id string, kind ceremonyKind) (ceremony, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupCeremoniesLocked(s.now())
	c, ok := s.ceremonies[id]
	if !ok || c.Kind != kind {
		return ceremony{}, fmt.Errorf("invalid, expired, or already used passkey ceremony: %w", core.ErrInvalid)
	}
	s.removeCeremonyLocked(id, c)
	return c, nil
}

func (s *Service) saveCeremony(value ceremony) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.cleanupCeremoniesLocked(now)
	if value.Kind == ceremonyLogin {
		return errors.New("login ceremonies require admission")
	}
	if len(s.ceremonies)+s.admission.pendingSlots >= maximumCeremonies {
		return fmt.Errorf("passkey ceremony capacity: %w", core.ErrCapacity)
	}
	if _, exists := s.ceremonies[value.ID]; exists {
		return fmt.Errorf("passkey ceremony identity: %w", core.ErrConflict)
	}
	value.ExpiresAt = now.Add(ceremonyTTL)
	s.ceremonies[value.ID] = value
	return nil
}

func randomID(random io.Reader, size int) (string, error) {
	b := make([]byte, size)
	if _, err := io.ReadFull(random, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
