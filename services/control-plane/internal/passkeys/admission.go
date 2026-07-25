package passkeys

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
)

const (
	// Anonymous authentication can never consume the entire ceremony store.
	// Bootstrap and authenticated registration retain this many slots even
	// during sustained hostile login traffic.
	privilegedCeremonyReserve     = 256
	maximumLoginCeremonies        = maximumCeremonies - privilegedCeremonyReserve
	maximumUnknownLoginCeremonies = 512
	maximumKnownDeviceInstances   = 4096
	maximumAdmissionDevices       = maximumKnownDeviceInstances + maximumUnknownLoginCeremonies
	knownDeviceLoadRetry          = time.Second

	deviceLoginBurst          = 4
	deviceLoginRefillInterval = 15 * time.Second
	unknownLoginBurst         = 32
	unknownLoginRefill        = time.Second
	knownLoginBurst           = 32
	knownLoginRefill          = 250 * time.Millisecond
)

var errLoginAdmissionUnavailable = fmt.Errorf("passkey login admission: %w", core.ErrCapacity)

type tokenBucket struct {
	tokens       int
	lastRefilled time.Time
}

func newTokenBucket(tokens int) tokenBucket {
	return tokenBucket{tokens: tokens}
}

func (b *tokenBucket) refill(now time.Time, capacity int, interval time.Duration) {
	if b.lastRefilled.IsZero() {
		b.tokens = capacity
		b.lastRefilled = now
		return
	}
	if now.Before(b.lastRefilled) {
		// A wall-clock correction must not mint additional admission credit.
		b.lastRefilled = now
		return
	}
	if b.tokens >= capacity {
		b.tokens = capacity
		b.lastRefilled = now
		return
	}
	refills := int(now.Sub(b.lastRefilled) / interval)
	if refills < 1 {
		return
	}
	b.tokens = min(capacity, b.tokens+refills)
	b.lastRefilled = b.lastRefilled.Add(time.Duration(refills) * interval)
	if b.tokens == capacity {
		// Discard surplus elapsed time; token buckets do not accumulate more
		// than their documented retry burst.
		b.lastRefilled = now
	}
}

type deviceLoginAdmission struct {
	rate     tokenBucket
	inFlight bool
}

type loginAdmissionState struct {
	byDevice map[[32]byte]*deviceLoginAdmission
	byActive map[[32]byte]string

	unknownRate tokenBucket
	knownRate   tokenBucket

	active         int
	unknownActive  int
	pendingSlots   int
	pendingUnknown int
}

func newLoginAdmissionState() loginAdmissionState {
	return loginAdmissionState{
		byDevice:    make(map[[32]byte]*deviceLoginAdmission),
		byActive:    make(map[[32]byte]string),
		unknownRate: newTokenBucket(unknownLoginBurst),
		knownRate:   newTokenBucket(knownLoginBurst),
	}
}

type loginReservation struct {
	deviceHash [32]byte
	known      bool
	reserved   bool
}

func (s *Service) knownDevice(ctx context.Context, deviceHash [32]byte) (bool, error) {
	s.knownMu.Lock()
	defer s.knownMu.Unlock()
	if !s.knownReady {
		now := s.now()
		if s.knownErr != nil && now.Before(s.knownRetry) {
			return false, s.knownErr
		}
		values, err := s.store.KnownDeviceInstanceHashes(ctx, maximumKnownDeviceInstances)
		if err != nil {
			s.knownErr = err
			s.knownRetry = now.Add(knownDeviceLoadRetry)
			return false, err
		}
		for _, value := range values {
			s.known[value] = struct{}{}
		}
		s.knownReady = true
		s.knownErr = nil
		s.knownRetry = time.Time{}
	}
	_, known := s.known[deviceHash]
	return known, nil
}

func (s *Service) rememberKnownDevice(deviceHash [32]byte) {
	s.knownMu.Lock()
	defer s.knownMu.Unlock()
	if !s.knownReady {
		// A later bounded store load includes the just-committed device.
		return
	}
	if _, exists := s.known[deviceHash]; exists || len(s.known) < maximumKnownDeviceInstances {
		s.known[deviceHash] = struct{}{}
	}
}

func (s *Service) reserveLogin(deviceHash [32]byte, known bool) (loginReservation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.cleanupCeremoniesLocked(now)
	s.cleanupAdmissionsLocked(now)

	state, exists := s.admission.byDevice[deviceHash]
	if !exists {
		if len(s.admission.byDevice) >= maximumAdmissionDevices {
			return loginReservation{}, errLoginAdmissionUnavailable
		}
		state = &deviceLoginAdmission{rate: newTokenBucket(deviceLoginBurst)}
	}
	state.rate.refill(now, deviceLoginBurst, deviceLoginRefillInterval)
	if state.inFlight || state.rate.tokens < 1 {
		return loginReservation{}, errLoginAdmissionUnavailable
	}

	global := &s.admission.unknownRate
	burst, refill := unknownLoginBurst, unknownLoginRefill
	if known {
		global = &s.admission.knownRate
		burst, refill = knownLoginBurst, knownLoginRefill
	}
	global.refill(now, burst, refill)
	if global.tokens < 1 {
		return loginReservation{}, errLoginAdmissionUnavailable
	}

	_, replacing := s.admission.byActive[deviceHash]
	if !replacing {
		if len(s.ceremonies)+s.admission.pendingSlots >= maximumCeremonies ||
			s.admission.active+s.admission.pendingSlots >= maximumLoginCeremonies ||
			(!known && s.admission.unknownActive+s.admission.pendingUnknown >= maximumUnknownLoginCeremonies) {
			return loginReservation{}, errLoginAdmissionUnavailable
		}
	}

	state.rate.tokens--
	state.inFlight = true
	global.tokens--
	s.admission.byDevice[deviceHash] = state
	reservation := loginReservation{deviceHash: deviceHash, known: known, reserved: !replacing}
	if reservation.reserved {
		s.admission.pendingSlots++
		if !known {
			s.admission.pendingUnknown++
		}
	}
	return reservation, nil
}

func (s *Service) cancelLogin(reservation loginReservation) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.admission.byDevice[reservation.deviceHash]
	if state != nil {
		state.inFlight = false
	}
	if reservation.reserved {
		s.releasePendingLocked(reservation.known)
	}
}

func (s *Service) commitLogin(reservation loginReservation, value ceremony) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.cleanupCeremoniesLocked(now)
	state := s.admission.byDevice[reservation.deviceHash]
	if state == nil || !state.inFlight || value.Kind != ceremonyLogin || value.DeviceHash != reservation.deviceHash || value.KnownDevice != reservation.known {
		return errors.New("invalid passkey login reservation")
	}
	if _, exists := s.ceremonies[value.ID]; exists {
		return fmt.Errorf("passkey ceremony identity: %w", core.ErrConflict)
	}

	replaced := false
	if existingID, exists := s.admission.byActive[reservation.deviceHash]; exists {
		if existing, ok := s.ceremonies[existingID]; ok {
			s.removeCeremonyLocked(existingID, existing)
			replaced = true
		}
	}
	if reservation.reserved {
		s.releasePendingLocked(reservation.known)
	} else if !replaced && (len(s.ceremonies)+s.admission.pendingSlots >= maximumCeremonies ||
		s.admission.active+s.admission.pendingSlots >= maximumLoginCeremonies ||
		(!reservation.known && s.admission.unknownActive+s.admission.pendingUnknown >= maximumUnknownLoginCeremonies)) {
		// The replaced ceremony may have expired while WebAuthn options were
		// generated. Re-check before converting that replacement into a new slot.
		return errLoginAdmissionUnavailable
	}

	value.ExpiresAt = now.Add(ceremonyTTL)
	s.ceremonies[value.ID] = value
	s.admission.byActive[value.DeviceHash] = value.ID
	s.admission.active++
	if !value.KnownDevice {
		s.admission.unknownActive++
	}
	state.inFlight = false
	return nil
}

func (s *Service) cleanupCeremoniesLocked(now time.Time) {
	for id, value := range s.ceremonies {
		if !now.Before(value.ExpiresAt) {
			s.removeCeremonyLocked(id, value)
		}
	}
}

func (s *Service) removeCeremonyLocked(id string, value ceremony) {
	delete(s.ceremonies, id)
	if value.Kind != ceremonyLogin {
		return
	}
	activeID, exists := s.admission.byActive[value.DeviceHash]
	if !exists || activeID != id {
		return
	}
	delete(s.admission.byActive, value.DeviceHash)
	if s.admission.active > 0 {
		s.admission.active--
	}
	if !value.KnownDevice && s.admission.unknownActive > 0 {
		s.admission.unknownActive--
	}
}

func (s *Service) releasePendingLocked(known bool) {
	if s.admission.pendingSlots > 0 {
		s.admission.pendingSlots--
	}
	if !known && s.admission.pendingUnknown > 0 {
		s.admission.pendingUnknown--
	}
}

func (s *Service) cleanupAdmissionsLocked(now time.Time) {
	for deviceHash, state := range s.admission.byDevice {
		state.rate.refill(now, deviceLoginBurst, deviceLoginRefillInterval)
		_, active := s.admission.byActive[deviceHash]
		if !state.inFlight && !active && state.rate.tokens == deviceLoginBurst {
			delete(s.admission.byDevice, deviceHash)
		}
	}
}
