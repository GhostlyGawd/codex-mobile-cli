package terminal

import (
	"errors"
	"sync"
	"time"
)

var ErrLeaseHeld = errors.New("terminal input lease held by another device")

type Lease struct {
	DeviceID  string
	ExpiresAt time.Time
}

type LeaseDecision struct {
	Lease     Lease
	Displaced string
}

type LeaseManager struct {
	mu    sync.Mutex
	ttl   time.Duration
	lease Lease
}

func NewLeaseManager(ttl time.Duration) (*LeaseManager, error) {
	if ttl < 5*time.Second || ttl > 5*time.Minute {
		return nil, errors.New("lease TTL must be between 5 seconds and 5 minutes")
	}
	return &LeaseManager{ttl: ttl}, nil
}

func (m *LeaseManager) Request(deviceID string, take bool, now time.Time) (LeaseDecision, error) {
	if deviceID == "" {
		return LeaseDecision{}, errors.New("device ID is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lease.DeviceID == "" || !now.Before(m.lease.ExpiresAt) || m.lease.DeviceID == deviceID {
		m.lease = Lease{DeviceID: deviceID, ExpiresAt: now.Add(m.ttl)}
		return LeaseDecision{Lease: m.lease}, nil
	}
	if !take {
		return LeaseDecision{Lease: m.lease}, ErrLeaseHeld
	}
	displaced := m.lease.DeviceID
	m.lease = Lease{DeviceID: deviceID, ExpiresAt: now.Add(m.ttl)}
	return LeaseDecision{Lease: m.lease, Displaced: displaced}, nil
}

func (m *LeaseManager) Renew(deviceID string, now time.Time) (Lease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lease.DeviceID != deviceID || !now.Before(m.lease.ExpiresAt) {
		return m.lease, ErrLeaseHeld
	}
	m.lease.ExpiresAt = now.Add(m.ttl)
	return m.lease, nil
}

func (m *LeaseManager) Release(deviceID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lease.DeviceID != deviceID {
		return false
	}
	m.lease = Lease{}
	return true
}

func (m *LeaseManager) Holder(now time.Time) Lease {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lease.DeviceID != "" && !now.Before(m.lease.ExpiresAt) {
		m.lease = Lease{}
	}
	return m.lease
}
