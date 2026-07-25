package preview

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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
)

const (
	defaultMaximumPreviewGrants          = 4096
	defaultMaximumPreviewGrantsPerOwner  = 1024
	defaultMaximumPreviewGrantsPerRoute  = 128
	defaultMaximumActivePreviews         = 1024
	defaultMaximumActivePreviewsPerOwner = 256
	defaultMaximumActivePreviewsPerRoute = 64
	previewCleanupInterval               = 30 * time.Second
)

type Route struct {
	ID          string `json:"id"`
	OwnerID     string `json:"owner_id"`
	WorkspaceID string `json:"workspace_id"`
	Port        uint16 `json:"port"`
	Process     string `json:"process"`
	// Host is the private provider workspace UUID used to establish a tunnel;
	// it is never exposed as an upstream HTTP host.
	Host      string     `json:"host"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

type Grant struct {
	ID          string
	RouteID     string
	OwnerID     string
	DeviceID    string
	WorkspaceID string
	Port        uint16
	Hash        [32]byte
	ExpiresAt   time.Time
	RevokedAt   *time.Time
}

type TokenManager struct {
	mu             sync.Mutex
	randomMu       sync.Mutex
	pepper         []byte
	random         io.Reader
	now            func() time.Time
	grants         map[string]Grant
	grantsByOwner  map[string]int
	grantsByRoute  map[string]int
	activeByRoute  map[string]map[uint64]activeAuthorization
	activeByOwner  map[string]int
	activeCount    int
	nextActiveID   uint64
	maxTTL         time.Duration
	maxGrants      int
	maxOwnerGrants int
	maxRouteGrants int
	maxActive      int
	maxOwnerActive int
	maxRouteActive int
	nextCleanup    time.Time
}

type activeAuthorization struct {
	ownerID   string
	deviceID  string
	expiresAt time.Time
	cancel    context.CancelFunc
}

func NewTokenManager(pepper []byte) (*TokenManager, error) {
	return NewTokenManagerWithDependencies(pepper, rand.Reader, func() time.Time { return time.Now().UTC() })
}

func NewTokenManagerWithDependencies(pepper []byte, random io.Reader, now func() time.Time) (*TokenManager, error) {
	if len(pepper) < 32 || random == nil || now == nil {
		return nil, errors.New("preview token pepper, random source, and clock are required")
	}
	return &TokenManager{
		pepper:         append([]byte(nil), pepper...),
		random:         random,
		now:            now,
		grants:         make(map[string]Grant),
		grantsByOwner:  make(map[string]int),
		grantsByRoute:  make(map[string]int),
		activeByRoute:  make(map[string]map[uint64]activeAuthorization),
		activeByOwner:  make(map[string]int),
		maxTTL:         10 * time.Minute,
		maxGrants:      defaultMaximumPreviewGrants,
		maxOwnerGrants: defaultMaximumPreviewGrantsPerOwner,
		maxRouteGrants: defaultMaximumPreviewGrantsPerRoute,
		maxActive:      defaultMaximumActivePreviews,
		maxOwnerActive: defaultMaximumActivePreviewsPerOwner,
		maxRouteActive: defaultMaximumActivePreviewsPerRoute,
	}, nil
}

func (m *TokenManager) Issue(route Route, deviceID string, ttl time.Duration) (string, time.Time, error) {
	if route.ID == "" || route.OwnerID == "" || deviceID == "" || route.WorkspaceID == "" || route.Port < 1024 || route.RevokedAt != nil {
		return "", time.Time{}, errors.New("invalid preview route")
	}
	if ttl <= 0 || ttl > m.maxTTL {
		return "", time.Time{}, errors.New("preview TTL must be between 1ns and 10 minutes")
	}
	// io.Reader does not promise concurrent safety. Keep injected entropy
	// sources serialized without holding the state mutex, since a slow reader
	// must not block validation or revocation of already-issued grants.
	m.randomMu.Lock()
	id, err := randomPart(m.random, 16)
	if err != nil {
		m.randomMu.Unlock()
		return "", time.Time{}, err
	}
	secret, err := randomPart(m.random, 32)
	m.randomMu.Unlock()
	if err != nil {
		return "", time.Time{}, err
	}
	m.mu.Lock()
	now := m.now()
	cancels := m.maybeCleanupLocked(now)
	if m.grantCapacityReachedLocked(route.OwnerID, route.ID) {
		m.mu.Unlock()
		cancelAll(cancels)
		return "", time.Time{}, fmt.Errorf("preview token capacity: %w", core.ErrCapacity)
	}
	if _, collision := m.grants[id]; collision {
		m.mu.Unlock()
		cancelAll(cancels)
		return "", time.Time{}, errors.New("preview token identity collision")
	}
	expires := now.Add(ttl)
	grant := Grant{ID: id, RouteID: route.ID, OwnerID: route.OwnerID, DeviceID: deviceID, WorkspaceID: route.WorkspaceID, Port: route.Port, ExpiresAt: expires}
	grant.Hash = m.hash(grant, secret)
	m.grants[id] = grant
	m.grantsByOwner[route.OwnerID]++
	m.grantsByRoute[route.ID]++
	m.mu.Unlock()
	cancelAll(cancels)
	return "pv_" + id + "." + secret, expires, nil
}

func (m *TokenManager) Validate(token, routeID, ownerID, workspaceID string, port uint16) error {
	id, secret, err := parse(token)
	if err != nil {
		return err
	}
	m.mu.Lock()
	now := m.now()
	cancels := m.maybeCleanupLocked(now)
	_, err = m.validateLocked(id, secret, routeID, ownerID, workspaceID, port, now)
	m.mu.Unlock()
	cancelAll(cancels)
	return err
}

// Authorize binds a proxied request to the lifetime of its audience-bound
// grant. RevokeRoute cancels every returned context for that route, allowing
// ReverseProxy to tear down long-lived HTTP streams and upgraded WebSockets
// instead of validating only at the initial handshake.
func (m *TokenManager) Authorize(parent context.Context, token, routeID, ownerID, workspaceID string, port uint16) (context.Context, func(), error) {
	if parent == nil {
		return nil, nil, errors.New("preview request context is required")
	}
	if err := parent.Err(); err != nil {
		return nil, nil, err
	}
	id, secret, err := parse(token)
	if err != nil {
		return nil, nil, err
	}
	m.mu.Lock()
	now := m.now()
	cancels := m.maybeCleanupLocked(now)
	grant, err := m.validateLocked(id, secret, routeID, ownerID, workspaceID, port, now)
	if err != nil {
		m.mu.Unlock()
		cancelAll(cancels)
		return nil, nil, err
	}
	active := m.activeByRoute[routeID]
	if m.activeCapacityReachedLocked(ownerID, active) {
		m.mu.Unlock()
		cancelAll(cancels)
		return nil, nil, fmt.Errorf("preview authorization capacity: %w", core.ErrCapacity)
	}
	remaining := grant.ExpiresAt.Sub(now)
	if remaining <= 0 {
		m.mu.Unlock()
		cancelAll(cancels)
		return nil, nil, errors.New("invalid preview token")
	}
	requestContext, cancel := context.WithTimeout(parent, remaining)
	m.nextActiveID++
	if m.nextActiveID == 0 {
		m.nextActiveID++
	}
	activeID := m.nextActiveID
	if active == nil {
		active = make(map[uint64]activeAuthorization)
		m.activeByRoute[routeID] = active
	}
	active[activeID] = activeAuthorization{ownerID: ownerID, deviceID: grant.DeviceID, expiresAt: grant.ExpiresAt, cancel: cancel}
	m.activeCount++
	m.activeByOwner[ownerID]++
	m.mu.Unlock()
	cancelAll(cancels)

	var once sync.Once
	release := func() {
		once.Do(func() {
			m.mu.Lock()
			if active := m.activeByRoute[routeID]; active != nil {
				if authorization, exists := active[activeID]; exists {
					delete(active, activeID)
					m.decrementActiveOwnerLocked(authorization.ownerID)
					m.activeCount--
					if len(active) == 0 {
						delete(m.activeByRoute, routeID)
					}
				}
			}
			m.mu.Unlock()
			cancel()
		})
	}
	return requestContext, release, nil
}

func (m *TokenManager) RevokeRoute(routeID string) int {
	m.mu.Lock()
	now := m.now()
	cancels := m.cleanupLocked(now)
	count := 0
	for id, grant := range m.grants {
		if grant.RouteID == routeID {
			m.removeGrantLocked(id, grant)
			count++
		}
	}
	active := m.activeByRoute[routeID]
	delete(m.activeByRoute, routeID)
	for _, authorization := range active {
		m.decrementActiveOwnerLocked(authorization.ownerID)
		m.activeCount--
		cancels = append(cancels, authorization.cancel)
	}
	m.mu.Unlock()
	cancelAll(cancels)
	return count
}

// RevokeDevice invalidates every grant issued to one exact owner/device and
// cancels its active proxy requests without disturbing another installation.
// Application session/device revocation serializes Issue with this sweep.
func (m *TokenManager) RevokeDevice(ownerID, deviceID string) int {
	if ownerID == "" || deviceID == "" {
		return 0
	}
	m.mu.Lock()
	now := m.now()
	cancels := m.cleanupLocked(now)
	count := 0
	for id, grant := range m.grants {
		if grant.OwnerID == ownerID && grant.DeviceID == deviceID {
			m.removeGrantLocked(id, grant)
			count++
		}
	}
	for routeID, active := range m.activeByRoute {
		for activeID, authorization := range active {
			if authorization.ownerID != ownerID || authorization.deviceID != deviceID {
				continue
			}
			delete(active, activeID)
			m.decrementActiveOwnerLocked(authorization.ownerID)
			m.activeCount--
			cancels = append(cancels, authorization.cancel)
		}
		if len(active) == 0 {
			delete(m.activeByRoute, routeID)
		}
	}
	m.mu.Unlock()
	cancelAll(cancels)
	return count
}

func (m *TokenManager) validateLocked(id, secret, routeID, ownerID, workspaceID string, port uint16, now time.Time) (Grant, error) {
	grant, ok := m.grants[id]
	if !ok || grant.RevokedAt != nil || !now.Before(grant.ExpiresAt) {
		return Grant{}, errors.New("invalid preview token")
	}
	if grant.RouteID != routeID || grant.OwnerID != ownerID || grant.WorkspaceID != workspaceID || grant.Port != port {
		return Grant{}, errors.New("preview token audience mismatch")
	}
	presented := m.hash(grant, secret)
	if subtle.ConstantTimeCompare(grant.Hash[:], presented[:]) != 1 {
		return Grant{}, errors.New("invalid preview token")
	}
	return grant, nil
}

func (m *TokenManager) grantCapacityReachedLocked(ownerID, routeID string) bool {
	return len(m.grants) >= m.maxGrants || m.grantsByOwner[ownerID] >= m.maxOwnerGrants || m.grantsByRoute[routeID] >= m.maxRouteGrants
}

func (m *TokenManager) activeCapacityReachedLocked(ownerID string, active map[uint64]activeAuthorization) bool {
	return m.activeCount >= m.maxActive || m.activeByOwner[ownerID] >= m.maxOwnerActive || len(active) >= m.maxRouteActive
}

func (m *TokenManager) maybeCleanupLocked(now time.Time) []context.CancelFunc {
	if !m.nextCleanup.IsZero() && now.Before(m.nextCleanup) {
		return nil
	}
	return m.cleanupLocked(now)
}

func (m *TokenManager) cleanupLocked(now time.Time) []context.CancelFunc {
	m.nextCleanup = now.Add(previewCleanupInterval)
	for id, grant := range m.grants {
		if grant.RevokedAt != nil || !now.Before(grant.ExpiresAt) {
			m.removeGrantLocked(id, grant)
		}
	}
	var cancels []context.CancelFunc
	for routeID, active := range m.activeByRoute {
		for activeID, authorization := range active {
			if !now.Before(authorization.expiresAt) {
				delete(active, activeID)
				m.decrementActiveOwnerLocked(authorization.ownerID)
				m.activeCount--
				cancels = append(cancels, authorization.cancel)
			}
		}
		if len(active) == 0 {
			delete(m.activeByRoute, routeID)
		}
	}
	return cancels
}

func (m *TokenManager) removeGrantLocked(id string, grant Grant) {
	delete(m.grants, id)
	if m.grantsByOwner[grant.OwnerID] <= 1 {
		delete(m.grantsByOwner, grant.OwnerID)
	} else {
		m.grantsByOwner[grant.OwnerID]--
	}
	if m.grantsByRoute[grant.RouteID] <= 1 {
		delete(m.grantsByRoute, grant.RouteID)
	} else {
		m.grantsByRoute[grant.RouteID]--
	}
}

func (m *TokenManager) decrementActiveOwnerLocked(ownerID string) {
	if m.activeByOwner[ownerID] <= 1 {
		delete(m.activeByOwner, ownerID)
	} else {
		m.activeByOwner[ownerID]--
	}
}

func cancelAll(cancels []context.CancelFunc) {
	for _, cancel := range cancels {
		cancel()
	}
}

// WorkspaceTarget is deliberately loopback-only. The workspace provider must
// execute the dial inside the authorized workspace network namespace.
func WorkspaceTarget(port uint16) (string, error) {
	if port < 1024 {
		return "", errors.New("privileged preview ports are not allowed")
	}
	return "127.0.0.1:" + strconv.Itoa(int(port)), nil
}

func (m *TokenManager) hash(grant Grant, secret string) [32]byte {
	h := hmac.New(sha256.New, m.pepper)
	for _, value := range []string{"codex-mobile:preview:v2", grant.ID, grant.RouteID, grant.OwnerID, grant.DeviceID, grant.WorkspaceID, strconv.Itoa(int(grant.Port)), secret} {
		h.Write([]byte(value))
		h.Write([]byte{0})
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func parse(token string) (string, string, error) {
	if !strings.HasPrefix(token, "pv_") || len(token) > 256 {
		return "", "", errors.New("malformed preview token")
	}
	parts := strings.Split(strings.TrimPrefix(token, "pv_"), ".")
	if len(parts) != 2 {
		return "", "", errors.New("malformed preview token")
	}
	for _, part := range parts {
		if _, err := base64.RawURLEncoding.DecodeString(part); err != nil {
			return "", "", errors.New("malformed preview token")
		}
	}
	return parts[0], parts[1], nil
}

func randomPart(random io.Reader, size int) (string, error) {
	b := make([]byte, size)
	if _, err := io.ReadFull(random, b); err != nil {
		return "", fmt.Errorf("random preview token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
