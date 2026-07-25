package session

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type testClock struct{ now time.Time }

type failingReplayStore struct {
	*MemoryStore
	err error
}

func (s *failingReplayStore) RevokeFamily(context.Context, string, time.Time) error {
	return s.err
}

func (c *testClock) Now() time.Time { return c.now }

func manager(t *testing.T) (*Manager, *testClock) {
	t.Helper()
	clock := &testClock{now: time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)}
	randomBytes := make([]byte, 4096)
	for i := range randomBytes {
		randomBytes[i] = byte(i)
	}
	m, err := NewWithDependencies(NewMemoryStore(), bytes.Repeat([]byte{9}, 32), 15*time.Minute, 30*24*time.Hour, bytes.NewReader(randomBytes), clock)
	if err != nil {
		t.Fatal(err)
	}
	return m, clock
}

func TestIssueAuthenticateRotate(t *testing.T) {
	t.Parallel()
	m, _ := manager(t)
	pair, err := m.Issue(context.Background(), "owner-1", "device-1")
	if err != nil {
		t.Fatal(err)
	}
	principal, err := m.Authenticate(context.Background(), pair.AccessToken)
	if err != nil || principal.OwnerID != "owner-1" || principal.DeviceID != "device-1" {
		t.Fatalf("principal = %#v, %v", principal, err)
	}
	next, err := m.Rotate(context.Background(), pair.RefreshToken)
	if err != nil || next.RefreshToken == pair.RefreshToken {
		t.Fatalf("rotation = %#v, %v", next, err)
	}
}

func TestValidatePrincipalAndRefreshIdentityTrackDurableRevocation(t *testing.T) {
	t.Parallel()
	m, _ := manager(t)
	pair, err := m.Issue(context.Background(), "owner", "device")
	if err != nil {
		t.Fatal(err)
	}
	principal, err := m.Authenticate(context.Background(), pair.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ValidatePrincipal(context.Background(), principal); err != nil {
		t.Fatalf("active principal did not validate: %v", err)
	}
	refreshPrincipal, err := m.RefreshPrincipal(context.Background(), pair.RefreshToken)
	if err != nil || refreshPrincipal != principal {
		t.Fatalf("refresh identity = %#v, %v", refreshPrincipal, err)
	}
	wrong := pair.RefreshToken[:strings.LastIndex(pair.RefreshToken, ".")+1] + strings.Repeat("A", 43)
	if _, err := m.RefreshPrincipal(context.Background(), wrong); err == nil {
		t.Fatal("wrong refresh secret exposed a principal")
	}
	if err := m.RevokeFamily(context.Background(), principal.FamilyID); err != nil {
		t.Fatal(err)
	}
	if err := m.ValidatePrincipal(context.Background(), principal); err == nil {
		t.Fatal("revoked family principal remained valid")
	}
	if _, err := m.RefreshPrincipal(context.Background(), pair.RefreshToken); err == nil {
		t.Fatal("revoked refresh credential exposed a principal")
	}
}

func TestRefreshReplayRevokesFamily(t *testing.T) {
	t.Parallel()
	m, _ := manager(t)
	pair, _ := m.Issue(context.Background(), "owner", "device")
	next, _ := m.Rotate(context.Background(), pair.RefreshToken)
	if _, err := m.Rotate(context.Background(), pair.RefreshToken); !errors.Is(err, ErrReplay) {
		t.Fatalf("expected replay, got %v", err)
	}
	if _, err := m.Authenticate(context.Background(), next.AccessToken); err == nil {
		t.Fatal("access token from replayed family remained valid")
	}
}

func TestRefreshReplayReportsDurableRevocationFailure(t *testing.T) {
	t.Parallel()
	clock := &testClock{now: time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)}
	randomBytes := make([]byte, 4096)
	for i := range randomBytes {
		randomBytes[i] = byte(i)
	}
	revokeFailure := errors.New("durable revoke failed")
	store := &failingReplayStore{MemoryStore: NewMemoryStore(), err: revokeFailure}
	m, err := NewWithDependencies(store, bytes.Repeat([]byte{9}, 32), 15*time.Minute, 30*24*time.Hour, bytes.NewReader(randomBytes), clock)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := m.Issue(context.Background(), "owner", "device")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Rotate(context.Background(), pair.RefreshToken); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Rotate(context.Background(), pair.RefreshToken); !errors.Is(err, revokeFailure) || errors.Is(err, ErrReplay) {
		t.Fatalf("replay durable-revoke failure = %v", err)
	}
}

func TestWrongRefreshSecretDoesNotRevokeFamily(t *testing.T) {
	t.Parallel()
	m, _ := manager(t)
	pair, _ := m.Issue(context.Background(), "owner", "device")
	wrong := pair.RefreshToken[:strings.LastIndex(pair.RefreshToken, ".")+1] + strings.Repeat("A", 43)
	if _, err := m.Rotate(context.Background(), wrong); err == nil {
		t.Fatal("wrong secret unexpectedly rotated")
	}
	if _, err := m.Rotate(context.Background(), pair.RefreshToken); err != nil {
		t.Fatalf("valid refresh failed after wrong guess: %v", err)
	}
}

func TestExpiryAndDeviceRevocation(t *testing.T) {
	t.Parallel()
	m, clock := manager(t)
	pair, _ := m.Issue(context.Background(), "owner", "device")
	clock.now = clock.now.Add(16 * time.Minute)
	if _, err := m.Authenticate(context.Background(), pair.AccessToken); err == nil {
		t.Fatal("expired access credential accepted")
	}
	next, err := m.Rotate(context.Background(), pair.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.RevokeDevice(context.Background(), "owner", "device"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Authenticate(context.Background(), next.AccessToken); err == nil {
		t.Fatal("revoked device credential accepted")
	}
}
