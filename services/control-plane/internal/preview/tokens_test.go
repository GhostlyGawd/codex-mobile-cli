package preview

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
)

func manager(t *testing.T) (*TokenManager, *time.Time) {
	t.Helper()
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	randomBytes := make([]byte, 1024)
	for i := range randomBytes {
		randomBytes[i] = byte(i)
	}
	m, err := NewTokenManagerWithDependencies(bytes.Repeat([]byte{1}, 32), bytes.NewReader(randomBytes), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return m, &now
}

func route() Route {
	return Route{ID: "route-1", OwnerID: "owner-1", WorkspaceID: "workspace-1", Port: 3000}
}

func TestAudienceBoundTokenAndRevocation(t *testing.T) {
	t.Parallel()
	m, _ := manager(t)
	token, _, err := m.Issue(route(), "device-1", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Validate(token, "route-1", "owner-1", "workspace-1", 3000); err != nil {
		t.Fatal(err)
	}
	if err := m.Validate(token, "route-1", "owner-1", "workspace-2", 3000); err == nil {
		t.Fatal("wrong workspace audience accepted")
	}
	if count := m.RevokeRoute("route-1"); count != 1 {
		t.Fatalf("revoked %d grants", count)
	}
	if err := m.Validate(token, "route-1", "owner-1", "workspace-1", 3000); err == nil {
		t.Fatal("revoked preview token accepted")
	}
}

func TestRouteRevocationCancelsAuthorizedRequestContexts(t *testing.T) {
	t.Parallel()
	m, _ := manager(t)
	token, _, err := m.Issue(route(), "device-1", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	authorized, release, err := m.Authorize(context.Background(), token, "route-1", "owner-1", "workspace-1", 3000)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	select {
	case <-authorized.Done():
		t.Fatalf("authorized context ended before revocation: %v", authorized.Err())
	default:
	}
	if count := m.RevokeRoute("route-1"); count != 1 {
		t.Fatalf("revoked %d grants", count)
	}
	select {
	case <-authorized.Done():
		if err := authorized.Err(); err != context.Canceled {
			t.Fatalf("authorized context error = %v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("authorized context remained active after route revocation")
	}
	m.mu.Lock()
	activeRoutes := len(m.activeByRoute)
	m.mu.Unlock()
	if activeRoutes != 0 {
		t.Fatalf("active route registrations = %d, want 0", activeRoutes)
	}
}

func TestDeviceRevocationInvalidatesOnlyThatDevicesPreviewAuthority(t *testing.T) {
	m, _ := manager(t)
	m.maxGrants = 2
	m.maxOwnerGrants = 2
	m.maxRouteGrants = 2
	first, _, err := m.Issue(route(), "device-1", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := m.Issue(route(), "device-2", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	firstContext, releaseFirst, err := m.Authorize(context.Background(), first, "route-1", "owner-1", "workspace-1", 3000)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseFirst()
	secondContext, releaseSecond, err := m.Authorize(context.Background(), second, "route-1", "owner-1", "workspace-1", 3000)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseSecond()

	if count := m.RevokeDevice("owner-1", "device-1"); count != 1 {
		t.Fatalf("device grant revocation count = %d", count)
	}
	select {
	case <-firstContext.Done():
		if firstContext.Err() != context.Canceled {
			t.Fatalf("revoked device context error = %v", firstContext.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("revoked device preview context remained active")
	}
	select {
	case <-secondContext.Done():
		t.Fatalf("other device preview context was canceled: %v", secondContext.Err())
	default:
	}
	if err := m.Validate(first, "route-1", "owner-1", "workspace-1", 3000); err == nil {
		t.Fatal("revoked device preview token remained valid")
	}
	if err := m.Validate(second, "route-1", "owner-1", "workspace-1", 3000); err != nil {
		t.Fatalf("other device preview token was revoked: %v", err)
	}
	if _, _, err := m.Issue(route(), "device-3", 5*time.Minute); err != nil {
		t.Fatalf("grant capacity did not recover after device revocation: %v", err)
	}
}

func TestTokenExpiry(t *testing.T) {
	t.Parallel()
	m, now := manager(t)
	token, _, _ := m.Issue(route(), "device-1", time.Minute)
	*now = now.Add(2 * time.Minute)
	if err := m.Validate(token, "route-1", "owner-1", "workspace-1", 3000); err == nil {
		t.Fatal("expired preview token accepted")
	}
}

func TestGrantCapacityRecoversAfterRevokeAndExpiry(t *testing.T) {
	m, now := manager(t)
	m.maxGrants = 2
	m.maxOwnerGrants = 2
	m.maxRouteGrants = 2

	first, _, err := m.Issue(route(), "device-1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Issue(route(), "device-1", time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Issue(route(), "device-1", time.Minute); !errors.Is(err, core.ErrCapacity) {
		t.Fatalf("grant capacity error = %v", err)
	}
	if count := m.RevokeRoute(route().ID); count != 2 {
		t.Fatalf("revoked grant count = %d", count)
	}
	m.mu.Lock()
	if len(m.grants) != 0 || len(m.grantsByOwner) != 0 || len(m.grantsByRoute) != 0 {
		m.mu.Unlock()
		t.Fatal("revoked grants remained retained")
	}
	m.mu.Unlock()
	if err := m.Validate(first, route().ID, route().OwnerID, route().WorkspaceID, route().Port); err == nil {
		t.Fatal("deleted revoked grant remained valid")
	}
	if _, _, err := m.Issue(route(), "device-1", time.Minute); err != nil {
		t.Fatalf("capacity did not recover after revoke: %v", err)
	}
	*now = now.Add(2 * time.Minute)
	if _, _, err := m.Issue(route(), "device-1", time.Minute); err != nil {
		t.Fatalf("capacity did not recover after expiry: %v", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.grants) != 1 || m.grantsByOwner[route().OwnerID] != 1 || m.grantsByRoute[route().ID] != 1 {
		t.Fatalf("expired grant cleanup mismatch: grants=%d owners=%v routes=%v", len(m.grants), m.grantsByOwner, m.grantsByRoute)
	}
}

func TestConcurrentIssueSerializesInjectedRandomSource(t *testing.T) {
	m, _ := manager(t)
	const issuers = 16
	errs := make(chan error, issuers)
	var wait sync.WaitGroup
	for range issuers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, _, err := m.Issue(route(), "device-1", time.Minute)
			errs <- err
		}()
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestActiveAuthorizationCapacityRecoversAfterReleaseAndExpiry(t *testing.T) {
	m, now := manager(t)
	m.maxActive = 2
	m.maxOwnerActive = 2
	m.maxRouteActive = 2
	token, _, err := m.Issue(route(), "device-1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, releaseFirst, err := m.Authorize(context.Background(), token, route().ID, route().OwnerID, route().WorkspaceID, route().Port)
	if err != nil {
		t.Fatal(err)
	}
	_, releaseSecond, err := m.Authorize(context.Background(), token, route().ID, route().OwnerID, route().WorkspaceID, route().Port)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Authorize(context.Background(), token, route().ID, route().OwnerID, route().WorkspaceID, route().Port); !errors.Is(err, core.ErrCapacity) {
		t.Fatalf("active capacity error = %v", err)
	}
	releaseFirst()
	_, releaseReplacement, err := m.Authorize(context.Background(), token, route().ID, route().OwnerID, route().WorkspaceID, route().Port)
	if err != nil {
		t.Fatalf("active capacity did not recover after release: %v", err)
	}
	releaseSecond()
	releaseReplacement()

	m.maxActive = 1
	m.maxOwnerActive = 1
	m.maxRouteActive = 1
	expiringContext, releaseExpiring, err := m.Authorize(context.Background(), token, route().ID, route().OwnerID, route().WorkspaceID, route().Port)
	if err != nil {
		t.Fatal(err)
	}
	*now = now.Add(2 * time.Minute)
	replacementToken, _, err := m.Issue(route(), "device-1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, releaseAfterExpiry, err := m.Authorize(context.Background(), replacementToken, route().ID, route().OwnerID, route().WorkspaceID, route().Port)
	if err != nil {
		t.Fatalf("active capacity did not recover after expiry: %v", err)
	}
	select {
	case <-expiringContext.Done():
	case <-time.After(time.Second):
		t.Fatal("expired active authorization was not canceled")
	}
	releaseExpiring()
	m.mu.Lock()
	if m.activeCount != 1 || m.activeByOwner[route().OwnerID] != 1 {
		m.mu.Unlock()
		t.Fatalf("late release corrupted active counts: count=%d owners=%v", m.activeCount, m.activeByOwner)
	}
	m.mu.Unlock()
	releaseAfterExpiry()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.activeCount != 0 || len(m.activeByOwner) != 0 || len(m.activeByRoute) != 0 {
		t.Fatalf("active authorization state retained after release: count=%d owners=%v routes=%v", m.activeCount, m.activeByOwner, m.activeByRoute)
	}
}

func TestWorkspaceTargetCannotAddressArbitraryHost(t *testing.T) {
	t.Parallel()
	target, err := WorkspaceTarget(8080)
	if err != nil || target != "127.0.0.1:8080" {
		t.Fatalf("target = %q, %v", target, err)
	}
	if _, err := WorkspaceTarget(80); err == nil {
		t.Fatal("privileged port accepted")
	}
}
