package githubsync

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/githubapp"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/postgres"
)

type fakeGitHub struct {
	mu                  sync.Mutex
	tokenCalls          int
	revokeCalls         int
	installationStarted chan struct{}
	installationRelease <-chan struct{}
	installationSignal  sync.Once
	installationErr     error
	listStarted         chan struct{}
	listRelease         <-chan struct{}
	listSignal          sync.Once
	listErr             error
	suspendedAt         *time.Time
}

func (g *fakeGitHub) Installation(ctx context.Context, _ int64) (githubapp.Installation, error) {
	if g.installationStarted != nil {
		g.installationSignal.Do(func() { close(g.installationStarted) })
	}
	if g.installationRelease != nil {
		select {
		case <-g.installationRelease:
		case <-ctx.Done():
			return githubapp.Installation{}, ctx.Err()
		}
	}
	if g.installationErr != nil {
		return githubapp.Installation{}, g.installationErr
	}
	now := time.Now().UTC()
	return githubapp.Installation{
		ID: 42, AccountID: 7, AccountLogin: "owner", AccountType: "User",
		RepositorySelection: "selected", Permissions: map[string]string{"contents": "write"},
		CreatedAt: now, UpdatedAt: now, SuspendedAt: g.suspendedAt,
	}, nil
}

func (g *fakeGitHub) InstallationToken(context.Context, int64, []int64, map[string]string) (githubapp.InstallationToken, error) {
	g.mu.Lock()
	g.tokenCalls++
	g.mu.Unlock()
	return githubapp.InstallationToken{Token: "installation-token", ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func (g *fakeGitHub) RevokeInstallationToken(context.Context, string) error {
	g.mu.Lock()
	g.revokeCalls++
	g.mu.Unlock()
	return nil
}

func (g *fakeGitHub) ListRepositories(ctx context.Context, _ string, _ int64) ([]core.Repository, error) {
	if g.listStarted != nil {
		g.listSignal.Do(func() { close(g.listStarted) })
	}
	if g.listRelease != nil {
		select {
		case <-g.listRelease:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if g.listErr != nil {
		return nil, g.listErr
	}
	return []core.Repository{{ID: "99", InstallationID: 42, FullName: "owner/repo", DefaultBranch: "main", Permission: "write", UpdatedAt: time.Now().UTC()}}, nil
}

func (g *fakeGitHub) mintedTokens() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.tokenCalls
}

func (g *fakeGitHub) revokedTokens() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.revokeCalls
}

type fakeStore struct {
	authority            sync.RWMutex
	data                 sync.Mutex
	installation         postgres.GitHubInstallation
	installationPresent  bool
	repositories         []core.Repository
	unavailable          bool
	repositoryAvailable  bool
	active               bool
	providerSuspended    bool
	suspendAttempted     chan struct{}
	suspendSignal        sync.Once
	reconnectBegun       chan struct{}
	reconnectSignal      sync.Once
	reconnectCompletions int
	tokenRevoked         func() bool
}

func (s *fakeStore) BeginGitHubInstallationTokenUse(context.Context, githubapp.TokenUseMetadata) error {
	return nil
}

func (s *fakeStore) SetGitHubInstallationTokenUseExpiry(context.Context, string, int64, string, time.Time) error {
	return nil
}

func (s *fakeStore) RevokeGitHubInstallationTokenUse(context.Context, string, int64, string, time.Time) error {
	return nil
}

func (s *fakeStore) WithGitHubInstallationSyncLease(ctx context.Context, _ string, _ int64, operation func(context.Context) error) error {
	s.authority.Lock()
	defer s.authority.Unlock()
	return operation(ctx)
}

func (s *fakeStore) GitHubInstallationActive(context.Context, string, int64) (bool, error) {
	// Sync calls this while holding authority exclusively. Avoid recursively
	// locking the non-reentrant fake lease.
	return s.active, nil
}

func (s *fakeStore) GitHubInstallationProviderActive(context.Context, string, int64) (bool, error) {
	return !s.providerSuspended, nil
}

func (s *fakeStore) UpsertInstallation(_ context.Context, value postgres.GitHubInstallation) error {
	s.data.Lock()
	defer s.data.Unlock()
	s.installation = value
	s.installationPresent = true
	return nil
}

func (s *fakeStore) UpsertInstallationFromProviderUnsuspend(_ context.Context, value postgres.GitHubInstallation) error {
	s.data.Lock()
	defer s.data.Unlock()
	s.installation = value
	s.installationPresent = true
	// The method is called only under the exclusive synchronization lease.
	// A fresh active provider response may clear provider suspension.
	s.active = value.SuspendedAt == nil
	s.providerSuspended = value.SuspendedAt != nil
	return nil
}

func (s *fakeStore) UpsertInstallationForOwnerReconnect(_ context.Context, value postgres.GitHubInstallation, _ time.Time) error {
	s.data.Lock()
	defer s.data.Unlock()
	s.installation = value
	s.installationPresent = true
	s.providerSuspended = value.SuspendedAt != nil
	s.active = false
	return nil
}

func (s *fakeStore) BeginGitHubInstallationReconnect(context.Context, string, int64, time.Time) error {
	s.active = false
	s.data.Lock()
	s.repositoryAvailable = false
	s.data.Unlock()
	if s.reconnectBegun != nil {
		s.reconnectSignal.Do(func() { close(s.reconnectBegun) })
	}
	return nil
}

func (s *fakeStore) CompleteGitHubInstallationReconnect(context.Context, string, int64, time.Time) error {
	if s.providerSuspended {
		return fmt.Errorf("GitHub installation is provider-suspended: %w", core.ErrPrecondition)
	}
	if s.tokenRevoked != nil && !s.tokenRevoked() {
		return errors.New("reconnect completed before its installation token was revoked")
	}
	s.active = true
	s.reconnectCompletions++
	return nil
}

func (s *fakeStore) withSharedTokenLease(ctx context.Context, operation func(context.Context) error) error {
	s.authority.RLock()
	defer s.authority.RUnlock()
	if !s.active {
		return fmt.Errorf("GitHub installation is inactive: %w", core.ErrPrecondition)
	}
	return operation(ctx)
}
func (s *fakeStore) MarkInstallationRepositoriesUnavailable(context.Context, string, int64) error {
	s.data.Lock()
	defer s.data.Unlock()
	s.unavailable = true
	s.repositoryAvailable = false
	return nil
}
func (s *fakeStore) Upsert(_ context.Context, _ string, value core.Repository) error {
	s.data.Lock()
	defer s.data.Unlock()
	s.repositories = append(s.repositories, value)
	s.repositoryAvailable = true
	return nil
}
func (s *fakeStore) SuspendInstallation(context.Context, string, int64, time.Time) error {
	if s.suspendAttempted != nil {
		s.suspendSignal.Do(func() { close(s.suspendAttempted) })
	}
	s.authority.Lock()
	defer s.authority.Unlock()
	s.active = false
	s.providerSuspended = true
	s.data.Lock()
	s.repositoryAvailable = false
	s.data.Unlock()
	return nil
}

func TestSyncAndSignedWebhook(t *testing.T) {
	store := &fakeStore{active: true}
	github := &fakeGitHub{}
	syncer, _ := New(github, store)
	count, err := syncer.Sync(context.Background(), "owner-id", 42)
	if err != nil || count != 1 || !store.unavailable || len(store.repositories) != 1 {
		t.Fatalf("sync = count %d, store %#v, err %v", count, store, err)
	}
	if github.mintedTokens() != 1 || github.revokedTokens() != 1 {
		t.Fatalf("sync token lifecycle: minted=%d revoked=%d", github.mintedTokens(), github.revokedTokens())
	}
	var permissions map[string]string
	if err := json.Unmarshal(store.installation.Permissions, &permissions); err != nil || permissions["contents"] != "write" {
		t.Fatalf("installation permissions = %s, %v", store.installation.Permissions, err)
	}
	secret := []byte(strings.Repeat("w", 32))
	webhook, _ := NewWebhook(secret, syncer, func(context.Context) (string, error) { return "owner-id", nil })
	body := []byte(`{"action":"created","installation":{"id":42}}`)
	digest := hmac.New(sha256.New, secret)
	_, _ = digest.Write(body)
	request := httptest.NewRequest(http.MethodPost, "/v1/github/webhook", strings.NewReader(string(body)))
	request.Header.Set("X-GitHub-Delivery", "delivery-1")
	request.Header.Set("X-GitHub-Event", "installation")
	request.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(digest.Sum(nil)))
	response := httptest.NewRecorder()
	webhook.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("webhook = %d: %s", response.Code, response.Body.String())
	}
}

func TestUnsuspendWebhookValidatesAndSynchronizesUnderOneLease(t *testing.T) {
	store := &fakeStore{active: false}
	github := &fakeGitHub{}
	syncer, err := New(github, store)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte(strings.Repeat("u", 32))
	webhook, err := NewWebhook(secret, syncer, func(context.Context) (string, error) { return "owner-id", nil })
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"action":"unsuspend","installation":{"id":42}}`)
	digest := hmac.New(sha256.New, secret)
	_, _ = digest.Write(body)
	request := httptest.NewRequest(http.MethodPost, "/v1/github/webhook", strings.NewReader(string(body)))
	request.Header.Set("X-GitHub-Delivery", "delivery-unsuspend")
	request.Header.Set("X-GitHub-Event", "installation")
	request.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(digest.Sum(nil)))
	response := httptest.NewRecorder()
	webhook.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("unsuspend webhook = %d: %s", response.Code, response.Body.String())
	}
	if !store.active || github.mintedTokens() != 1 {
		t.Fatalf("unsuspend result: active=%t minted=%d", store.active, github.mintedTokens())
	}
}

func TestStaleUnsuspendKeepsSharedTokenUsersOutsideAuthorityWindow(t *testing.T) {
	installationStarted := make(chan struct{})
	installationRelease := make(chan struct{})
	suspendedAt := time.Now().UTC()
	github := &fakeGitHub{
		installationStarted: installationStarted,
		installationRelease: installationRelease,
		suspendedAt:         &suspendedAt,
	}
	store := &fakeStore{active: false}
	syncer, err := New(github, store)
	if err != nil {
		t.Fatal(err)
	}
	unsuspendDone := make(chan error, 1)
	go func() {
		_, syncErr := syncer.SyncProviderUnsuspend(context.Background(), "owner-id", 42)
		unsuspendDone <- syncErr
	}()
	<-installationStarted
	if store.authority.TryRLock() {
		store.authority.RUnlock()
		t.Fatal("provider validation did not hold the exclusive synchronization lease")
	}
	sharedOperationCalled := make(chan struct{}, 1)
	sharedAttempted := make(chan struct{})
	sharedDone := make(chan error, 1)
	go func() {
		close(sharedAttempted)
		sharedDone <- store.withSharedTokenLease(context.Background(), func(context.Context) error {
			sharedOperationCalled <- struct{}{}
			return nil
		})
	}()
	<-sharedAttempted
	close(installationRelease)
	if err := <-unsuspendDone; err != nil {
		t.Fatal(err)
	}
	if err := <-sharedDone; !errors.Is(err, core.ErrPrecondition) {
		t.Fatalf("shared token user after stale unsuspend returned %v", err)
	}
	select {
	case <-sharedOperationCalled:
		t.Fatal("stale unsuspend opened an installation-token authority window")
	default:
	}
	if github.mintedTokens() != 0 || store.active {
		t.Fatalf("stale unsuspend result: active=%t minted=%d", store.active, github.mintedTokens())
	}
}

func TestOwnerReconnectKeepsSharedTokenUsersBlockedUntilSynchronizationSucceeds(t *testing.T) {
	installationStarted := make(chan struct{})
	installationRelease := make(chan struct{})
	reconnectBegun := make(chan struct{})
	github := &fakeGitHub{installationStarted: installationStarted, installationRelease: installationRelease}
	store := &fakeStore{active: false, reconnectBegun: reconnectBegun}
	store.tokenRevoked = func() bool { return github.revokedTokens() == 1 }
	syncer, err := New(github, store)
	if err != nil {
		t.Fatal(err)
	}
	reconnectDone := make(chan struct {
		count int
		err   error
	}, 1)
	go func() {
		count, reconnectErr := syncer.SyncOwnerReconnect(context.Background(), "owner-id", 42)
		reconnectDone <- struct {
			count int
			err   error
		}{count: count, err: reconnectErr}
	}()
	<-reconnectBegun
	<-installationStarted
	if store.authority.TryRLock() {
		store.authority.RUnlock()
		t.Fatal("owner reconnect released its exclusive lease during provider validation")
	}
	sharedAttempted := make(chan struct{})
	sharedOperationCalled := make(chan struct{}, 1)
	sharedDone := make(chan error, 1)
	go func() {
		close(sharedAttempted)
		sharedDone <- store.withSharedTokenLease(context.Background(), func(context.Context) error {
			sharedOperationCalled <- struct{}{}
			return nil
		})
	}()
	<-sharedAttempted
	close(installationRelease)
	result := <-reconnectDone
	if result.err != nil || result.count != 1 {
		t.Fatalf("owner reconnect = count %d err %v", result.count, result.err)
	}
	if err := <-sharedDone; err != nil {
		t.Fatalf("shared token user after successful reconnect: %v", err)
	}
	select {
	case <-sharedOperationCalled:
	default:
		t.Fatal("shared token user did not enter after successful reconnect")
	}
	if !store.installationPresent || !store.active || store.reconnectCompletions != 1 || github.mintedTokens() != 1 || github.revokedTokens() != 1 {
		t.Fatalf("successful fresh reconnect state: present=%t active=%t completions=%d minted=%d revoked=%d", store.installationPresent, store.active, store.reconnectCompletions, github.mintedTokens(), github.revokedTokens())
	}
}

func TestFreshOwnerReconnectProviderFailureRemainsAbsent(t *testing.T) {
	providerFailure := errors.New("installation lookup failed")
	github := &fakeGitHub{installationErr: providerFailure}
	store := &fakeStore{}
	syncer, err := New(github, store)
	if err != nil {
		t.Fatal(err)
	}
	count, err := syncer.SyncOwnerReconnect(context.Background(), "owner-id", 42)
	if !errors.Is(err, providerFailure) || count != 0 {
		t.Fatalf("fresh failed owner reconnect = count %d err %v", count, err)
	}
	if store.installationPresent || store.active || store.reconnectCompletions != 0 || github.mintedTokens() != 0 {
		t.Fatalf("fresh failed reconnect state: present=%t active=%t completions=%d minted=%d", store.installationPresent, store.active, store.reconnectCompletions, github.mintedTokens())
	}
}

func TestOwnerReconnectFailureRemainsDisconnected(t *testing.T) {
	providerFailure := errors.New("repository listing failed")
	github := &fakeGitHub{listErr: providerFailure}
	store := &fakeStore{active: false, repositoryAvailable: true}
	syncer, err := New(github, store)
	if err != nil {
		t.Fatal(err)
	}
	count, err := syncer.SyncOwnerReconnect(context.Background(), "owner-id", 42)
	if !errors.Is(err, providerFailure) || count != 0 {
		t.Fatalf("failed owner reconnect = count %d err %v", count, err)
	}
	operationCalled := false
	err = store.withSharedTokenLease(context.Background(), func(context.Context) error {
		operationCalled = true
		return nil
	})
	if !errors.Is(err, core.ErrPrecondition) || operationCalled {
		t.Fatalf("shared token lease after failed reconnect = called=%t err=%v", operationCalled, err)
	}
	store.data.Lock()
	available := store.repositoryAvailable
	store.data.Unlock()
	if store.active || available || store.reconnectCompletions != 0 || github.mintedTokens() != 1 {
		t.Fatalf("failed reconnect state: active=%t available=%t completions=%d minted=%d", store.active, available, store.reconnectCompletions, github.mintedTokens())
	}
}

func TestOwnerReconnectCannotClearProviderSuspension(t *testing.T) {
	suspendedAt := time.Now().UTC()
	github := &fakeGitHub{suspendedAt: &suspendedAt}
	store := &fakeStore{active: false, providerSuspended: true}
	syncer, err := New(github, store)
	if err != nil {
		t.Fatal(err)
	}
	count, err := syncer.SyncOwnerReconnect(context.Background(), "owner-id", 42)
	if !errors.Is(err, core.ErrPrecondition) || count != 0 {
		t.Fatalf("provider-suspended owner reconnect = count %d err %v", count, err)
	}
	if store.active || store.reconnectCompletions != 0 || github.mintedTokens() != 0 {
		t.Fatalf("provider-suspended reconnect state: active=%t completions=%d minted=%d", store.active, store.reconnectCompletions, github.mintedTokens())
	}
}

func TestSyncDoesNotUndoOwnerDisconnect(t *testing.T) {
	store := &fakeStore{active: false}
	github := &fakeGitHub{}
	syncer, err := New(github, store)
	if err != nil {
		t.Fatal(err)
	}
	count, err := syncer.Sync(context.Background(), "owner-id", 42)
	if err != nil || count != 0 || store.unavailable || len(store.repositories) != 0 {
		t.Fatalf("disconnected sync = count %d, store %#v, err %v", count, store, err)
	}
	if github.mintedTokens() != 0 {
		t.Fatalf("disconnected sync minted %d installation tokens", github.mintedTokens())
	}
	store.authority.Lock()
	store.active = true
	store.authority.Unlock()
	count, err = syncer.Sync(context.Background(), "owner-id", 42)
	if err != nil || count != 1 {
		t.Fatalf("explicitly reconnected sync = count %d err %v", count, err)
	}
	store.data.Lock()
	available := store.repositoryAvailable
	store.data.Unlock()
	if !available {
		t.Fatal("denied stale sync made repositories unavailable after explicit reconnect")
	}
}

func TestSyncFirstIsDrainedBeforeSuspendMakesFinalAvailabilityWrite(t *testing.T) {
	installationStarted := make(chan struct{})
	installationRelease := make(chan struct{})
	suspendAttempted := make(chan struct{})
	github := &fakeGitHub{installationStarted: installationStarted, installationRelease: installationRelease}
	store := &fakeStore{active: true, suspendAttempted: suspendAttempted}
	syncer, err := New(github, store)
	if err != nil {
		t.Fatal(err)
	}
	syncDone := make(chan error, 1)
	go func() {
		_, syncErr := syncer.Sync(context.Background(), "owner-id", 42)
		syncDone <- syncErr
	}()
	<-installationStarted
	suspendDone := make(chan error, 1)
	go func() {
		suspendDone <- syncer.Suspend(context.Background(), "owner-id", 42)
	}()
	<-suspendAttempted
	select {
	case err := <-suspendDone:
		t.Fatalf("suspend completed while provider metadata fetch still held the synchronization lease: %v", err)
	default:
	}
	close(installationRelease)
	if err := <-syncDone; err != nil {
		t.Fatal(err)
	}
	if err := <-suspendDone; err != nil {
		t.Fatal(err)
	}
	store.data.Lock()
	available := store.repositoryAvailable
	store.data.Unlock()
	if available {
		t.Fatal("repository sync re-enabled availability after suspension")
	}
	if github.mintedTokens() != 1 {
		t.Fatalf("initial sync minted %d tokens", github.mintedTokens())
	}
	if count, err := syncer.Sync(context.Background(), "owner-id", 42); err != nil || count != 0 {
		t.Fatalf("post-suspension sync = count %d err %v", count, err)
	}
	if github.mintedTokens() != 1 {
		t.Fatal("post-suspension sync minted another installation token")
	}
}

func TestSuspendFirstCannotBeUndoneByStaleActiveProviderMetadata(t *testing.T) {
	github := &fakeGitHub{}
	store := &fakeStore{active: true, repositoryAvailable: true}
	syncer, err := New(github, store)
	if err != nil {
		t.Fatal(err)
	}
	if err := syncer.Suspend(context.Background(), "owner-id", 42); err != nil {
		t.Fatal(err)
	}
	count, err := syncer.Sync(context.Background(), "owner-id", 42)
	if err != nil || count != 0 {
		t.Fatalf("stale post-suspend sync = count %d err %v", count, err)
	}
	if github.mintedTokens() != 0 {
		t.Fatalf("stale post-suspend sync minted %d tokens", github.mintedTokens())
	}
	store.data.Lock()
	available := store.repositoryAvailable
	repositories := len(store.repositories)
	store.data.Unlock()
	if available || repositories != 0 {
		t.Fatalf("stale metadata restored repositories: available=%t repositories=%d", available, repositories)
	}
}
