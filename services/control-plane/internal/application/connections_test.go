package application

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/githubapp"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/gitops"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/httpapi"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/postgres"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/terminal"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/workspacehelper"
)

type fakeConnections struct {
	lease               sync.RWMutex
	tokenMu             sync.Mutex
	tokenUses           map[string]githubapp.TokenUseMetadata
	installations       []postgres.GitHubInstallationConnection
	active              bool
	ownerID             string
	installation        int64
	disconnects         int
	disconnectAttempted chan struct{}
	disconnectSignal    sync.Once
}

func (f *fakeConnections) ListGitHubInstallations(_ context.Context, ownerID string) ([]postgres.GitHubInstallationConnection, error) {
	f.ownerID = ownerID
	return append([]postgres.GitHubInstallationConnection(nil), f.installations...), nil
}

func (f *fakeConnections) WithGitHubInstallationLease(ctx context.Context, ownerID string, installationID int64, operation func(context.Context) error) error {
	f.lease.RLock()
	defer f.lease.RUnlock()
	f.ownerID, f.installation = ownerID, installationID
	if !f.active {
		return fmt.Errorf("GitHub installation is disconnected: %w", core.ErrPrecondition)
	}
	return operation(ctx)
}

func (f *fakeConnections) DisconnectGitHubInstallation(_ context.Context, ownerID string, installationID int64, _ time.Time) error {
	if f.disconnectAttempted != nil {
		f.disconnectSignal.Do(func() { close(f.disconnectAttempted) })
	}
	f.lease.Lock()
	defer f.lease.Unlock()
	f.ownerID, f.installation = ownerID, installationID
	f.disconnects++
	f.active = false
	f.tokenMu.Lock()
	defer f.tokenMu.Unlock()
	for _, use := range f.tokenUses {
		if use.ExpiresAt.After(time.Now()) {
			return fmt.Errorf("GitHub disconnect awaits installation token expiry: %w", core.ErrConflict)
		}
	}
	return nil
}

func (f *fakeConnections) BeginGitHubInstallationTokenUse(_ context.Context, value githubapp.TokenUseMetadata) error {
	f.tokenMu.Lock()
	defer f.tokenMu.Unlock()
	if f.tokenUses == nil {
		f.tokenUses = make(map[string]githubapp.TokenUseMetadata)
	}
	f.tokenUses[value.ID] = value
	return nil
}

func (f *fakeConnections) SetGitHubInstallationTokenUseExpiry(_ context.Context, _ string, _ int64, useID string, expiresAt time.Time) error {
	f.tokenMu.Lock()
	defer f.tokenMu.Unlock()
	value, ok := f.tokenUses[useID]
	if !ok {
		return core.ErrNotFound
	}
	value.ExpiresAt = expiresAt
	f.tokenUses[useID] = value
	return nil
}

func (f *fakeConnections) RevokeGitHubInstallationTokenUse(_ context.Context, _ string, _ int64, useID string, _ time.Time) error {
	f.tokenMu.Lock()
	defer f.tokenMu.Unlock()
	delete(f.tokenUses, useID)
	return nil
}

func (f *fakeConnections) outstandingTokenUses() int {
	f.tokenMu.Lock()
	defer f.tokenMu.Unlock()
	count := 0
	for _, use := range f.tokenUses {
		if use.ExpiresAt.After(time.Now()) {
			count++
		}
	}
	return count
}

type lockedApplicationState struct {
	*fakeState
	mu sync.Mutex
}

func (s *lockedApplicationState) Audit(ctx context.Context, ownerID, deviceID, workspaceID, action, result, targetType, targetID string, details json.RawMessage, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fakeState.Audit(ctx, ownerID, deviceID, workspaceID, action, result, targetType, targetID, details, at)
}

func TestConnectionStatusSeparatesGitHubConfigurationFromOwnerConnectionAndCodexScope(t *testing.T) {
	now := time.Unix(1_784_166_400, 0).UTC()
	running := core.Workspace{ID: "ws-running", OwnerID: "owner", Name: "Running", ProviderResourceID: "provider-running", State: core.WorkspaceRunning}
	suspended := core.Workspace{ID: "ws-suspended", OwnerID: "owner", Name: "Suspended", ProviderResourceID: "provider-suspended", State: core.WorkspaceSuspended}
	connections := &fakeConnections{installations: []postgres.GitHubInstallationConnection{{
		InstallationID: 42, AccountLogin: "owner", AccountType: "User", RepositorySelection: "selected", UpdatedAt: now,
	}}}
	coderRuntime := &fakeCoder{runHelper: func(data []byte) ([]byte, error) {
		var request workspacehelper.Request
		if err := json.Unmarshal(data, &request); err != nil || request.Operation != workspacehelper.OpCodexAuthStatus {
			t.Fatalf("connection helper request = %#v, %v", request, err)
		}
		return json.Marshal(workspacehelper.Response{Version: workspacehelper.Version, OK: true, CodexAuthState: "connected"})
	}}
	application := &Application{
		config: Config{GitHubConfigured: true},
		deps: Dependencies{
			Connections: connections, WorkspaceStore: &fakeWorkspaceStore{values: []core.Workspace{suspended, running}},
			Coder: coderRuntime, Clock: fixedClock{now},
		},
	}
	status, err := application.GetConnections(context.Background(), httpapi.Principal{OwnerID: "owner", DeviceID: "device"})
	if err != nil {
		t.Fatal(err)
	}
	if connections.ownerID != "owner" || !status.GitHub.Configured || !status.GitHub.Connected || len(status.GitHub.Installations) != 1 {
		t.Fatalf("GitHub connection status = %#v, owner=%q", status.GitHub, connections.ownerID)
	}
	if status.Codex.Scope != "per_workspace" || status.Codex.ConnectedWorkspaceCount != 1 || status.Codex.UnavailableWorkspaceCount != 1 || len(status.Codex.Workspaces) != 2 {
		t.Fatalf("Codex connection status = %#v", status.Codex)
	}
}

func TestDisconnectGitHubIsOwnerScopedAndBlocksFutureTokenMinting(t *testing.T) {
	now := time.Unix(1_784_166_400, 0).UTC()
	connections := &fakeConnections{active: true}
	github := &fakeGitHub{token: "must-not-be-minted"}
	state := &fakeState{}
	application := &Application{
		config: Config{GitHubConfigured: true},
		deps:   Dependencies{Connections: connections, GitHub: github, State: state, Clock: fixedClock{now}},
	}
	principal := httpapi.Principal{OwnerID: "owner", DeviceID: "device"}
	if err := application.DisconnectGitHub(context.Background(), principal, 42); err != nil {
		t.Fatal(err)
	}
	if connections.ownerID != "owner" || connections.installation != 42 || connections.disconnects != 1 {
		t.Fatalf("disconnect scope = %#v", connections)
	}
	err := application.withInstallationToken(context.Background(), "owner", core.Repository{ID: "123", InstallationID: 42}, map[string]string{"contents": "read"}, func(context.Context, string) error {
		t.Fatal("disconnected installation invoked token consumer")
		return nil
	})
	if !errors.Is(err, core.ErrPrecondition) || github.installationID != 0 {
		t.Fatalf("token after disconnect = %v, GitHub calls=%d", err, github.installationID)
	}
	if len(state.audits) != 1 || state.audits[0].action != "github.connection.disconnect" {
		t.Fatalf("disconnect audit = %#v", state.audits)
	}
}

func TestDisconnectGitHubWaitsForInFlightTokenUseAndRefusesLaterMint(t *testing.T) {
	helperStarted := make(chan struct{})
	helperRelease := make(chan struct{})
	disconnectAttempted := make(chan struct{})
	connections := &fakeConnections{active: true, disconnectAttempted: disconnectAttempted}
	github := &fakeGitHub{token: "ephemeral-token"}
	state := &lockedApplicationState{fakeState: &fakeState{}}
	workspaceStore := &fakeWorkspaceStore{value: core.Workspace{
		ID: "workspace-1", OwnerID: "owner", State: core.WorkspaceRunning,
		ProviderResourceID: "provider-1",
		Repository:         core.Repository{ID: "123", InstallationID: 42, FullName: "owner/repository"},
	}}
	coderRuntime := &fakeCoder{runHelper: func(request []byte) ([]byte, error) {
		var decoded workspacehelper.Request
		if err := json.Unmarshal(request, &decoded); err != nil {
			return nil, err
		}
		if decoded.GitHubToken != "ephemeral-token" || decoded.Operation != workspacehelper.OpGitPush {
			return nil, errors.New("in-flight Git operation omitted its leased token")
		}
		close(helperStarted)
		<-helperRelease
		return json.Marshal(workspacehelper.Response{
			Version: workspacehelper.Version, OK: true,
			GitStatus: &gitops.Status{Branch: "branch"},
		})
	}}
	application := &Application{
		config: Config{GitHubConfigured: true},
		deps: Dependencies{
			Connections: connections, GitHub: github, State: state, WorkspaceStore: workspaceStore,
			Coder: coderRuntime, Clock: fixedClock{time.Unix(1_784_166_400, 0).UTC()},
		},
		mutationLocks: map[string]*mutationGate{},
	}
	principal := httpapi.Principal{OwnerID: "owner", DeviceID: "device"}
	pushDone := make(chan error, 1)
	go func() {
		_, err := application.PushWorkspace(context.Background(), principal, "workspace-1")
		pushDone <- err
	}()
	<-helperStarted
	disconnectDone := make(chan error, 1)
	go func() {
		disconnectDone <- application.DisconnectGitHub(context.Background(), principal, 42)
	}()
	<-disconnectAttempted
	select {
	case err := <-disconnectDone:
		t.Fatalf("disconnect returned before in-flight token use completed: %v", err)
	default:
	}
	close(helperRelease)
	if err := <-pushDone; err != nil {
		t.Fatal(err)
	}
	if err := <-disconnectDone; err != nil {
		t.Fatal(err)
	}
	if github.tokenCalls != 1 {
		t.Fatalf("in-flight operation minted %d tokens", github.tokenCalls)
	}
	if _, err := application.PushWorkspace(context.Background(), principal, "workspace-1"); !errors.Is(err, core.ErrPrecondition) {
		t.Fatalf("post-disconnect push = %v", err)
	}
	if github.tokenCalls != 1 {
		t.Fatal("post-disconnect push minted another installation token")
	}
}

type ambiguousRemoteHelperError struct {
	cause     error
	safeAfter time.Time
}

func (e ambiguousRemoteHelperError) Error() string {
	return "remote workspace helper exit is ambiguous"
}
func (e ambiguousRemoteHelperError) Unwrap() error { return e.cause }
func (e ambiguousRemoteHelperError) GitHubTokenUseSafeAfter() time.Time {
	return e.safeAfter
}

func TestEarlyCallerCancellationCannotReportDisconnectSuccessBeforeRemoteSafeAfter(t *testing.T) {
	helperStarted := make(chan struct{})
	safeAfter := time.Now().Add(500 * time.Millisecond).UTC()
	connections := &fakeConnections{active: true}
	github := &fakeGitHub{token: "ephemeral-token"}
	workspaceStore := &fakeWorkspaceStore{value: core.Workspace{
		ID: "workspace-1", OwnerID: "owner", State: core.WorkspaceRunning,
		ProviderResourceID: "provider-1",
		Repository:         core.Repository{ID: "123", InstallationID: 42, FullName: "owner/repository"},
	}}
	coderRuntime := &fakeCoder{runHelperContext: func(ctx context.Context, _ []byte) ([]byte, error) {
		close(helperStarted)
		<-ctx.Done()
		return nil, ambiguousRemoteHelperError{cause: ctx.Err(), safeAfter: safeAfter}
	}}
	application := &Application{
		config: Config{GitHubConfigured: true},
		deps: Dependencies{
			Connections: connections, GitHub: github, State: &lockedApplicationState{fakeState: &fakeState{}},
			WorkspaceStore: workspaceStore, Coder: coderRuntime, Clock: fixedClock{time.Now().UTC()},
		},
		mutationLocks: map[string]*mutationGate{},
	}
	principal := httpapi.Principal{OwnerID: "owner", DeviceID: "device"}
	pushCtx, cancelPush := context.WithCancel(context.Background())
	pushDone := make(chan error, 1)
	go func() {
		_, err := application.PushWorkspace(pushCtx, principal, "workspace-1")
		pushDone <- err
	}()
	<-helperStarted
	cancelPush()
	if err := <-pushDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("early-canceled push = %v", err)
	}
	if connections.outstandingTokenUses() != 1 {
		t.Fatal("early cancellation released durable installation-token authority")
	}

	err := application.DisconnectGitHub(context.Background(), principal, 42)
	if !errors.Is(err, core.ErrConflict) {
		t.Fatalf("disconnect before remote safe-after = %v", err)
	}
	if !time.Now().Before(safeAfter) {
		t.Fatal("test did not exercise disconnect before the remote safe-after deadline")
	}
	if connections.active {
		t.Fatal("conflicted disconnect did not durably disable future token minting")
	}
	if github.tokenCalls != 1 {
		t.Fatalf("canceled operation minted %d tokens", github.tokenCalls)
	}

	if wait := time.Until(safeAfter.Add(25 * time.Millisecond)); wait > 0 {
		timer := time.NewTimer(wait)
		<-timer.C
	}
	if err := application.DisconnectGitHub(context.Background(), principal, 42); err != nil {
		t.Fatalf("disconnect after remote safe-after: %v", err)
	}
}

func TestDisconnectCodexStopsOnlyCodexRuntimeAndRevokesWorkspaceCredentials(t *testing.T) {
	const tabID = "11111111-1111-4111-8111-111111111111"
	now := time.Unix(1_784_166_400, 0).UTC()
	workspace := core.Workspace{ID: "ws-one", OwnerID: "owner", Name: "One", ProviderResourceID: "provider-one", State: core.WorkspaceRunning}
	state := &fakeState{tab: postgres.TerminalTabRecord{ID: tabID, OwnerID: "owner", WorkspaceID: workspace.ID, Kind: "codex"}}
	terminals := &fakeTerminals{}
	coderRuntime := &fakeCoder{runHelper: func(data []byte) ([]byte, error) {
		var request workspacehelper.Request
		if err := json.Unmarshal(data, &request); err != nil {
			t.Fatal(err)
		}
		if request.Operation != workspacehelper.OpCodexAuthRevoke || !request.Confirmed || len(request.CodexTerminalTabIDs) != 1 || request.CodexTerminalTabIDs[0] != tabID {
			t.Fatalf("Codex revoke request = %#v", request)
		}
		return json.Marshal(workspacehelper.Response{Version: workspacehelper.Version, OK: true, CodexAuthState: "disconnected"})
	}}
	application := &Application{
		deps: Dependencies{
			WorkspaceStore: &fakeWorkspaceStore{value: workspace}, State: state, Coder: coderRuntime,
			Terminals: terminals, Clock: fixedClock{now},
		},
		running: map[string]bool{tabID: true}, mutationLocks: map[string]*mutationGate{},
	}
	err := application.DisconnectCodex(context.Background(), httpapi.Principal{OwnerID: "owner", DeviceID: "device"}, workspace.ID, httpapi.ConfirmConnectionDisconnectRequest{Confirmed: true})
	if err != nil {
		t.Fatal(err)
	}
	if terminals.unregisterCalls != 1 || application.running[tabID] {
		t.Fatalf("Codex runtime was not revoked: unregister=%d running=%v", terminals.unregisterCalls, application.running)
	}
	if len(state.audits) != 1 || state.audits[0].action != "codex.connection.disconnect" {
		t.Fatalf("Codex disconnect audit = %#v", state.audits)
	}
}

func TestDisconnectCodexRevokesCredentialsBeforeRuntimeCleanupFailure(t *testing.T) {
	const tabID = "11111111-1111-4111-8111-111111111111"
	now := time.Unix(1_784_166_400, 0).UTC()
	workspace := core.Workspace{ID: "ws-one", OwnerID: "owner", Name: "One", ProviderResourceID: "provider-one", State: core.WorkspaceRunning}
	state := &fakeState{tab: postgres.TerminalTabRecord{ID: tabID, OwnerID: "owner", WorkspaceID: workspace.ID, Kind: "codex"}}
	credentialsActive := true
	helperCalls := 0
	coderRuntime := &fakeCoder{runHelper: func(data []byte) ([]byte, error) {
		var request workspacehelper.Request
		if err := json.Unmarshal(data, &request); err != nil || request.Operation != workspacehelper.OpCodexAuthRevoke {
			t.Fatalf("Codex revoke request = %#v, %v", request, err)
		}
		helperCalls++
		credentialsActive = false
		return json.Marshal(workspacehelper.Response{Version: workspacehelper.Version, OK: true, CodexAuthState: "disconnected"})
	}}
	terminals := &fakeTerminals{unregisterHook: func(terminal.TabID, string) error {
		if credentialsActive {
			t.Fatal("terminal cleanup ran before credential revocation")
		}
		return errors.New("injected terminal cleanup failure")
	}}
	application := &Application{
		deps: Dependencies{
			WorkspaceStore: &fakeWorkspaceStore{value: workspace}, State: state, Coder: coderRuntime,
			Terminals: terminals, Clock: fixedClock{now},
		},
		running: map[string]bool{tabID: true}, mutationLocks: map[string]*mutationGate{},
	}

	err := application.DisconnectCodex(context.Background(), httpapi.Principal{OwnerID: "owner", DeviceID: "device"}, workspace.ID, httpapi.ConfirmConnectionDisconnectRequest{Confirmed: true})
	if !errors.Is(err, core.ErrExternal) {
		t.Fatalf("disconnect cleanup failure = %v", err)
	}
	if credentialsActive || helperCalls != 1 {
		t.Fatalf("credentials remained active after cleanup failure: active=%v helperCalls=%d", credentialsActive, helperCalls)
	}
	if terminals.unregisterCalls != 1 || application.running[tabID] {
		t.Fatalf("runtime cleanup was not attempted after revocation: unregister=%d running=%v", terminals.unregisterCalls, application.running)
	}
	if len(state.audits) != 1 || state.audits[0].action != "codex.connection.disconnect" {
		t.Fatalf("Codex disconnect audit = %#v", state.audits)
	}
}

func TestCodexDisconnectRejectsCrossOwnerAndSuspendedWorkspaceWithoutHelperCall(t *testing.T) {
	now := time.Unix(1_784_166_400, 0).UTC()
	workspace := core.Workspace{ID: "ws-one", OwnerID: "owner", Name: "One", ProviderResourceID: "provider-one", State: core.WorkspaceSuspended}
	coderRuntime := &fakeCoder{}
	application := &Application{
		deps: Dependencies{
			WorkspaceStore: &fakeWorkspaceStore{value: workspace}, State: &fakeState{}, Coder: coderRuntime,
			Terminals: &fakeTerminals{}, Clock: fixedClock{now},
		},
		mutationLocks: map[string]*mutationGate{},
	}
	request := httpapi.ConfirmConnectionDisconnectRequest{Confirmed: true}
	if err := application.DisconnectCodex(context.Background(), httpapi.Principal{OwnerID: "other", DeviceID: "device"}, workspace.ID, request); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("cross-owner disconnect = %v", err)
	}
	if err := application.DisconnectCodex(context.Background(), httpapi.Principal{OwnerID: "owner", DeviceID: "device"}, workspace.ID, request); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("suspended disconnect = %v", err)
	}
	if coderRuntime.helperRequest != nil {
		t.Fatal("rejected disconnect reached the workspace helper")
	}
}
