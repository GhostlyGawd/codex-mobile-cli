package application

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/httpapi"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/postgres"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/preview"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/session"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/terminal"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/workspacehelper"
	"github.com/coder/websocket"
)

type revocableSessions struct {
	mu                sync.Mutex
	principal         session.Principal
	refreshToken      string
	refreshUsed       bool
	familyRevoked     bool
	deviceRevoked     bool
	validateCalls     int
	revokeFamilyCalls int
	revokeDeviceCalls int
}

func (s *revocableSessions) Issue(context.Context, string, string) (session.Pair, error) {
	return session.Pair{}, errors.New("unexpected session issue")
}

func (s *revocableSessions) RefreshPrincipal(_ context.Context, token string) (session.Principal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if token == "" || token != s.refreshToken || s.deviceRevoked || s.familyRevoked {
		return session.Principal{}, errors.New("invalid refresh credential")
	}
	return s.principal, nil
}

func (s *revocableSessions) Rotate(_ context.Context, token string) (session.Pair, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if token != s.refreshToken || s.deviceRevoked || s.familyRevoked {
		return session.Pair{}, errors.New("invalid refresh credential")
	}
	if s.refreshUsed {
		s.familyRevoked = true
		return session.Pair{}, session.ErrReplay
	}
	s.refreshUsed = true
	return session.Pair{}, errors.New("unexpected successful rotation")
}

func (s *revocableSessions) RevokeFamily(_ context.Context, familyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if familyID != s.principal.FamilyID {
		return errors.New("unknown session family")
	}
	s.familyRevoked = true
	s.revokeFamilyCalls++
	return nil
}

func (s *revocableSessions) Authenticate(context.Context, string) (session.Principal, error) {
	return session.Principal{}, errors.New("unexpected session authentication")
}

func (s *revocableSessions) ValidatePrincipal(_ context.Context, principal session.Principal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.validateCalls++
	if principal != s.principal || s.familyRevoked || s.deviceRevoked {
		return errors.New("invalid session principal")
	}
	return nil
}

func (s *revocableSessions) ListDevices(context.Context, string) ([]session.Device, error) {
	return nil, errors.New("unexpected device list")
}

func (s *revocableSessions) RevokeDevice(_ context.Context, ownerID, deviceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ownerID != s.principal.OwnerID || deviceID != s.principal.DeviceID {
		return errors.New("unknown device")
	}
	s.deviceRevoked = true
	s.revokeDeviceCalls++
	return nil
}

type blockingTerminalManager struct {
	registerEntered chan struct{}
	registerRelease chan struct{}
	registerOnce    sync.Once
	issueEntered    chan struct{}
	issueRelease    chan struct{}
	issueOnce       sync.Once

	mu          sync.Mutex
	issueCalls  int
	revokeCalls int
	ticketLive  bool
	redactor    terminal.OutputRedactor
}

type blockingPreviewRandom struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	next    byte
}

type blockingNotificationState struct {
	*fakeState
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	mu      sync.Mutex
	calls   int
}

func (s *blockingNotificationState) RegisterNotification(context.Context, string, string, string, string, string, time.Time) error {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	s.once.Do(func() { close(s.entered) })
	<-s.release
	return nil
}

func (s *blockingNotificationState) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func newBlockingPreviewRandom() *blockingPreviewRandom {
	return &blockingPreviewRandom{entered: make(chan struct{}), release: make(chan struct{})}
}

func (r *blockingPreviewRandom) Read(value []byte) (int, error) {
	r.once.Do(func() { close(r.entered) })
	<-r.release
	for index := range value {
		r.next++
		value[index] = r.next
	}
	return len(value), nil
}

func newBlockingTerminalManager(blockRegistration, blockIssue bool) *blockingTerminalManager {
	manager := &blockingTerminalManager{
		registerEntered: make(chan struct{}),
		registerRelease: make(chan struct{}),
		issueEntered:    make(chan struct{}),
		issueRelease:    make(chan struct{}),
	}
	if !blockRegistration {
		close(manager.registerRelease)
	}
	if !blockIssue {
		close(manager.issueRelease)
	}
	return manager
}

func (m *blockingTerminalManager) Register(_ string, _ string, _ terminal.TabID, _ terminal.Runtime, redactor terminal.OutputRedactor, _ bool) error {
	m.mu.Lock()
	m.redactor = redactor
	m.mu.Unlock()
	m.registerOnce.Do(func() { close(m.registerEntered) })
	<-m.registerRelease
	return nil
}

func (m *blockingTerminalManager) Unregister(terminal.TabID, string) error { return nil }

func (m *blockingTerminalManager) Issue(string, string, string, terminal.TabID, uint64, string) (terminal.Connection, error) {
	m.issueOnce.Do(func() { close(m.issueEntered) })
	<-m.issueRelease
	m.mu.Lock()
	defer m.mu.Unlock()
	m.issueCalls++
	m.ticketLive = true
	return terminal.Connection{
		Ticket: "ticket", ReconnectToken: "reconnect", ProtocolVersion: terminal.Version, MaximumFrameBytes: terminal.MaxPayload,
	}, nil
}

func (m *blockingTerminalManager) RevokeDevice(string, string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revokeCalls++
	m.ticketLive = false
	return 1
}

func (m *blockingTerminalManager) counts() (int, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.issueCalls, m.revokeCalls
}

func (m *blockingTerminalManager) ticketIsLive() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ticketLive
}

func (m *blockingTerminalManager) closeRedactor() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.redactor != nil {
		m.redactor.Close()
		m.redactor = nil
	}
}

func TestTerminalRuntimeSetupInFlightIsSweptBeforeRevocationReturns(t *testing.T) {
	for _, test := range []struct {
		name   string
		revoke func(*Application, httpapi.Principal) error
	}{
		{
			name: "current session",
			revoke: func(application *Application, principal httpapi.Principal) error {
				return application.RevokeCurrentSession(context.Background(), principal)
			},
		},
		{
			name: "device",
			revoke: func(application *Application, principal httpapi.Principal) error {
				caller := httpapi.Principal{OwnerID: principal.OwnerID, DeviceID: "other-device", FamilyID: "other-family"}
				return application.RevokeDevice(context.Background(), caller, principal.DeviceID)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			principal := httpapi.Principal{OwnerID: "owner", DeviceID: "device", FamilyID: "family"}
			sessions := &revocableSessions{principal: session.Principal{
				OwnerID: principal.OwnerID, DeviceID: principal.DeviceID, FamilyID: principal.FamilyID,
			}}
			terminals := newBlockingTerminalManager(true, false)
			application, workspaceID, tabID := terminalRevocationApplication(t, sessions, terminals)
			defer terminals.closeRedactor()

			issued := make(chan error, 1)
			go func() {
				_, err := application.CreateTerminalConnection(
					context.Background(), principal, workspaceID, tabID, httpapi.TerminalConnectRequest{},
				)
				issued <- err
			}()
			<-terminals.registerEntered

			revoked := make(chan error, 1)
			go func() { revoked <- test.revoke(application, principal) }()
			waitForTerminalAdmissionRefs(t, application, principal.OwnerID, principal.DeviceID, 2)
			if sessions.revokeFamilyCalls != 0 || sessions.revokeDeviceCalls != 0 {
				t.Fatal("durable revocation crossed runtime setup already holding the device gate")
			}
			close(terminals.registerRelease)
			if err := <-issued; err != nil {
				t.Fatalf("runtime setup ordered before revocation failed: %v", err)
			}
			if err := <-revoked; err != nil {
				t.Fatal(err)
			}
			if terminals.ticketIsLive() {
				t.Fatal("ticket minted after runtime setup survived revocation")
			}
			issueCalls, revokeCalls := terminals.counts()
			if issueCalls != 1 || revokeCalls != 1 {
				t.Fatalf("terminal ordering mismatch: issue=%d revoke=%d", issueCalls, revokeCalls)
			}
			waitForTerminalAdmissionRefs(t, application, principal.OwnerID, principal.DeviceID, 0)
		})
	}
}

func TestPreviewIssueInFlightIsSweptBeforeSessionRevocationReturns(t *testing.T) {
	principal := httpapi.Principal{OwnerID: "owner", DeviceID: "device", FamilyID: "family"}
	sessions := &revocableSessions{principal: session.Principal{
		OwnerID: principal.OwnerID, DeviceID: principal.DeviceID, FamilyID: principal.FamilyID,
	}}
	terminals := newBlockingTerminalManager(false, false)
	random := newBlockingPreviewRandom()
	tokens, err := preview.NewTokenManagerWithDependencies(
		[]byte("0123456789abcdef0123456789abcdef"), random, func() time.Time { return time.Unix(100, 0) },
	)
	if err != nil {
		t.Fatal(err)
	}
	const (
		workspaceID = "ws-preview-revocation"
		providerID  = "33333333-3333-4333-8333-333333333333"
		routeID     = "pv-preview-revocation"
	)
	state := &fakeState{route: postgres.PreviewRouteRecord{
		ID: routeID, OwnerID: principal.OwnerID, WorkspaceID: workspaceID, Port: 3000,
		WorkspaceHost: providerID, CreatedAt: time.Unix(90, 0),
	}}
	application := &Application{
		config: Config{
			PreviewsConfigured: true, PreviewDomain: "preview.example.test", PreviewAccessTTL: 5 * time.Minute,
		},
		deps: Dependencies{
			Sessions: sessions, Terminals: terminals, PreviewTokens: tokens, State: state,
			WorkspaceStore: &fakeWorkspaceStore{value: core.Workspace{
				ID: workspaceID, OwnerID: principal.OwnerID, State: core.WorkspaceRunning, ProviderResourceID: providerID,
			}},
			Clock: fixedClock{time.Unix(100, 0)},
		},
	}
	type previewResult struct {
		access httpapi.PreviewAccess
		err    error
	}
	issued := make(chan previewResult, 1)
	go func() {
		access, err := application.CreatePreviewAccess(
			context.Background(), principal, workspaceID, httpapi.PreviewAccessRequest{PreviewID: routeID},
		)
		issued <- previewResult{access: access, err: err}
	}()
	<-random.entered

	revoked := make(chan error, 1)
	go func() { revoked <- application.RevokeCurrentSession(context.Background(), principal) }()
	waitForTerminalAdmissionRefs(t, application, principal.OwnerID, principal.DeviceID, 2)
	if sessions.revokeFamilyCalls != 0 {
		t.Fatal("durable revocation crossed preview issuance already holding the device gate")
	}
	close(random.release)
	result := <-issued
	if result.err != nil {
		t.Fatalf("preview issuance ordered before revocation failed: %v", result.err)
	}
	if err := <-revoked; err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(result.access.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := tokens.Validate(parsed.Fragment, routeID, principal.OwnerID, workspaceID, 3000); err == nil {
		t.Fatal("preview grant minted by the overlapping request survived revocation")
	}
	if _, err := application.CreatePreviewAccess(
		context.Background(), principal, workspaceID, httpapi.PreviewAccessRequest{PreviewID: routeID},
	); !errors.Is(err, core.ErrUnauthorized) {
		t.Fatalf("revoked principal preview issuance error = %v", err)
	}
	waitForTerminalAdmissionRefs(t, application, principal.OwnerID, principal.DeviceID, 0)
}

func TestPushRegistrationInFlightIsOrderedBeforeDeviceRevocation(t *testing.T) {
	principal := httpapi.Principal{OwnerID: "owner", DeviceID: "device", FamilyID: "family"}
	sessions := &revocableSessions{principal: session.Principal{
		OwnerID: principal.OwnerID, DeviceID: principal.DeviceID, FamilyID: principal.FamilyID,
	}}
	state := &blockingNotificationState{
		fakeState: &fakeState{}, entered: make(chan struct{}), release: make(chan struct{}),
	}
	application := &Application{
		config: Config{APNSConfigured: true, APNSTopic: "com.example.CodexMobile"},
		deps: Dependencies{
			Sessions: sessions, Terminals: newBlockingTerminalManager(false, false), State: state,
			Clock: fixedClock{time.Unix(100, 0)},
		},
	}
	registered := make(chan error, 1)
	go func() {
		registered <- application.RegisterPushDevice(context.Background(), principal, httpapi.PushDeviceRegistration{
			Token: strings.Repeat("ab", 32), Environment: httpapi.PushProduction,
		})
	}()
	<-state.entered

	revoked := make(chan error, 1)
	go func() {
		revoked <- application.RevokeDevice(
			context.Background(), httpapi.Principal{OwnerID: principal.OwnerID, DeviceID: "other", FamilyID: "other"},
			principal.DeviceID,
		)
	}()
	waitForTerminalAdmissionRefs(t, application, principal.OwnerID, principal.DeviceID, 2)
	if sessions.revokeDeviceCalls != 0 {
		t.Fatal("device revocation crossed an APNs registration already holding the device gate")
	}
	close(state.release)
	if err := <-registered; err != nil {
		t.Fatal(err)
	}
	if err := <-revoked; err != nil {
		t.Fatal(err)
	}
	if err := application.RegisterPushDevice(context.Background(), principal, httpapi.PushDeviceRegistration{
		Token: strings.Repeat("cd", 32), Environment: httpapi.PushProduction,
	}); !errors.Is(err, core.ErrUnauthorized) {
		t.Fatalf("revoked device APNs registration error = %v", err)
	}
	if calls := state.callCount(); calls != 1 {
		t.Fatalf("revoked device reached APNs persistence %d times", calls)
	}
	waitForTerminalAdmissionRefs(t, application, principal.OwnerID, principal.DeviceID, 0)
}

func TestTerminalRuntimeSetupTimeoutCannotBlockRevocation(t *testing.T) {
	principal := httpapi.Principal{OwnerID: "owner", DeviceID: "device", FamilyID: "family"}
	sessions := &revocableSessions{principal: session.Principal{
		OwnerID: principal.OwnerID, DeviceID: principal.DeviceID, FamilyID: principal.FamilyID,
	}}
	terminals := newBlockingTerminalManager(false, false)
	application, workspaceID, tabID := terminalRevocationApplication(t, sessions, terminals)
	application.terminalSetupLimit = 200 * time.Millisecond
	helperEntered := make(chan struct{})
	helperOnce := sync.Once{}
	application.deps.Coder.(*fakeCoder).runHelperContext = func(ctx context.Context, _ []byte) ([]byte, error) {
		helperOnce.Do(func() { close(helperEntered) })
		<-ctx.Done()
		return nil, ctx.Err()
	}

	issued := make(chan error, 1)
	go func() {
		_, err := application.CreateTerminalConnection(
			context.Background(), principal, workspaceID, tabID, httpapi.TerminalConnectRequest{},
		)
		issued <- err
	}()
	<-helperEntered

	revoked := make(chan error, 1)
	go func() { revoked <- application.RevokeCurrentSession(context.Background(), principal) }()
	waitForTerminalAdmissionRefs(t, application, principal.OwnerID, principal.DeviceID, 2)

	select {
	case err := <-issued:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("terminal setup timeout error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("bounded terminal setup did not cancel a hung helper")
	}
	select {
	case err := <-revoked:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("session revocation remained blocked after terminal setup timeout")
	}
	select {
	case <-terminals.registerEntered:
		t.Fatal("timed-out terminal setup registered a persistent runtime")
	default:
	}
	issueCalls, revokeCalls := terminals.counts()
	if issueCalls != 0 || revokeCalls != 1 {
		t.Fatalf("timeout/revocation ordering mismatch: issue=%d revoke=%d", issueCalls, revokeCalls)
	}
	waitForTerminalAdmissionRefs(t, application, principal.OwnerID, principal.DeviceID, 0)
}

func TestRevokedPrincipalCannotStartPersistentTerminalRuntime(t *testing.T) {
	for _, test := range []struct {
		name   string
		revoke func(*Application, httpapi.Principal) error
	}{
		{
			name: "current session",
			revoke: func(application *Application, principal httpapi.Principal) error {
				return application.RevokeCurrentSession(context.Background(), principal)
			},
		},
		{
			name: "device",
			revoke: func(application *Application, principal httpapi.Principal) error {
				caller := httpapi.Principal{OwnerID: principal.OwnerID, DeviceID: "other-device", FamilyID: "other-family"}
				return application.RevokeDevice(context.Background(), caller, principal.DeviceID)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			principal := httpapi.Principal{OwnerID: "owner", DeviceID: "device", FamilyID: "family"}
			sessions := &revocableSessions{principal: session.Principal{
				OwnerID: principal.OwnerID, DeviceID: principal.DeviceID, FamilyID: principal.FamilyID,
			}}
			terminals := newBlockingTerminalManager(false, false)
			application, workspaceID, tabID := terminalRevocationApplication(t, sessions, terminals)
			defer terminals.closeRedactor()

			if err := test.revoke(application, principal); err != nil {
				t.Fatal(err)
			}
			if _, err := application.CreateTerminalConnection(
				context.Background(), principal, workspaceID, tabID, httpapi.TerminalConnectRequest{},
			); !errors.Is(err, core.ErrUnauthorized) {
				t.Fatalf("revoked terminal request error = %v", err)
			}
			select {
			case <-terminals.registerEntered:
				t.Fatal("revoked request registered a persistent terminal runtime")
			default:
			}
			issueCalls, revokeCalls := terminals.counts()
			if issueCalls != 0 || revokeCalls != 1 {
				t.Fatalf("post-revocation ordering mismatch: issue=%d revoke=%d", issueCalls, revokeCalls)
			}
			waitForTerminalAdmissionRefs(t, application, principal.OwnerID, principal.DeviceID, 0)
		})
	}
}

func TestTerminalIssueInFlightIsSweptBeforeRevocationReturns(t *testing.T) {
	for _, test := range []struct {
		name   string
		revoke func(*Application, httpapi.Principal) error
	}{
		{
			name: "current session",
			revoke: func(application *Application, principal httpapi.Principal) error {
				return application.RevokeCurrentSession(context.Background(), principal)
			},
		},
		{
			name: "device",
			revoke: func(application *Application, principal httpapi.Principal) error {
				caller := httpapi.Principal{OwnerID: principal.OwnerID, DeviceID: "other-device", FamilyID: "other-family"}
				return application.RevokeDevice(context.Background(), caller, principal.DeviceID)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			principal := httpapi.Principal{OwnerID: "owner", DeviceID: "device", FamilyID: "family"}
			sessions := &revocableSessions{principal: session.Principal{
				OwnerID: principal.OwnerID, DeviceID: principal.DeviceID, FamilyID: principal.FamilyID,
			}}
			terminals := newBlockingTerminalManager(false, true)
			application, workspaceID, tabID := terminalRevocationApplication(t, sessions, terminals)
			defer terminals.closeRedactor()

			issued := make(chan error, 1)
			go func() {
				_, err := application.CreateTerminalConnection(
					context.Background(), principal, workspaceID, tabID, httpapi.TerminalConnectRequest{},
				)
				issued <- err
			}()
			<-terminals.issueEntered

			revoked := make(chan error, 1)
			go func() { revoked <- test.revoke(application, principal) }()
			waitForTerminalAdmissionRefs(t, application, principal.OwnerID, principal.DeviceID, 2)
			if sessions.revokeFamilyCalls != 0 || sessions.revokeDeviceCalls != 0 {
				t.Fatal("durable revocation crossed an issuance already holding the device gate")
			}

			close(terminals.issueRelease)
			if err := <-issued; err != nil {
				t.Fatalf("issuance ordered before revocation failed: %v", err)
			}
			if err := <-revoked; err != nil {
				t.Fatal(err)
			}
			if terminals.ticketIsLive() {
				t.Fatal("ticket minted by the overlapping request survived revocation")
			}
			issueCalls, revokeCalls := terminals.counts()
			if issueCalls != 1 || revokeCalls != 1 {
				t.Fatalf("terminal ordering mismatch: issue=%d revoke=%d", issueCalls, revokeCalls)
			}
			waitForTerminalAdmissionRefs(t, application, principal.OwnerID, principal.DeviceID, 0)
		})
	}
}

func TestTerminalIssuanceWithActiveSession(t *testing.T) {
	principal := httpapi.Principal{OwnerID: "owner", DeviceID: "device", FamilyID: "family"}
	sessions := &revocableSessions{principal: session.Principal{
		OwnerID: principal.OwnerID, DeviceID: principal.DeviceID, FamilyID: principal.FamilyID,
	}}
	terminals := newBlockingTerminalManager(false, false)
	application, workspaceID, tabID := terminalRevocationApplication(t, sessions, terminals)
	defer terminals.closeRedactor()

	descriptor, err := application.CreateTerminalConnection(
		context.Background(), principal, workspaceID, tabID, httpapi.TerminalConnectRequest{},
	)
	if err != nil || descriptor.ConnectionTicket != "ticket" {
		t.Fatalf("ordinary terminal issuance = %#v, %v", descriptor, err)
	}
	issueCalls, revokeCalls := terminals.counts()
	if issueCalls != 1 || revokeCalls != 0 || sessions.validateCalls != 1 {
		t.Fatalf("ordinary terminal ordering mismatch: issue=%d revoke=%d validate=%d", issueCalls, revokeCalls, sessions.validateCalls)
	}
	waitForTerminalAdmissionRefs(t, application, principal.OwnerID, principal.DeviceID, 0)
}

func TestTerminalAdmissionGateIndexIsBounded(t *testing.T) {
	application := &Application{}
	for index := 0; index < 2_000; index++ {
		release := application.acquireTerminalAdmission("owner", fmt.Sprintf("hostile-device-%d", index))
		release()
	}
	application.mutationMu.Lock()
	defer application.mutationMu.Unlock()
	if len(application.terminalLocks) != 0 {
		t.Fatalf("released terminal admission gates retained %d hostile keys", len(application.terminalLocks))
	}
}

func TestRefreshReplayRevokesTicketsAndActiveWebSocket(t *testing.T) {
	principal := session.Principal{OwnerID: "owner", DeviceID: "device", FamilyID: "family"}
	sessions := &revocableSessions{principal: principal, refreshToken: "refresh-secret", refreshUsed: true}
	manager, err := terminal.NewManager([]byte("0123456789abcdef0123456789abcdef"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	tabID, err := terminal.ParseTabID("52e782d5-6e80-4944-a42f-a21201900c74")
	if err != nil {
		t.Fatal(err)
	}
	runtime := newFakeRuntime()
	redactor, err := terminal.NewOutputRedactor()
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Register(principal.OwnerID, "workspace", tabID, runtime, redactor, false); err != nil {
		t.Fatal(err)
	}
	active, err := manager.Issue(principal.OwnerID, principal.DeviceID, "workspace", tabID, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	unused, err := manager.Issue(principal.OwnerID, principal.DeviceID, "workspace", tabID, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := terminal.NewGateway(manager, "https://api.example.test")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gateway)
	defer server.Close()
	websocketURL := "ws" + strings.TrimPrefix(server.URL, "http")
	options := &websocket.DialOptions{
		Subprotocols: []string{terminal.Subprotocol},
		HTTPHeader:   http.Header{"Authorization": {"Bearer " + active.Ticket}},
	}
	socket, _, err := websocket.Dial(context.Background(), websocketURL, options)
	if err != nil {
		t.Fatal(err)
	}
	defer socket.CloseNow()

	application := &Application{deps: Dependencies{
		Sessions: sessions, Terminals: manager, State: &fakeState{}, Clock: fixedClock{time.Unix(100, 0)},
	}}
	if _, err := application.RefreshSession(context.Background(), httpapi.RefreshSessionRequest{RefreshToken: "refresh-secret"}); !errors.Is(err, session.ErrReplay) {
		t.Fatalf("refresh replay result = %v", err)
	}
	readContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, _, err := socket.Read(readContext); err == nil {
		t.Fatal("refresh replay left the active terminal WebSocket usable")
	}
	unusedOptions := &websocket.DialOptions{
		Subprotocols: []string{terminal.Subprotocol},
		HTTPHeader:   http.Header{"Authorization": {"Bearer " + unused.Ticket}},
	}
	if retry, _, err := websocket.Dial(context.Background(), websocketURL, unusedOptions); err == nil {
		retry.CloseNow()
		t.Fatal("refresh replay left an unused terminal ticket redeemable")
	}
}

func terminalRevocationApplication(t *testing.T, sessions SessionService, terminals TerminalManager) (*Application, string, string) {
	t.Helper()
	const (
		workspaceID = "ws-revocation"
		tabID       = "11111111-1111-4111-8111-111111111111"
	)
	state := &fakeState{
		tab: postgres.TerminalTabRecord{
			ID: tabID, OwnerID: "owner", WorkspaceID: workspaceID, Title: "Shell", Kind: "shell",
			CoderReconnectID: "22222222-2222-4222-8222-222222222222", CreatedAt: time.Unix(100, 0),
		},
		grantedSecrets: map[string][]byte{},
	}
	helpResponse, err := json.Marshal(workspacehelper.Response{Version: workspacehelper.Version, OK: true})
	if err != nil {
		t.Fatal(err)
	}
	coderRuntime := &fakeCoder{
		agentID: "agent-1", runtime: newFakeRuntime(),
		runHelper: func([]byte) ([]byte, error) { return append([]byte(nil), helpResponse...), nil },
	}
	application := &Application{
		config: Config{
			TerminalWebSocketURL: "wss://api.example.test/v1/terminal",
			InitialTerminalSize:  terminal.Size{Rows: 24, Columns: 80},
		},
		deps: Dependencies{
			Sessions: sessions,
			WorkspaceStore: &fakeWorkspaceStore{value: core.Workspace{
				ID: workspaceID, OwnerID: "owner", State: core.WorkspaceRunning,
				ProviderResourceID: "33333333-3333-4333-8333-333333333333", Repository: core.Repository{ID: "repo-1"},
			}},
			State: state, Coder: coderRuntime, Terminals: terminals, Clock: fixedClock{time.Unix(100, 0)},
		},
		running: make(map[string]bool), starting: make(map[string]chan struct{}),
	}
	return application, workspaceID, tabID
}

func waitForTerminalAdmissionRefs(t *testing.T, application *Application, ownerID, deviceID string, want int) {
	t.Helper()
	key := fmt.Sprintf("%d:%s:%s", len(ownerID), ownerID, deviceID)
	deadline := time.Now().Add(2 * time.Second)
	for {
		application.mutationMu.Lock()
		refs := 0
		if gate := application.terminalLocks[key]; gate != nil {
			refs = gate.refs
		}
		application.mutationMu.Unlock()
		if refs == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("terminal admission refs = %d, want %d", refs, want)
		}
		runtime.Gosched()
	}
}
