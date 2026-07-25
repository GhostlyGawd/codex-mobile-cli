package application

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/coder"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/httpapi"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/postgres"
	secretmodel "github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/secrets"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/session"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/terminal"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/workspacehelper"
)

type serializedSecretState struct {
	*fakeState

	mu               sync.Mutex
	workspaceID      string
	mutationEntered  chan struct{}
	continueMutation chan struct{}
	terminalLookup   chan struct{}
	lookupOnce       sync.Once
}

func (s *serializedSecretState) ListSecretWorkspaceIDs(context.Context, string, string) ([]string, error) {
	return []string{s.workspaceID}, nil
}

func (s *serializedSecretState) UpdateSecret(_ context.Context, ownerID, secretID string, plaintext []byte, now time.Time) (secretmodel.Metadata, error) {
	close(s.mutationEntered)
	<-s.continueMutation
	s.mu.Lock()
	s.grantedSecrets = map[string][]byte{"DEPLOY_TOKEN": bytes.Clone(plaintext)}
	s.mu.Unlock()
	return secretmodel.Metadata{
		ID: secretID, OwnerID: ownerID, Name: "DEPLOY_TOKEN", ValueBytes: len(plaintext), CreatedAt: now, UpdatedAt: now,
	}, nil
}

func (s *serializedSecretState) DeleteSecret(context.Context, string, string, time.Time) error {
	close(s.mutationEntered)
	<-s.continueMutation
	s.mu.Lock()
	for name, value := range s.grantedSecrets {
		secretmodel.Wipe(value)
		delete(s.grantedSecrets, name)
	}
	s.mu.Unlock()
	return nil
}

func (s *serializedSecretState) LoadGrantedWorkspaceSecrets(context.Context, string, string) (map[string][]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.grantLoads++
	return cloneSecretValues(s.grantedSecrets), nil
}

func (s *serializedSecretState) GetTerminalTab(context.Context, string, string, string) (postgres.TerminalTabRecord, error) {
	s.lookupOnce.Do(func() { close(s.terminalLookup) })
	return s.tab, nil
}

type launchOrderCoder struct {
	*fakeCoder

	mu               sync.Mutex
	helperSecretSets []map[string][]byte
	openAfterHelpers int
}

type orderedSecretState struct {
	*fakeState
	workspaceIDs []string
}

func (s *orderedSecretState) ListSecretWorkspaceIDs(context.Context, string, string) ([]string, error) {
	return append([]string(nil), s.workspaceIDs...), nil
}

type orderedWorkspaceStore struct {
	*fakeWorkspaceStore
	values map[string]core.Workspace
}

func (s *orderedWorkspaceStore) Get(_ context.Context, ownerID, workspaceID string) (core.Workspace, error) {
	value, ok := s.values[workspaceID]
	if !ok || value.OwnerID != ownerID {
		return core.Workspace{}, core.ErrNotFound
	}
	return value, nil
}

type workspaceOrderCoder struct {
	*fakeCoder
	providerIDs []string
}

type grantSerializationState struct {
	*fakeState

	mu              sync.Mutex
	listEntered     chan struct{}
	continueList    chan struct{}
	grantEntered    chan struct{}
	updateCommitted bool
}

func (s *grantSerializationState) ListSecretWorkspaceIDs(context.Context, string, string) ([]string, error) {
	close(s.listEntered)
	<-s.continueList
	return nil, nil
}

func (s *grantSerializationState) UpdateSecret(_ context.Context, ownerID, secretID string, plaintext []byte, now time.Time) (secretmodel.Metadata, error) {
	s.mu.Lock()
	s.updateCommitted = true
	s.grantedSecrets = map[string][]byte{"TOKEN": bytes.Clone(plaintext)}
	s.mu.Unlock()
	return secretmodel.Metadata{
		ID: secretID, OwnerID: ownerID, Name: "TOKEN", ValueBytes: len(plaintext), CreatedAt: now, UpdatedAt: now,
	}, nil
}

func (s *grantSerializationState) GrantWorkspaceSecret(context.Context, string, string, string, time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.updateCommitted {
		return errors.New("grant crossed an in-progress secret rotation")
	}
	close(s.grantEntered)
	return nil
}

func (s *grantSerializationState) LoadGrantedWorkspaceSecrets(context.Context, string, string) (map[string][]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneSecretValues(s.grantedSecrets), nil
}

func (c *workspaceOrderCoder) RunHelper(_ context.Context, providerID string, raw []byte) ([]byte, error) {
	var request workspacehelper.Request
	if err := json.Unmarshal(raw, &request); err != nil || request.Operation != workspacehelper.OpRuntimeSecretsSync {
		return nil, errors.New("unexpected runtime secret sync request")
	}
	c.providerIDs = append(c.providerIDs, providerID)
	return json.Marshal(workspacehelper.Response{Version: workspacehelper.Version, OK: true})
}

func (c *launchOrderCoder) RunHelper(_ context.Context, _ string, raw []byte) ([]byte, error) {
	var request workspacehelper.Request
	if err := json.Unmarshal(raw, &request); err != nil {
		return nil, err
	}
	if request.Operation != workspacehelper.OpRuntimeSecretsSync {
		return nil, errors.New("unexpected helper operation")
	}
	c.mu.Lock()
	c.helperSecretSets = append(c.helperSecretSets, cloneSecretValues(request.GrantedSecrets))
	c.mu.Unlock()
	return json.Marshal(workspacehelper.Response{Version: workspacehelper.Version, OK: true})
}

func (c *launchOrderCoder) OpenPTY(config coder.PTYConfig) (terminal.Runtime, error) {
	c.mu.Lock()
	c.openAfterHelpers = len(c.helperSecretSets)
	c.mu.Unlock()
	return c.fakeCoder.OpenPTY(config)
}

func TestSecretMutationSynchronizesRuntimeBeforeConcurrentTerminalLaunch(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name          string
		expectedValue string
		mutate        func(*Application, httpapi.Principal) error
	}{
		{
			name:          "update",
			expectedValue: "rotated-runtime-value",
			mutate: func(application *Application, principal httpapi.Principal) error {
				_, err := application.UpdateSecret(context.Background(), principal, "secret-1", httpapi.UpdateSecretRequest{Value: httpapi.SecretValue("rotated-runtime-value")})
				return err
			},
		},
		{
			name: "delete",
			mutate: func(application *Application, principal httpapi.Principal) error {
				return application.DeleteSecret(context.Background(), principal, "secret-1")
			},
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			const (
				workspaceID = "ws-live"
				tabID       = "11111111-1111-4111-8111-111111111111"
			)
			state := &serializedSecretState{
				fakeState: &fakeState{
					tab: postgres.TerminalTabRecord{
						ID: tabID, OwnerID: "owner", WorkspaceID: workspaceID, Title: "Shell", Kind: "shell",
						CoderReconnectID: "22222222-2222-4222-8222-222222222222", CreatedAt: time.Unix(100, 0),
					},
					grantedSecrets: map[string][]byte{"DEPLOY_TOKEN": []byte("old-runtime-value")},
				},
				workspaceID:      workspaceID,
				mutationEntered:  make(chan struct{}),
				continueMutation: make(chan struct{}),
				terminalLookup:   make(chan struct{}),
			}
			coderRuntime := &launchOrderCoder{fakeCoder: &fakeCoder{agentID: "agent-1", runtime: newFakeRuntime()}}
			terminals := &fakeTerminals{}
			principal := httpapi.Principal{OwnerID: "owner", DeviceID: "device", FamilyID: "family"}
			sessions := &revocableSessions{principal: session.Principal{
				OwnerID: principal.OwnerID, DeviceID: principal.DeviceID, FamilyID: principal.FamilyID,
			}}
			application := &Application{
				config: Config{
					TerminalWebSocketURL: "wss://api.example.test/v1/terminal",
					InitialTerminalSize:  terminal.Size{Rows: 24, Columns: 80},
				},
				deps: Dependencies{
					WorkspaceStore: &fakeWorkspaceStore{value: core.Workspace{
						ID: workspaceID, OwnerID: "owner", State: core.WorkspaceRunning,
						ProviderResourceID: "33333333-3333-4333-8333-333333333333", Repository: core.Repository{ID: "repo-1"},
					}},
					Sessions: sessions, State: state, Coder: coderRuntime, Terminals: terminals, Clock: fixedClock{time.Unix(100, 0)},
				},
				running: make(map[string]bool), starting: make(map[string]chan struct{}),
			}
			mutationResult := make(chan error, 1)
			go func() { mutationResult <- test.mutate(application, principal) }()
			<-state.mutationEntered

			terminalStarted := make(chan struct{})
			terminalResult := make(chan error, 1)
			go func() {
				close(terminalStarted)
				_, err := application.CreateTerminalConnection(
					context.Background(), principal, workspaceID, tabID, httpapi.TerminalConnectRequest{},
				)
				terminalResult <- err
			}()
			<-terminalStarted
			select {
			case <-state.terminalLookup:
				t.Fatal("terminal launch crossed the workspace lock before the secret mutation and runtime sync")
			case <-time.After(100 * time.Millisecond):
			}

			close(state.continueMutation)
			if err := <-mutationResult; err != nil {
				t.Fatalf("secret mutation failed: %v", err)
			}
			if err := <-terminalResult; err != nil {
				t.Fatalf("terminal launch failed: %v", err)
			}

			coderRuntime.mu.Lock()
			helperSets := coderRuntime.helperSecretSets
			openAfterHelpers := coderRuntime.openAfterHelpers
			coderRuntime.mu.Unlock()
			if len(helperSets) != 2 || openAfterHelpers != 2 {
				t.Fatalf("runtime sync ordering: helper calls=%d, OpenPTY after=%d", len(helperSets), openAfterHelpers)
			}
			for index, values := range helperSets {
				if got := string(values["DEPLOY_TOKEN"]); got != test.expectedValue || len(values) != boolToInt(test.expectedValue != "") {
					t.Fatalf("helper sync %d used a stale/inconsistent grant set: %#v", index, values)
				}
				for _, value := range values {
					secretmodel.Wipe(value)
				}
			}
			if test.expectedValue != "" {
				redacted := append(terminals.redactor.Process([]byte(test.expectedValue)), terminals.redactor.Flush()...)
				terminals.redactor.Close()
				if string(redacted) != "[REDACTED]" {
					t.Fatalf("new terminal redactor did not match synchronized plaintext: %q", redacted)
				}
			}
		})
	}
}

func TestSecretMutationLocksAndSynchronizesWorkspacesInDeterministicOrder(t *testing.T) {
	t.Parallel()
	state := &orderedSecretState{
		fakeState:    &fakeState{grantedSecrets: map[string][]byte{"TOKEN": []byte("rotated-value")}},
		workspaceIDs: []string{"ws-z", "ws-a", "ws-z"},
	}
	workspaceStore := &orderedWorkspaceStore{
		fakeWorkspaceStore: &fakeWorkspaceStore{},
		values: map[string]core.Workspace{
			"ws-a": {
				ID: "ws-a", OwnerID: "owner", State: core.WorkspaceRunning,
				ProviderResourceID: "provider-a",
			},
			"ws-z": {
				ID: "ws-z", OwnerID: "owner", State: core.WorkspaceRunning,
				ProviderResourceID: "provider-z",
			},
		},
	}
	coderRuntime := &workspaceOrderCoder{fakeCoder: &fakeCoder{}}
	application := &Application{deps: Dependencies{
		WorkspaceStore: workspaceStore, State: state, Coder: coderRuntime, Clock: fixedClock{time.Unix(100, 0)},
	}}
	_, err := application.UpdateSecret(
		context.Background(), httpapi.Principal{OwnerID: "owner", DeviceID: "device"}, "secret-1",
		httpapi.UpdateSecretRequest{Value: httpapi.SecretValue("rotated-value")},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(coderRuntime.providerIDs) != 2 || coderRuntime.providerIDs[0] != "provider-a" || coderRuntime.providerIDs[1] != "provider-z" {
		t.Fatalf("workspace synchronization order = %#v", coderRuntime.providerIDs)
	}
}

func TestSecretRotationSerializesConcurrentGrantDiscovery(t *testing.T) {
	t.Parallel()
	state := &grantSerializationState{
		fakeState:    &fakeState{},
		listEntered:  make(chan struct{}),
		continueList: make(chan struct{}),
		grantEntered: make(chan struct{}),
	}
	coderRuntime := &fakeCoder{runHelper: func(raw []byte) ([]byte, error) {
		var request workspacehelper.Request
		if err := json.Unmarshal(raw, &request); err != nil || string(request.GrantedSecrets["TOKEN"]) != "rotated-value" {
			return nil, errors.New("grant runtime sync did not use the rotated value")
		}
		return json.Marshal(workspacehelper.Response{Version: workspacehelper.Version, OK: true})
	}}
	application := &Application{deps: Dependencies{
		WorkspaceStore: &fakeWorkspaceStore{value: core.Workspace{
			ID: "ws-live", OwnerID: "owner", State: core.WorkspaceRunning, ProviderResourceID: "provider-live",
		}},
		State: state, Coder: coderRuntime, Clock: fixedClock{time.Unix(100, 0)},
	}}
	principal := httpapi.Principal{OwnerID: "owner", DeviceID: "device"}
	updateResult := make(chan error, 1)
	go func() {
		_, err := application.UpdateSecret(
			context.Background(), principal, "secret-1", httpapi.UpdateSecretRequest{Value: httpapi.SecretValue("rotated-value")},
		)
		updateResult <- err
	}()
	<-state.listEntered

	grantStarted := make(chan struct{})
	grantResult := make(chan error, 1)
	go func() {
		close(grantStarted)
		grantResult <- application.GrantWorkspaceSecret(context.Background(), principal, "ws-live", "secret-1")
	}()
	<-grantStarted
	select {
	case <-state.grantEntered:
		t.Fatal("grant crossed secret discovery before the rotation committed")
	case <-time.After(100 * time.Millisecond):
	}

	close(state.continueList)
	if err := <-updateResult; err != nil {
		t.Fatalf("secret rotation failed: %v", err)
	}
	if err := <-grantResult; err != nil {
		t.Fatalf("serialized grant failed: %v", err)
	}
	select {
	case <-state.grantEntered:
	default:
		t.Fatal("grant did not proceed after secret rotation released its lock")
	}
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
