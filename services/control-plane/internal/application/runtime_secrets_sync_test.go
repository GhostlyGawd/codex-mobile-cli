package application

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/httpapi"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/postgres"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/session"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/terminal"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/workspacehelper"
)

type runtimeSecretAudit struct {
	action  string
	result  string
	details json.RawMessage
}

type runtimeSecretState struct {
	*fakeState
	grantValues  map[string][]byte
	workspaceIDs []string
	grantCalls   int
	revokeCalls  int
	audits       []runtimeSecretAudit
}

func (s *runtimeSecretState) ListSecretWorkspaceIDs(context.Context, string, string) ([]string, error) {
	return append([]string(nil), s.workspaceIDs...), nil
}

func (s *runtimeSecretState) GrantWorkspaceSecret(context.Context, string, string, string, time.Time) error {
	s.grantCalls++
	s.grantedSecrets = cloneSecretValues(s.grantValues)
	return nil
}

func (s *runtimeSecretState) RevokeWorkspaceSecret(context.Context, string, string, string, time.Time) error {
	s.revokeCalls++
	for name, value := range s.grantedSecrets {
		for index := range value {
			value[index] = 0
		}
		delete(s.grantedSecrets, name)
	}
	return nil
}

func (s *runtimeSecretState) Audit(_ context.Context, _, _, _ string, action, result, _, _ string, details json.RawMessage, _ time.Time) error {
	s.audits = append(s.audits, runtimeSecretAudit{
		action: action, result: result, details: append(json.RawMessage(nil), details...),
	})
	return nil
}

func cloneSecretValues(values map[string][]byte) map[string][]byte {
	cloned := make(map[string][]byte, len(values))
	for name, value := range values {
		cloned[name] = bytes.Clone(value)
	}
	return cloned
}

func TestLiveSecretGrantAndRevokeSynchronizeAuthoritativeRuntimeState(t *testing.T) {
	t.Parallel()
	const workspaceID = "ws-live"
	state := &runtimeSecretState{
		fakeState:   &fakeState{},
		grantValues: map[string][]byte{"DEPLOY_TOKEN": []byte("current-runtime-value")},
	}
	workspaceStore := &fakeWorkspaceStore{value: core.Workspace{
		ID: workspaceID, OwnerID: "owner", State: core.WorkspaceRunning,
		ProviderResourceID: "11111111-1111-4111-8111-111111111111",
	}}
	coderRuntime := &fakeCoder{}
	helperCalls := 0
	coderRuntime.runHelper = func(raw []byte) ([]byte, error) {
		helperCalls++
		var request workspacehelper.Request
		if err := json.Unmarshal(raw, &request); err != nil {
			return nil, err
		}
		if request.Operation != workspacehelper.OpRuntimeSecretsSync {
			t.Fatalf("unexpected helper operation: %#v", request)
		}
		switch helperCalls {
		case 1:
			if len(request.GrantedSecrets) != 1 || string(request.GrantedSecrets["DEPLOY_TOKEN"]) != "current-runtime-value" {
				t.Fatalf("grant sync omitted the authoritative value: %#v", request.GrantedSecrets)
			}
		case 2:
			if len(request.GrantedSecrets) != 0 {
				t.Fatalf("revoke sync retained stale grants: %#v", request.GrantedSecrets)
			}
		default:
			t.Fatalf("unexpected helper sync count %d", helperCalls)
		}
		return json.Marshal(workspacehelper.Response{Version: workspacehelper.Version, OK: true})
	}
	application := &Application{deps: Dependencies{
		WorkspaceStore: workspaceStore, State: state, Coder: coderRuntime,
		Clock: fixedClock{time.Unix(100, 0)},
	}}
	principal := httpapi.Principal{OwnerID: "owner", DeviceID: "device"}

	if err := application.GrantWorkspaceSecret(context.Background(), principal, workspaceID, "secret-1"); err != nil {
		t.Fatal(err)
	}
	if err := application.RevokeWorkspaceSecret(context.Background(), principal, workspaceID, "secret-1"); err != nil {
		t.Fatal(err)
	}
	if state.grantCalls != 1 || state.revokeCalls != 1 || state.grantLoads != 2 || helperCalls != 2 {
		t.Fatalf("grant synchronization counts: grant=%d revoke=%d loads=%d helper=%d", state.grantCalls, state.revokeCalls, state.grantLoads, helperCalls)
	}
	if len(state.audits) != 2 || state.audits[0].action != "secret.grant" || state.audits[0].result != "success" ||
		state.audits[1].action != "secret.revoke" || state.audits[1].result != "success" {
		t.Fatalf("unexpected grant synchronization audits: %#v", state.audits)
	}
	for _, audit := range state.audits {
		if !bytes.Contains(audit.details, []byte(`"runtime_sync":"applied"`)) || bytes.Contains(audit.details, []byte("current-runtime-value")) {
			t.Fatalf("runtime synchronization audit was inaccurate or sensitive: %s", audit.details)
		}
	}

	if err := application.GrantWorkspaceSecret(context.Background(), httpapi.Principal{OwnerID: "other", DeviceID: "device"}, workspaceID, "secret-1"); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("cross-owner grant was not hidden: %v", err)
	}
	if state.grantCalls != 1 || helperCalls != 2 {
		t.Fatalf("cross-owner grant reached state/helper: grant=%d helper=%d", state.grantCalls, helperCalls)
	}
}

func TestLiveSecretGrantReportsCommittedStateWhenRuntimeSyncFails(t *testing.T) {
	t.Parallel()
	state := &runtimeSecretState{
		fakeState:   &fakeState{},
		grantValues: map[string][]byte{"DEPLOY_TOKEN": []byte("must-not-leak")},
	}
	coderRuntime := &fakeCoder{runHelper: func([]byte) ([]byte, error) {
		return nil, errors.New("workspace transport unavailable")
	}}
	application := &Application{deps: Dependencies{
		WorkspaceStore: &fakeWorkspaceStore{value: core.Workspace{
			ID: "ws-live", OwnerID: "owner", State: core.WorkspaceRunning,
			ProviderResourceID: "11111111-1111-4111-8111-111111111111",
		}},
		State: state, Coder: coderRuntime, Clock: fixedClock{time.Unix(100, 0)},
	}}
	err := application.GrantWorkspaceSecret(
		context.Background(), httpapi.Principal{OwnerID: "owner", DeviceID: "device"}, "ws-live", "secret-1",
	)
	if !errors.Is(err, core.ErrExternal) || state.grantCalls != 1 || state.grantLoads != 1 {
		t.Fatalf("failed live sync did not expose its partial failure: err=%v grant=%d loads=%d", err, state.grantCalls, state.grantLoads)
	}
	if len(state.audits) != 1 || state.audits[0].result != "failed" ||
		!bytes.Contains(state.audits[0].details, []byte(`"database_mutation":"committed"`)) ||
		!bytes.Contains(state.audits[0].details, []byte(`"runtime_sync":"failed"`)) ||
		bytes.Contains(state.audits[0].details, []byte("must-not-leak")) {
		t.Fatalf("partial grant failure audit was inaccurate or sensitive: %#v", state.audits)
	}
	for _, value := range coderRuntime.helperRequest {
		if value != 0 {
			t.Fatal("failed helper request retained serialized secret material")
		}
	}
}

func TestTerminalLaunchFailsClosedWhenRuntimeSecretSyncFails(t *testing.T) {
	t.Parallel()
	const (
		workspaceID = "ws-live"
		tabID       = "11111111-1111-4111-8111-111111111111"
	)
	state := &fakeState{
		tab: postgres.TerminalTabRecord{
			ID: tabID, OwnerID: "owner", WorkspaceID: workspaceID, Title: "Shell", Kind: "shell",
			CoderReconnectID: "22222222-2222-4222-8222-222222222222", CreatedAt: time.Unix(100, 0),
		},
		grantedSecrets: map[string][]byte{"DEPLOY_TOKEN": []byte("current-runtime-value")},
	}
	coderRuntime := &fakeCoder{
		agentID: "agent-1", runtime: newFakeRuntime(),
		runHelper: func([]byte) ([]byte, error) { return nil, errors.New("runtime sync rejected") },
	}
	terminals := &fakeTerminals{}
	sessions := &revocableSessions{principal: session.Principal{OwnerID: "owner", DeviceID: "device"}}
	application := &Application{
		config: Config{TerminalWebSocketURL: "wss://api.example.test/v1/terminal", InitialTerminalSize: terminal.Size{Rows: 24, Columns: 80}},
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
	_, err := application.CreateTerminalConnection(
		context.Background(), httpapi.Principal{OwnerID: "owner", DeviceID: "device"}, workspaceID, tabID, httpapi.TerminalConnectRequest{},
	)
	if !errors.Is(err, core.ErrExternal) {
		t.Fatalf("terminal launch did not surface authoritative sync failure: %v", err)
	}
	if coderRuntime.openCalls != 0 || terminals.registerCalls != 0 || terminals.issueCalls != 0 || application.running[tabID] {
		t.Fatalf("terminal launched with unsynchronized grants: open=%d register=%d issue=%d running=%v", coderRuntime.openCalls, terminals.registerCalls, terminals.issueCalls, application.running[tabID])
	}
	if state.grantLoads != 1 {
		t.Fatalf("terminal launch loaded authoritative grants %d times", state.grantLoads)
	}
}

func TestSecretMutationReportsCommittedStateWhenRuntimeSyncFails(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		action string
		mutate func(*Application, httpapi.Principal) error
	}{
		{
			name: "update", action: "secret.update",
			mutate: func(application *Application, principal httpapi.Principal) error {
				_, err := application.UpdateSecret(context.Background(), principal, "secret-1", httpapi.UpdateSecretRequest{Value: httpapi.SecretValue("rotated-must-not-audit")})
				return err
			},
		},
		{
			name: "delete", action: "secret.delete",
			mutate: func(application *Application, principal httpapi.Principal) error {
				return application.DeleteSecret(context.Background(), principal, "secret-1")
			},
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			state := &runtimeSecretState{
				fakeState:    &fakeState{grantedSecrets: map[string][]byte{"DEPLOY_TOKEN": []byte("must-not-audit")}},
				workspaceIDs: []string{"ws-live"},
			}
			application := &Application{deps: Dependencies{
				WorkspaceStore: &fakeWorkspaceStore{value: core.Workspace{
					ID: "ws-live", OwnerID: "owner", State: core.WorkspaceRunning,
					ProviderResourceID: "11111111-1111-4111-8111-111111111111",
				}},
				State: state,
				Coder: &fakeCoder{runHelper: func([]byte) ([]byte, error) {
					return nil, errors.New("workspace transport unavailable")
				}},
				Clock: fixedClock{time.Unix(100, 0)},
			}}
			err := test.mutate(application, httpapi.Principal{OwnerID: "owner", DeviceID: "device"})
			if !errors.Is(err, core.ErrExternal) || state.grantLoads != 1 {
				t.Fatalf("failed live sync did not expose committed state: err=%v loads=%d", err, state.grantLoads)
			}
			if len(state.audits) != 1 || state.audits[0].action != test.action || state.audits[0].result != "failed" ||
				!bytes.Contains(state.audits[0].details, []byte(`"database_mutation":"committed"`)) ||
				!bytes.Contains(state.audits[0].details, []byte(`"workspace_sync_failed":1`)) ||
				bytes.Contains(state.audits[0].details, []byte("must-not-audit")) ||
				bytes.Contains(state.audits[0].details, []byte("rotated-must-not-audit")) {
				t.Fatalf("partial mutation audit was inaccurate or sensitive: %#v", state.audits)
			}
		})
	}
}
