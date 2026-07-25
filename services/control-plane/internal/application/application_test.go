package application

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/attachments"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/checkpoint"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/coder"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/githubapp"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/gitops"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/httpapi"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/maintenance"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/passkeys"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/postgres"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/preview"
	secretmodel "github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/secrets"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/session"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/terminal"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/workspacehelper"
	"github.com/go-webauthn/webauthn/protocol"
)

func TestAuthenticatorMapsPrincipalAndHidesFailure(t *testing.T) {
	t.Parallel()
	authenticator, err := NewAuthenticator(fakeSessionAuthenticator{principal: session.Principal{OwnerID: "owner", DeviceID: "device", FamilyID: "family"}})
	if err != nil {
		t.Fatal(err)
	}
	principal, err := authenticator.Authenticate(context.Background(), "access")
	if err != nil {
		t.Fatal(err)
	}
	if principal != (httpapi.Principal{OwnerID: "owner", DeviceID: "device", FamilyID: "family"}) {
		t.Fatalf("unexpected principal: %#v", principal)
	}

	failed, err := NewAuthenticator(fakeSessionAuthenticator{err: errors.New("database detail")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := failed.Authenticate(context.Background(), "access"); !errors.Is(err, core.ErrUnauthorized) {
		t.Fatalf("expected unauthorized marker, got %v", err)
	}
}

func TestPasskeyChallengeAndCredentialBoundary(t *testing.T) {
	t.Parallel()
	challenge := protocol.URLEncodedBase64([]byte("challenge"))
	userID := protocol.URLEncodedBase64([]byte("user"))
	credentialID := protocol.URLEncodedBase64([]byte("credential"))
	result, err := registrationChallenge(passkeys.RegistrationStart{
		CeremonyID: "ceremony",
		Options: &protocol.CredentialCreation{Response: protocol.PublicKeyCredentialCreationOptions{
			Challenge:             challenge,
			RelyingParty:          protocol.RelyingPartyEntity{ID: "example.test"},
			User:                  protocol.UserEntity{ID: userID, DisplayName: "Owner", CredentialEntity: protocol.CredentialEntity{Name: "owner"}},
			CredentialExcludeList: []protocol.CredentialDescriptor{{CredentialID: credentialID}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Challenge != challenge.String() || result.UserID != userID.String() || result.ExcludedCredentialIDs[0] != credentialID.String() {
		t.Fatalf("unexpected challenge mapping: %#v", result)
	}

	encodedID := base64.RawURLEncoding.EncodeToString([]byte("credential"))
	encodedData := base64.RawURLEncoding.EncodeToString([]byte("data"))
	data, err := registrationCredentialJSON(httpapi.PasskeyRegistrationCredential{
		CredentialID:      encodedID,
		RawID:             encodedID,
		ClientDataJSON:    encodedData,
		AttestationObject: encodedData,
	})
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	if document["type"] != "public-key" {
		t.Fatalf("unexpected WebAuthn credential: %s", data)
	}
	if _, err := registrationCredentialJSON(httpapi.PasskeyRegistrationCredential{
		CredentialID:      encodedID,
		RawID:             base64.RawURLEncoding.EncodeToString([]byte("other")),
		ClientDataJSON:    encodedData,
		AttestationObject: encodedData,
	}); err == nil {
		t.Fatal("expected mismatched credential IDs to be rejected")
	}
	oversizedID := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 1025))
	if _, err := registrationCredentialJSON(httpapi.PasskeyRegistrationCredential{
		CredentialID: oversizedID, RawID: oversizedID,
		ClientDataJSON: encodedData, AttestationObject: encodedData,
	}); err == nil {
		t.Fatal("oversized passkey credential ID was accepted")
	}
}

func TestAuthenticatedPasskeyManagementUsesPrincipalAndReturnsMetadataOnly(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 16, 16, 0, 0, 0, time.UTC)
	service := &fakePasskeyService{metadata: []passkeys.CredentialMetadata{{
		CredentialID: []byte("credential"), DeviceID: "internal-device", DeviceName: "iPhone",
		CreatedAt: now,
	}}}
	state := &fakeState{}
	application := &Application{deps: Dependencies{Passkeys: service, State: state, Clock: fixedClock{now}}}
	principal := httpapi.Principal{OwnerID: "owner", DeviceID: "device", FamilyID: "family"}
	instanceID := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	challenge := protocol.URLEncodedBase64([]byte("challenge"))
	userID := protocol.URLEncodedBase64([]byte("user"))
	service.start = passkeys.RegistrationStart{
		CeremonyID: "ceremony",
		Options: &protocol.CredentialCreation{Response: protocol.PublicKeyCredentialCreationOptions{
			Challenge: challenge, RelyingParty: protocol.RelyingPartyEntity{ID: "api.codex.test"},
			User: protocol.UserEntity{ID: userID, DisplayName: "Owner", CredentialEntity: protocol.CredentialEntity{Name: "owner"}},
		}},
	}
	if _, err := application.BeginAdditionalPasskeyRegistration(context.Background(), principal, httpapi.DeviceIdentityRequest{
		DeviceInstanceID: instanceID, DeviceName: "iPhone",
	}); err != nil {
		t.Fatal(err)
	}
	if service.ownerID != principal.OwnerID || service.deviceID != principal.DeviceID || service.device.InstanceID != instanceID {
		t.Fatalf("registration was not principal/device bound: %#v", service)
	}
	values, err := application.ListPasskeys(context.Background(), principal)
	if err != nil || len(values) != 1 || values[0].ID != base64.RawURLEncoding.EncodeToString([]byte("credential")) || values[0].DeviceName != "iPhone" {
		t.Fatalf("unexpected passkey metadata: %#v %v", values, err)
	}
	encoded, err := json.Marshal(values[0])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("internal-device")) || bytes.Contains(encoded, []byte("public_key")) {
		t.Fatalf("internal passkey material leaked: %s", encoded)
	}
	if err := application.RevokePasskey(context.Background(), principal, values[0].ID); err != nil {
		t.Fatal(err)
	}
	if service.revokedOwner != principal.OwnerID || service.revokedID != values[0].ID || len(state.audits) != 1 || state.audits[0].action != "passkey.revoke" {
		t.Fatalf("passkey revoke/audit mismatch: %#v %#v", service, state.audits)
	}
}

func TestDiagnosticsAreBoundedMetadataOnly(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 16, 18, 0, 0, 0, time.UTC)
	state := &fakeState{}
	application := &Application{
		config: Config{
			GitHubConfigured: true, APNSConfigured: true, PreviewsConfigured: true,
			MaximumRunningWorkspaces: 10,
		},
		deps: Dependencies{
			Health: fakeHealth{}, Clock: fixedClock{now}, State: state,
			WorkspaceStore: &fakeWorkspaceStore{values: []core.Workspace{
				{ID: "ws-running", OwnerID: "owner", Name: "sensitive-repository-name", State: core.WorkspaceRunning},
				{ID: "ws-queued", OwnerID: "owner", WorktreePath: "/sensitive/path", State: core.WorkspaceQueued},
				{ID: "ws-failed", OwnerID: "owner", FailureCode: "private command output", State: core.WorkspaceFailed},
			}},
		},
	}
	report, err := application.GetDiagnostics(context.Background(), httpapi.Principal{OwnerID: "owner", DeviceID: "device"})
	if err != nil {
		t.Fatal(err)
	}
	if !report.MetadataOnly || report.IncludesSensitiveData || report.WorkspaceTotal != 3 ||
		report.WorkspaceRunning != 1 || report.WorkspaceQueued != 1 || report.WorkspaceFailed != 1 {
		t.Fatalf("unexpected diagnostics report: %#v", report)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"sensitive-repository-name", "/sensitive/path", "private command output", "prompt", "terminal_output", "credential"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("diagnostics leaked %q: %s", forbidden, encoded)
		}
	}
	if len(state.audits) != 1 || state.audits[0].action != "diagnostics.view" {
		t.Fatalf("diagnostics access was not audited: %#v", state.audits)
	}
}

func TestMaintenanceActionsAreOwnerAndStateBound(t *testing.T) {
	t.Parallel()
	service := &fakeMaintenanceService{run: maintenance.Run{
		ID: "maint_0123456789abcdef01234567", OwnerID: "owner", State: maintenance.StateReadyForUpdate,
	}}
	application := &Application{deps: Dependencies{Maintenance: service, State: &fakeState{}, Clock: fixedClock{time.Unix(100, 0)}}}
	principal := httpapi.Principal{OwnerID: "owner", DeviceID: "device"}
	value, err := application.AdvanceMaintenance(context.Background(), principal, service.run.ID, httpapi.MaintenanceActionRequest{Action: "begin_update"})
	if err != nil || value.State != string(maintenance.StateUpdating) || service.beginUpdateCalls != 1 {
		t.Fatalf("unexpected maintenance transition: %#v calls=%d err=%v", value, service.beginUpdateCalls, err)
	}
	if _, err := application.AdvanceMaintenance(context.Background(), principal, "maint_ffffffffffffffffffffffff", httpapi.MaintenanceActionRequest{Action: "begin_update"}); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("mismatched run ID should be hidden as not found, got %v", err)
	}
	if _, err := application.AdvanceMaintenance(context.Background(), principal, "maintenance-looks-plausible", httpapi.MaintenanceActionRequest{Action: "begin_update"}); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("out-of-contract maintenance ID should be invalid, got %v", err)
	}
	if _, err := application.AdvanceMaintenance(context.Background(), httpapi.Principal{OwnerID: "other"}, service.run.ID, httpapi.MaintenanceActionRequest{Action: "begin_update"}); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("cross-owner run should be hidden as not found, got %v", err)
	}
}

func TestTerminalRuntimeIsRegisteredLazilyOnce(t *testing.T) {
	t.Parallel()
	workspaceID := "ws_test"
	providerID := "11111111-1111-4111-8111-111111111111"
	tabID, err := terminal.NewTabID()
	if err != nil {
		t.Fatal(err)
	}
	reconnectID, err := terminal.NewTabID()
	if err != nil {
		t.Fatal(err)
	}
	state := &fakeState{tab: postgres.TerminalTabRecord{
		ID: tabID.String(), OwnerID: "owner", WorkspaceID: workspaceID, Title: "Codex",
		Kind: "codex", CoderReconnectID: reconnectID.String(), CreatedAt: time.Now(),
	}, initialPrompt: "start with the failing test", grantedSecrets: map[string][]byte{"DEPLOY_TOKEN": []byte("current-runtime-value")}}
	workspaceStore := &fakeWorkspaceStore{value: core.Workspace{
		ID: workspaceID, OwnerID: "owner", State: core.WorkspaceRunning,
		ProviderResourceID: providerID, Repository: core.Repository{ID: "repo-1"},
	}}
	runtime := newFakeRuntime()
	coderRuntime := &fakeCoder{runtime: runtime, agentID: "agent-1"}
	coderRuntime.runHelper = func(raw []byte) ([]byte, error) {
		var request workspacehelper.Request
		if err := json.Unmarshal(raw, &request); err != nil {
			t.Fatal(err)
		}
		switch request.Operation {
		case workspacehelper.OpCodexThreadLookup:
			if request.TerminalTabID != tabID.String() {
				t.Fatalf("thread lookup was not scoped to the terminal tab: %#v", request)
			}
			return json.Marshal(workspacehelper.Response{Version: workspacehelper.Version, OK: true, CodexThreadID: "33333333-3333-4333-8333-333333333333"})
		case workspacehelper.OpRuntimeSecretsSync:
			if string(request.GrantedSecrets["DEPLOY_TOKEN"]) != "current-runtime-value" {
				t.Fatalf("terminal launch omitted authoritative runtime grants: %#v", request)
			}
			return json.Marshal(workspacehelper.Response{Version: workspacehelper.Version, OK: true})
		default:
			t.Fatalf("unexpected terminal helper operation: %#v", request)
			return nil, nil
		}
	}
	terminals := &fakeTerminals{}
	principal := httpapi.Principal{OwnerID: "owner", DeviceID: "device", FamilyID: "family"}
	sessions := &revocableSessions{principal: session.Principal{
		OwnerID: principal.OwnerID, DeviceID: principal.DeviceID, FamilyID: principal.FamilyID,
	}}
	application := &Application{
		config:  Config{TerminalWebSocketURL: "wss://api.example.test/v1/terminal", InitialTerminalSize: terminal.Size{Rows: 24, Columns: 80}},
		deps:    Dependencies{Sessions: sessions, WorkspaceStore: workspaceStore, State: state, Coder: coderRuntime, Terminals: terminals, Clock: fixedClock{time.Unix(100, 0)}},
		running: make(map[string]bool), starting: make(map[string]chan struct{}),
	}
	for index := 0; index < 2; index++ {
		descriptor, err := application.CreateTerminalConnection(context.Background(), principal, workspaceID, tabID.String(), httpapi.TerminalConnectRequest{})
		if err != nil {
			t.Fatal(err)
		}
		if descriptor.WebSocketURL != application.config.TerminalWebSocketURL || descriptor.ConnectionTicket == "" {
			t.Fatalf("unexpected descriptor: %#v", descriptor)
		}
	}
	if coderRuntime.openCalls != 1 || terminals.registerCalls != 1 || terminals.issueCalls != 2 || state.grantLoads != 2 {
		t.Fatalf("lazy registration counts: open=%d register=%d issue=%d grant_syncs=%d", coderRuntime.openCalls, terminals.registerCalls, terminals.issueCalls, state.grantLoads)
	}
	if coderRuntime.config.InitialPrompt != "start with the failing test" || coderRuntime.config.InitialPromptDelivered == nil {
		t.Fatalf("initial prompt was not passed through the encrypted one-shot boundary: %#v", coderRuntime.config)
	}
	if coderRuntime.config.CodexTabID != tabID.String() || coderRuntime.config.CodexThreadID != "33333333-3333-4333-8333-333333333333" || state.tab.CodexThreadID != coderRuntime.config.CodexThreadID {
		t.Fatalf("Codex tab/thread mapping was not persisted and launched exactly: state=%#v config=%#v", state.tab, coderRuntime.config)
	}
	redacted := append(terminals.redactor.Process([]byte("current-runtime-")), terminals.redactor.Process([]byte("value visible"))...)
	redacted = append(redacted, terminals.redactor.Flush()...)
	terminals.redactor.Close()
	if got := string(redacted); got != "[REDACTED] visible" {
		t.Fatalf("terminal registration did not receive the active-grant redactor: %q", got)
	}
	coderRuntime.config.InitialPromptDelivered()
	if !state.promptDelivered {
		t.Fatal("initial prompt delivery was not recorded")
	}
	terminals.issueErr = terminal.ErrTerminalCapacity
	if _, err := application.CreateTerminalConnection(context.Background(), principal, workspaceID, tabID.String(), httpapi.TerminalConnectRequest{}); !errors.Is(err, core.ErrCapacity) || errors.Is(err, core.ErrUnauthorized) {
		t.Fatalf("terminal admission capacity was not preserved for HTTP mapping: %v", err)
	}
	terminals.issueErr = errors.New("invalid terminal reconnect token")
	if _, err := application.CreateTerminalConnection(context.Background(), principal, workspaceID, tabID.String(), httpapi.TerminalConnectRequest{}); !errors.Is(err, core.ErrUnauthorized) || errors.Is(err, core.ErrCapacity) {
		t.Fatalf("invalid reconnect was not kept unauthorized: %v", err)
	}
	terminals.issueErr = nil
	terminals.registerErr = terminal.ErrTerminalCapacity
	secondTabID, err := terminal.NewTabID()
	if err != nil {
		t.Fatal(err)
	}
	state.tab.ID = secondTabID.String()
	state.tab.Kind = "shell"
	state.tab.CodexThreadID = ""
	if _, err := application.CreateTerminalConnection(context.Background(), principal, workspaceID, secondTabID.String(), httpapi.TerminalConnectRequest{}); !errors.Is(err, core.ErrCapacity) || errors.Is(err, core.ErrExternal) {
		t.Fatalf("registered terminal capacity was not preserved for HTTP mapping: %v", err)
	}
}

func TestTerminalTabMutationsAreScopedSanitizedAndAudited(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 16, 19, 0, 0, 0, time.UTC)
	workspaceID := "ws-test"
	tabID := "11111111-1111-4111-8111-111111111111"
	state := &fakeState{tab: postgres.TerminalTabRecord{
		ID: tabID, OwnerID: "owner", WorkspaceID: workspaceID, Title: "Shell",
		Kind: "shell", CoderReconnectID: "22222222-2222-4222-8222-222222222222", CreatedAt: now,
	}}
	workspaces := &fakeWorkspaceStore{value: core.Workspace{ID: workspaceID, OwnerID: "owner", State: core.WorkspaceRunning}}
	terminals := &fakeTerminals{}
	application := &Application{
		deps:    Dependencies{WorkspaceStore: workspaces, State: state, Terminals: terminals, Clock: fixedClock{now}},
		running: map[string]bool{tabID: true}, starting: make(map[string]chan struct{}), mutationLocks: make(map[string]*mutationGate),
	}
	principal := httpapi.Principal{OwnerID: "owner", DeviceID: "device"}

	renamed, err := application.RenameTerminalTab(context.Background(), principal, workspaceID, tabID, httpapi.RenameTerminalTabRequest{Title: "  Build logs  "})
	if err != nil || renamed.Title != "Build logs" || !renamed.IsRunning {
		t.Fatalf("terminal rename mismatch: %#v %v", renamed, err)
	}
	if bytes.Contains(state.audits[0].details, []byte("Build logs")) || !bytes.Contains(state.audits[0].details, []byte(`"title_characters":10`)) {
		t.Fatalf("terminal title leaked into audit metadata: %s", state.audits[0].details)
	}

	reordered, err := application.ReorderTerminalTabs(context.Background(), principal, workspaceID, httpapi.ReorderTerminalTabsRequest{TabIDs: []string{tabID}})
	if err != nil || len(reordered) != 1 || reordered[0].ID != tabID || reordered[0].Order != 0 {
		t.Fatalf("terminal reorder mismatch: %#v %v", reordered, err)
	}
	if err := application.CloseTerminalTab(context.Background(), principal, workspaceID, tabID, httpapi.CloseTerminalTabRequest{}); !errors.Is(err, core.ErrInvalid) || terminals.unregisterCalls != 0 {
		t.Fatalf("unconfirmed close reached the runtime: calls=%d err=%v", terminals.unregisterCalls, err)
	}
	if _, err := application.RenameTerminalTab(context.Background(), httpapi.Principal{OwnerID: "other", DeviceID: "device"}, workspaceID, tabID, httpapi.RenameTerminalTabRequest{Title: "Hidden"}); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("cross-owner rename was not hidden: %v", err)
	}
	if err := application.CloseTerminalTab(context.Background(), principal, workspaceID, tabID, httpapi.CloseTerminalTabRequest{Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	if terminals.unregisterCalls != 1 || state.tab.ClosedAt == nil || application.running[tabID] {
		t.Fatalf("terminal runtime was not closed safely: calls=%d tab=%#v running=%v", terminals.unregisterCalls, state.tab, application.running[tabID])
	}
	if actions := []string{state.audits[0].action, state.audits[1].action, state.audits[2].action}; !slices.Equal(actions, []string{"terminal_tab.rename", "terminal_tab.reorder", "terminal_tab.close"}) {
		t.Fatalf("terminal audit actions mismatch: %#v", actions)
	}
}

func TestTerminalTabMutationValidation(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"", "bad\nname", "spoof\u202eexe", strings.Repeat("x", 121)} {
		if _, err := canonicalTerminalTitle(value); !errors.Is(err, core.ErrInvalid) {
			t.Fatalf("unsafe terminal title %q was accepted: %v", value, err)
		}
	}
	validID := "11111111-1111-4111-8111-111111111111"
	if err := validateTerminalTabOrder([]string{validID, validID}); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("duplicate terminal order was accepted: %v", err)
	}
	if err := validateTerminalTabOrder([]string{"not-a-uuid"}); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("invalid terminal identity was accepted: %v", err)
	}
}

func TestStageTerminalAttachmentsUsesOwnerBoundTabAndScrubsBytes(t *testing.T) {
	t.Parallel()
	workspaceID := "ws_test"
	tabID := "11111111-1111-4111-8111-111111111111"
	state := &fakeState{tab: postgres.TerminalTabRecord{ID: tabID, OwnerID: "owner", WorkspaceID: workspaceID}}
	workspaceStore := &fakeWorkspaceStore{value: core.Workspace{
		ID: workspaceID, OwnerID: "owner", State: core.WorkspaceRunning,
		ProviderResourceID: "22222222-2222-4222-8222-222222222222",
	}}
	coderRuntime := &fakeCoder{}
	var helperUpload attachments.Upload
	coderRuntime.runHelper = func(request []byte) ([]byte, error) {
		var decoded workspacehelper.Request
		if err := json.Unmarshal(request, &decoded); err != nil {
			return nil, err
		}
		if decoded.Operation != workspacehelper.OpAttachmentStage || len(decoded.Attachments) != 1 {
			t.Fatalf("unexpected helper request: %#v", decoded)
		}
		helperUpload = decoded.Attachments[0]
		return json.Marshal(workspacehelper.Response{
			Version: workspacehelper.Version, OK: true,
			Attachments: []attachments.Staged{{
				ID:        "att_abcdefghijklmnopqrstuvwx",
				Path:      "/codex-mobile-attachments/stage-1784205000-abcdefghijklmnop/att_abcdefghijklmnopqrstuvwx.txt",
				MediaType: "text/plain", SizeBytes: 11, ExpiresAt: time.Unix(1784205000, 0).UTC(),
			}},
		})
	}
	application := &Application{
		deps: Dependencies{WorkspaceStore: workspaceStore, State: state, Coder: coderRuntime, Clock: fixedClock{time.Unix(1784203200, 0)}},
	}
	content := []byte("owner draft")
	result, err := application.StageTerminalAttachments(
		context.Background(), httpapi.Principal{OwnerID: "owner", DeviceID: "device"}, workspaceID, tabID,
		httpapi.StageAttachmentsRequest{Attachments: []httpapi.AttachmentUpload{{MediaType: "text/plain", Content: content}}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Attachments) != 1 || result.Attachments[0].Path == "" || string(helperUpload.Content) != "owner draft" {
		t.Fatalf("unexpected attachment result=%#v helper=%#v", result, helperUpload)
	}
	for _, value := range content {
		if value != 0 {
			t.Fatal("application retained plaintext attachment content")
		}
	}
	if len(state.audits) != 1 || state.audits[0].action != "terminal_attachment.stage" || strings.Contains(string(state.audits[0].details), "owner draft") || strings.Contains(string(state.audits[0].details), "/codex-mobile") {
		t.Fatalf("attachment audit was not metadata-only: %#v", state.audits)
	}
}

func TestPushUsesScopedEphemeralTokenAndScrubsHelperRequest(t *testing.T) {
	t.Parallel()
	state := &fakeState{grantedSecrets: map[string][]byte{"DEPLOY_TOKEN": []byte("granted-runtime-value")}}
	workspaceStore := &fakeWorkspaceStore{value: core.Workspace{
		ID: "ws_test", OwnerID: "owner", State: core.WorkspaceRunning,
		ProviderResourceID: "11111111-1111-4111-8111-111111111111",
		Repository:         core.Repository{ID: "42", InstallationID: 7, FullName: "octo/repo"},
	}}
	coderRuntime := &fakeCoder{}
	coderRuntime.runHelper = func(raw []byte) ([]byte, error) {
		var request workspacehelper.Request
		if err := json.Unmarshal(raw, &request); err != nil || request.Repository != "octo/repo" || !bytes.Equal(request.GrantedSecrets["DEPLOY_TOKEN"], []byte("granted-runtime-value")) {
			t.Fatalf("trusted Git helper request omitted active grants: %#v, %v", request.GrantedSecrets, err)
		}
		response, err := json.Marshal(workspacehelper.Response{
			Version: workspacehelper.Version,
			OK:      true,
			GitStatus: &gitops.Status{Branch: "feature", Changes: []gitops.Change{
				{Path: "main.go", Worktree: 'M', Unstaged: true},
				{Path: ".env", Worktree: 'M', Unstaged: true},
			}},
		})
		return response, err
	}
	github := &fakeGitHub{token: "ghs_ephemeral"}
	application := &Application{
		config: Config{GitHubConfigured: true},
		deps: Dependencies{
			WorkspaceStore: workspaceStore, Coder: coderRuntime, GitHub: github, State: state,
			Connections: &fakeConnections{active: true}, Clock: fixedClock{time.Unix(100, 0)},
		},
	}
	status, err := application.PushWorkspace(context.Background(), httpapi.Principal{OwnerID: "owner", DeviceID: "device"}, "ws_test")
	if err != nil {
		t.Fatal(err)
	}
	if github.installationID != 7 || len(github.repositoryIDs) != 1 || github.repositoryIDs[0] != 42 || github.permissions["contents"] != "write" {
		t.Fatalf("installation token was not narrowly scoped: %#v", github)
	}
	if len(status.Changes) != 1 || status.Changes[0].Path != "main.go" {
		t.Fatalf("sensitive Git path was exposed: %#v", status.Changes)
	}
	if state.grantLoads != 1 {
		t.Fatalf("active grants loaded %d times, want 1", state.grantLoads)
	}
	for _, value := range coderRuntime.helperRequest {
		if value != 0 {
			t.Fatal("serialized helper request was not scrubbed after use")
		}
	}
}

func TestCheckpointListingDeniesCrossOwnerBeforeReadingCheckpointStorage(t *testing.T) {
	t.Parallel()
	checkpoints := &fakeCheckpoints{}
	application := &Application{deps: Dependencies{
		WorkspaceStore: &fakeWorkspaceStore{value: core.Workspace{ID: "ws_test", OwnerID: "owner"}},
		Checkpoints:    checkpoints,
	}}
	_, err := application.ListCheckpoints(context.Background(), httpapi.Principal{OwnerID: "other-owner"}, "ws_test")
	if !errors.Is(err, core.ErrNotFound) || checkpoints.listCalls != 0 {
		t.Fatalf("cross-owner checkpoint read = %v, calls=%d", err, checkpoints.listCalls)
	}
}

func TestDiscardReturnsVerifiedRecoveryCheckpointAndUpdatedStatus(t *testing.T) {
	t.Parallel()
	const checkpointID = "cp_20260716T010203.000000000Z_aaaaaaaaaaaaaaaaaaaaaaaa"
	workspaceStore := &fakeWorkspaceStore{value: core.Workspace{
		ID: "ws_test", OwnerID: "owner", State: core.WorkspaceRunning,
		ProviderResourceID: "11111111-1111-4111-8111-111111111111",
	}}
	checkpoints := &fakeCheckpoints{createID: checkpointID}
	coderRuntime := &fakeCoder{}
	coderRuntime.runHelper = func(request []byte) ([]byte, error) {
		var decoded workspacehelper.Request
		if err := json.Unmarshal(request, &decoded); err != nil {
			return nil, err
		}
		if decoded.Operation != workspacehelper.OpGitDiscard || decoded.CheckpointID != checkpointID || !decoded.Confirmed || len(decoded.Paths) != 1 || decoded.Paths[0] != "tracked.txt" {
			return nil, errors.New("discard helper request did not carry verified recovery boundary")
		}
		return json.Marshal(workspacehelper.Response{
			Version: workspacehelper.Version, OK: true, CheckpointID: checkpointID,
			GitStatus: &gitops.Status{Branch: "feature", Dirty: false},
		})
	}
	application := &Application{deps: Dependencies{
		WorkspaceStore: workspaceStore, Checkpoints: checkpoints, Coder: coderRuntime,
		State: &fakeState{}, Clock: fixedClock{time.Unix(100, 0)},
	}}
	result, err := application.DiscardGitChanges(context.Background(), httpapi.Principal{OwnerID: "owner", DeviceID: "device"}, "ws_test", httpapi.GitDiscardRequest{Paths: []string{"tracked.txt"}, Confirmed: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.RecoveryCheckpointID != checkpointID || result.Status.Branch != "feature" || !strings.Contains(result.RestoreURL, checkpointID) || checkpoints.createCalls != 1 {
		t.Fatalf("discard result = %#v checkpoint calls=%d", result, checkpoints.createCalls)
	}
}

func TestPreviewAccessUsesFragmentAndPrivateCoderTarget(t *testing.T) {
	t.Parallel()
	expires := time.Unix(600, 0)
	state := &fakeState{route: postgres.PreviewRouteRecord{
		ID: "pv-1234", OwnerID: "owner", WorkspaceID: "ws_test", Port: 3000,
		ProcessName: "node", WorkspaceHost: "11111111-1111-4111-8111-111111111111", CreatedAt: time.Unix(10, 0),
	}}
	workspaceStore := &fakeWorkspaceStore{value: core.Workspace{
		ID: "ws_test", OwnerID: "owner", State: core.WorkspaceRunning,
		ProviderResourceID: state.route.WorkspaceHost,
	}}
	tokens := &fakePreviewTokens{token: "pv_grant.secret", expires: expires}
	principal := httpapi.Principal{OwnerID: "owner", DeviceID: "device", FamilyID: "family"}
	sessions := &revocableSessions{principal: session.Principal{
		OwnerID: principal.OwnerID, DeviceID: principal.DeviceID, FamilyID: principal.FamilyID,
	}}
	application := &Application{
		config: Config{PreviewsConfigured: true, PreviewDomain: "preview.example.test", PreviewAccessTTL: 5 * time.Minute},
		deps: Dependencies{
			Sessions: sessions, WorkspaceStore: workspaceStore, State: state, PreviewTokens: tokens, Clock: fixedClock{time.Unix(100, 0)},
		},
	}
	access, err := application.CreatePreviewAccess(context.Background(), principal, "ws_test", httpapi.PreviewAccessRequest{PreviewID: state.route.ID})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(access.URL)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.RawQuery != "" || parsed.Fragment != tokens.token || parsed.Host != "pv-1234.preview.example.test" {
		t.Fatalf("preview credential was not fragment-isolated: %s", access.URL)
	}
	if tokens.route.Host != state.route.WorkspaceHost {
		t.Fatalf("preview route did not preserve private Coder target: %#v", tokens.route)
	}
}

func TestPreviewRevocationInvalidatesGrantAndCoderTunnel(t *testing.T) {
	t.Parallel()
	now := time.Unix(100, 0)
	route := postgres.PreviewRouteRecord{
		ID: "pv-1234", OwnerID: "owner", WorkspaceID: "ws_test", Port: 3000,
		WorkspaceHost: "11111111-1111-4111-8111-111111111111", CreatedAt: time.Unix(10, 0),
	}
	state := &fakeState{route: route}
	tokens := &fakePreviewTokens{}
	tunnels := &fakePreviewTunnels{}
	application := &Application{
		config: Config{PreviewsConfigured: true},
		deps: Dependencies{
			WorkspaceStore: &fakeWorkspaceStore{value: core.Workspace{ID: "ws_test", OwnerID: "owner", State: core.WorkspaceRunning}},
			State:          state, PreviewTokens: tokens, PreviewTunnels: tunnels, Clock: fixedClock{now},
		},
	}
	if err := application.RevokePreviewAccess(context.Background(), httpapi.Principal{OwnerID: "owner", DeviceID: "device"}, "ws_test", route.ID); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(tokens.revokedRoutes, []string{route.ID}) ||
		!slices.Equal(tunnels.revoked, []previewTunnelTarget{{workspaceID: route.WorkspaceHost, port: uint16(route.Port)}}) ||
		!slices.Equal(state.revokedPreviewRoutes, []string{route.ID}) {
		t.Fatalf("preview revoke mismatch: tokens=%v tunnels=%v state=%v", tokens.revokedRoutes, tunnels.revoked, state.revokedPreviewRoutes)
	}
}

func TestPreviewSyncRevokesStaleRouteRuntime(t *testing.T) {
	t.Parallel()
	route := postgres.PreviewRouteRecord{
		ID: "pv-stale", OwnerID: "owner", WorkspaceID: "ws_test", Port: 3000,
		WorkspaceHost: "11111111-1111-4111-8111-111111111111", CreatedAt: time.Unix(10, 0),
	}
	state := &fakeState{routes: []postgres.PreviewRouteRecord{route}}
	tokens := &fakePreviewTokens{}
	tunnels := &fakePreviewTunnels{}
	application := &Application{
		config: Config{PreviewsConfigured: true},
		deps: Dependencies{
			WorkspaceStore: &fakeWorkspaceStore{value: core.Workspace{
				ID: "ws_test", OwnerID: "owner", State: core.WorkspaceRunning, ProviderResourceID: route.WorkspaceHost,
			}},
			Coder: &fakeCoder{agentID: "agent-1"}, State: state,
			PreviewTokens: tokens, PreviewTunnels: tunnels, Clock: fixedClock{time.Unix(100, 0)},
		},
	}
	values, err := application.ListPreviews(context.Background(), httpapi.Principal{OwnerID: "owner", DeviceID: "device"}, "ws_test")
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 0 || !slices.Equal(tokens.revokedRoutes, []string{route.ID}) ||
		!slices.Equal(tunnels.revoked, []previewTunnelTarget{{workspaceID: route.WorkspaceHost, port: uint16(route.Port)}}) {
		t.Fatalf("stale preview runtime survived sync: values=%v tokens=%v tunnels=%v", values, tokens.revokedRoutes, tunnels.revoked)
	}
}

func TestResolveApprovalContinuesProvisioning(t *testing.T) {
	t.Parallel()
	now := time.Unix(100, 0)
	state := &fakeState{event: postgres.SafetyEvent{
		ID: "approval_1", WorkspaceID: "ws_test", WorkspaceName: "Task", SafetyMode: "balanced",
		Action: "approve_repository_setup", Decision: "requested", Reason: "Review setup", CreatedAt: now,
	}}
	operations := &fakeWorkspaceOperations{approved: core.Workspace{ID: "ws_test", OwnerID: "owner", State: core.WorkspaceRunning}}
	store := &fakeWorkspaceStore{value: core.Workspace{
		ID: "ws_test", OwnerID: "owner", State: core.WorkspaceAwaitingSetupApproval,
		SafetyMode: core.SafetyBalanced, DevcontainerDir: ".",
	}}
	application := &Application{
		deps: Dependencies{State: state, Workspaces: operations, WorkspaceStore: store, Clock: fixedClock{now}, Random: zeroReader{}},
	}
	review, err := application.ResolveApproval(context.Background(), httpapi.Principal{OwnerID: "owner", DeviceID: "device"}, "approval_1", httpapi.ApprovalDecisionRequest{Decision: httpapi.DecisionApprove})
	if err != nil {
		t.Fatal(err)
	}
	if operations.approveCalls != 1 || review.State != httpapi.ActivityResolved || !review.StructuredDetailAvailable {
		t.Fatalf("approval was not applied: review=%#v calls=%d", review, operations.approveCalls)
	}
}

func TestDeniedSetupRetryCreatesFreshStructuredApproval(t *testing.T) {
	t.Parallel()
	now := time.Unix(100, 0).UTC()
	current := core.Workspace{
		ID: "ws_test", OwnerID: "owner", Name: "Task", Branch: "codex-mobile/task",
		BaseBranch: "main", State: core.WorkspaceFailed, FailureCode: "setup_approval_denied",
		SafetyMode: core.SafetyBalanced, Retention: core.Retention30Days,
		CreatedAt: now, UpdatedAt: now, LastActivityAt: now,
	}
	retried := current
	retried.State = core.WorkspaceAwaitingSetupApproval
	retried.FailureCode = ""
	operations := &fakeWorkspaceOperations{retried: retried}
	state := &fakeState{}
	reviews := &fakeSetupReviews{}
	application := &Application{deps: Dependencies{
		Workspaces: operations, WorkspaceStore: &fakeWorkspaceStore{value: current},
		State: state, SetupReviews: reviews, Clock: fixedClock{now}, Random: zeroReader{},
	}}
	result, err := application.PerformWorkspaceAction(
		context.Background(), httpapi.Principal{OwnerID: "owner", DeviceID: "device"}, current.ID,
		httpapi.WorkspaceActionRequest{Action: httpapi.ActionRetryProvisioning},
	)
	if err != nil {
		t.Fatal(err)
	}
	if operations.retryCalls != 1 || reviews.calls != 1 ||
		result.Workspace.Summary.Lifecycle != httpapi.WorkspaceAwaitingSetupApproval {
		t.Fatalf("denied retry did not create a new setup review: result=%#v retries=%d approvals=%d", result, operations.retryCalls, reviews.calls)
	}
}

func TestResolveApprovalRetriesEventAfterWorkspaceAcceptance(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	state := &fakeState{
		event: postgres.SafetyEvent{
			ID: "approval_retry", WorkspaceID: "ws_retry", WorkspaceName: "Task", SafetyMode: "balanced",
			Action: "approve_repository_setup", Decision: "requested", Reason: "Review setup", CreatedAt: now,
		},
		resolveErrors: []error{errors.New("injected event persistence failure"), nil},
	}
	store := &fakeWorkspaceStore{value: core.Workspace{
		ID: "ws_retry", OwnerID: "owner", State: core.WorkspaceAwaitingSetupApproval,
		SafetyMode: core.SafetyBalanced, DevcontainerDir: ".",
	}}
	operations := &fakeWorkspaceOperations{approved: core.Workspace{
		ID: "ws_retry", OwnerID: "owner", State: core.WorkspaceRunning, SetupApproved: true,
	}}
	operations.approveHook = func() { store.value = operations.approved }
	application := &Application{deps: Dependencies{
		State: state, Workspaces: operations, WorkspaceStore: store, Clock: fixedClock{now}, Random: zeroReader{},
	}}
	principal := httpapi.Principal{OwnerID: "owner", DeviceID: "device"}
	request := httpapi.ApprovalDecisionRequest{Decision: httpapi.DecisionApprove}
	if _, err := application.ResolveApproval(context.Background(), principal, state.event.ID, request); err == nil {
		t.Fatal("injected event failure was not returned")
	}
	review, err := application.ResolveApproval(context.Background(), principal, state.event.ID, request)
	if err != nil {
		t.Fatal(err)
	}
	if operations.approveCalls != 1 || state.resolveCalls != 2 || review.State != httpapi.ActivityResolved {
		t.Fatalf("retry repeated setup or failed to finalize event: approvals=%d resolutions=%d review=%#v", operations.approveCalls, state.resolveCalls, review)
	}
}

func TestCreateWorkspaceRejectsUnverifiedNestedDockerAndScrubsInput(t *testing.T) {
	t.Parallel()
	operations := &fakeWorkspaceOperations{}
	environment := map[string]string{"PRIVATE_VALUE": "must-not-survive"}
	application := &Application{deps: Dependencies{
		Workspaces: operations,
		State:      &fakeState{},
		Clock:      fixedClock{time.Unix(100, 0)},
	}}
	_, err := application.CreateWorkspace(context.Background(), httpapi.Principal{OwnerID: "owner", DeviceID: "device"}, httpapi.NewWorkspaceRequest{
		RepositoryID:         "repo-1",
		Autonomy:             httpapi.AutonomyBalanced,
		Retention:            httpapi.RetentionThirtyDays,
		NestedDocker:         true,
		EnvironmentVariables: environment,
	})
	if !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("expected fail-closed nested Docker rejection, got %v", err)
	}
	if operations.createCalls != 0 {
		t.Fatalf("workspace provider was called %d times", operations.createCalls)
	}
	if environment["PRIVATE_VALUE"] != "" {
		t.Fatal("rejected workspace environment plaintext was not scrubbed")
	}
}

func TestSecretMutationsScrubPlaintextAndAuditMetadataOnly(t *testing.T) {
	t.Parallel()
	now := time.Unix(100, 0)
	state := &fakeState{}
	workspaceStore := &fakeWorkspaceStore{value: core.Workspace{
		ID: "ws-1", OwnerID: "owner", Repository: core.Repository{ID: "repo-1"},
	}}
	application := &Application{deps: Dependencies{
		State: state, WorkspaceStore: workspaceStore, Clock: fixedClock{now}, Random: zeroReader{},
	}}
	principal := httpapi.Principal{OwnerID: "owner", DeviceID: "device"}
	created, err := application.CreateSecret(context.Background(), principal, httpapi.CreateSecretRequest{
		Name: "TOKEN", Value: httpapi.SecretValue("plaintext-must-not-audit"),
	})
	if err != nil || created.Name != "TOKEN" || created.ValueBytes != len("plaintext-must-not-audit") {
		t.Fatalf("create secret = %#v, %v", created, err)
	}
	for _, value := range state.secretPlaintext {
		if value != 0 {
			t.Fatal("create plaintext buffer was not scrubbed")
		}
	}
	if _, err := application.UpdateSecret(context.Background(), principal, created.ID, httpapi.UpdateSecretRequest{Value: httpapi.SecretValue("rotated-must-not-audit")}); err != nil {
		t.Fatal(err)
	}
	for _, value := range state.secretPlaintext {
		if value != 0 {
			t.Fatal("update plaintext buffer was not scrubbed")
		}
	}
	if err := application.GrantWorkspaceSecret(context.Background(), principal, workspaceStore.value.ID, created.ID); err != nil {
		t.Fatal(err)
	}
	if err := application.RevokeWorkspaceSecret(context.Background(), principal, workspaceStore.value.ID, created.ID); err != nil {
		t.Fatal(err)
	}
	if err := application.DeleteSecret(context.Background(), principal, created.ID); err != nil {
		t.Fatal(err)
	}
	wanted := []string{"secret.create", "secret.update", "secret.grant", "secret.revoke", "secret.delete"}
	if len(state.audits) != len(wanted) {
		t.Fatalf("audit count = %d, want %d", len(state.audits), len(wanted))
	}
	for index, audit := range state.audits {
		if audit.action != wanted[index] || bytes.Contains(audit.details, []byte("must-not-audit")) || bytes.Contains(audit.details, []byte("plaintext")) {
			t.Fatalf("unsafe secret audit %d: action=%q details=%s", index, audit.action, audit.details)
		}
	}
}

func TestWorkspaceDeleteDrainsRuntimeAuthoritiesBeforeCascadeAndReturnsSnapshot(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 16, 20, 0, 0, 0, time.UTC)
	workspaceID := "ws-delete"
	tabID := "11111111-1111-4111-8111-111111111111"
	providerID := "22222222-2222-4222-8222-222222222222"
	current := core.Workspace{
		ID: workspaceID, OwnerID: "owner", Name: "Delete me", Branch: "codex-mobile/delete-me", BaseBranch: "main",
		State: core.WorkspaceFailed, SafetyMode: core.SafetyBalanced, Retention: core.Retention30Days,
		ProviderResourceID: providerID, Repository: core.Repository{ID: "repo-1", FullName: "owner/repo"},
		CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Minute), LastActivityAt: now.Add(-time.Minute),
	}
	store := &fakeWorkspaceStore{value: current}
	state := &fakeState{
		tab: postgres.TerminalTabRecord{
			ID: tabID, OwnerID: current.OwnerID, WorkspaceID: workspaceID, Title: "Codex", Kind: "codex",
			CoderReconnectID: "33333333-3333-4333-8333-333333333333", CreatedAt: current.CreatedAt,
		},
		routes: []postgres.PreviewRouteRecord{{
			ID: "pv-delete", OwnerID: current.OwnerID, WorkspaceID: workspaceID, Port: 3000,
			WorkspaceHost: providerID, CreatedAt: current.CreatedAt,
		}},
		routesSynced: true,
	}
	terminals := &fakeTerminals{}
	tokens := &fakePreviewTokens{}
	tunnels := &fakePreviewTunnels{}
	operations := &fakeWorkspaceOperations{}
	var application *Application
	operations.deleteHook = func(ctx context.Context, ownerID, id string) error {
		if ownerID != current.OwnerID || id != workspaceID {
			return errors.New("delete was not owner/workspace scoped")
		}
		release, err := application.BeginWorkspaceDeleteFinalization(ctx, current)
		if err != nil {
			return err
		}
		defer release()
		// Simulate the exact-row PostgreSQL delete and its child cascades while
		// the process-local mutation boundary is still held.
		store.deleted = true
		state.tab = postgres.TerminalTabRecord{}
		state.routes = nil
		return nil
	}
	application = &Application{
		config: Config{PreviewsConfigured: true},
		deps: Dependencies{
			Workspaces: operations, WorkspaceStore: store, State: state, Terminals: terminals,
			PreviewTokens: tokens, PreviewTunnels: tunnels, Clock: fixedClock{now},
		},
		running: map[string]bool{tabID: true}, starting: make(map[string]chan struct{}),
		mutationLocks: make(map[string]*mutationGate),
	}
	result, err := application.PerformWorkspaceAction(
		context.Background(), httpapi.Principal{OwnerID: current.OwnerID, DeviceID: "device"}, workspaceID,
		httpapi.WorkspaceActionRequest{Action: httpapi.ActionDelete},
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Accepted || result.Workspace.Summary.Lifecycle != httpapi.WorkspaceDeleting ||
		result.Workspace.Summary.Connectivity != httpapi.ConnectivityUnavailable {
		t.Fatalf("delete tombstone response = %#v", result)
	}
	if store.getAfterDelete != 0 {
		t.Fatalf("application refetched finalized workspace %d times", store.getAfterDelete)
	}
	if terminals.unregisterCalls != 1 || application.running[tabID] {
		t.Fatalf("terminal runtime survived delete: unregisters=%d running=%v", terminals.unregisterCalls, application.running[tabID])
	}
	if !slices.Equal(tokens.revokedRoutes, []string{"pv-delete"}) ||
		!slices.Equal(tunnels.revoked, []previewTunnelTarget{{workspaceID: providerID, port: 3000}}) {
		t.Fatalf("preview authority survived delete: tokens=%v tunnels=%v", tokens.revokedRoutes, tunnels.revoked)
	}
	if len(state.audits) != 1 {
		t.Fatalf("delete audit count = %d", len(state.audits))
	}
	audit := state.audits[0]
	if audit.action != "workspace.delete" || audit.result != "success" || audit.workspaceID != "" || audit.targetID != workspaceID {
		t.Fatalf("post-delete audit lost nullable-link semantics: %#v", audit)
	}
}

func TestWorkspaceSuspensionDrainsAllRuntimeAuthorityAndResumeReopensPTY(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 16, 20, 30, 0, 0, time.UTC)
	workspaceID := "ws-suspend"
	tabID := "11111111-1111-4111-8111-111111111111"
	providerID := "22222222-2222-4222-8222-222222222222"
	value := core.Workspace{
		ID: workspaceID, OwnerID: "owner", State: core.WorkspaceSuspending,
		ProviderResourceID: providerID, Repository: core.Repository{ID: "repo-1"},
		CreatedAt: now.Add(-time.Hour), UpdatedAt: now, LastActivityAt: now,
	}
	store := &fakeWorkspaceStore{value: value}
	state := &fakeState{
		tab: postgres.TerminalTabRecord{
			ID: tabID, OwnerID: value.OwnerID, WorkspaceID: workspaceID, Title: "Shell", Kind: "shell",
			CoderReconnectID: "33333333-3333-4333-8333-333333333333", CreatedAt: value.CreatedAt,
		},
		routes: []postgres.PreviewRouteRecord{{
			ID: "pv-suspend", OwnerID: value.OwnerID, WorkspaceID: workspaceID, Port: 3000,
			WorkspaceHost: providerID, CreatedAt: value.CreatedAt,
		}},
		routesSynced: true,
	}
	terminals := &fakeTerminals{
		registerCalls: 1, issueCalls: 1, activeTickets: 1, activeReconnects: 1, activeSubscribers: 1,
	}
	tokens := &fakePreviewTokens{}
	tunnels := &fakePreviewTunnels{}
	coderRuntime := &fakeCoder{runtime: newFakeRuntime(), agentID: "agent-1", openCalls: 1}
	coderRuntime.runHelper = func(raw []byte) ([]byte, error) {
		var request workspacehelper.Request
		if err := json.Unmarshal(raw, &request); err != nil {
			return nil, err
		}
		if request.Operation != workspacehelper.OpRuntimeSecretsSync {
			return nil, fmt.Errorf("unexpected helper operation %q", request.Operation)
		}
		return json.Marshal(workspacehelper.Response{Version: workspacehelper.Version, OK: true})
	}
	principal := httpapi.Principal{OwnerID: value.OwnerID, DeviceID: "device", FamilyID: "family"}
	sessions := &revocableSessions{principal: session.Principal{
		OwnerID: principal.OwnerID, DeviceID: principal.DeviceID, FamilyID: principal.FamilyID,
	}}
	application := &Application{
		config: Config{
			PreviewsConfigured: true, TerminalWebSocketURL: "wss://api.example.test/v1/terminal",
			InitialTerminalSize: terminal.Size{Rows: 24, Columns: 80},
		},
		deps: Dependencies{
			Sessions: sessions, WorkspaceStore: store, State: state, Coder: coderRuntime, Terminals: terminals,
			PreviewTokens: tokens, PreviewTunnels: tunnels, Clock: fixedClock{now},
		},
		running: map[string]bool{tabID: true}, starting: make(map[string]chan struct{}),
		mutationLocks: make(map[string]*mutationGate), terminalLocks: make(map[string]*mutationGate),
	}

	release, err := application.BeginWorkspaceSuspension(context.Background(), value)
	if err != nil {
		t.Fatal(err)
	}
	if application.running[tabID] || terminals.unregisterCalls != 1 || terminals.activeTickets != 0 ||
		terminals.activeReconnects != 0 || terminals.activeSubscribers != 0 {
		t.Fatalf("terminal authority survived suspension: running=%v unregisters=%d tickets=%d reconnects=%d subscribers=%d",
			application.running[tabID], terminals.unregisterCalls, terminals.activeTickets, terminals.activeReconnects, terminals.activeSubscribers)
	}
	if !slices.Equal(tokens.revokedRoutes, []string{"pv-suspend"}) ||
		!slices.Equal(tunnels.revoked, []previewTunnelTarget{{workspaceID: providerID, port: 3000}}) ||
		!slices.Equal(state.revokedPreviewRoutes, []string{"pv-suspend"}) {
		t.Fatalf("preview authority survived suspension: grants=%v tunnels=%v durable=%v",
			tokens.revokedRoutes, tunnels.revoked, state.revokedPreviewRoutes)
	}

	// Simulate the service's final suspended save and a later resume becoming
	// visible while the runtime-drain gate is still retained. A new terminal
	// cannot race into the cleanup/final-state window; after release it must open
	// and register a fresh PTY rather than issue against the stale runtime bit.
	store.value.State = core.WorkspaceRunning
	connected := make(chan error, 1)
	go func() {
		_, connectErr := application.CreateTerminalConnection(
			context.Background(), principal, workspaceID, tabID, httpapi.TerminalConnectRequest{},
		)
		connected <- connectErr
	}()
	select {
	case connectErr := <-connected:
		t.Fatalf("terminal creation crossed retained suspension gate: %v", connectErr)
	case <-time.After(25 * time.Millisecond):
	}
	release()
	if err := <-connected; err != nil {
		t.Fatal(err)
	}
	if coderRuntime.openCalls != 2 || terminals.registerCalls != 2 || terminals.issueCalls != 2 || !application.running[tabID] {
		t.Fatalf("resume reused stale runtime: opens=%d registers=%d issues=%d running=%v",
			coderRuntime.openCalls, terminals.registerCalls, terminals.issueCalls, application.running[tabID])
	}
}

type fakeSessionAuthenticator struct {
	principal session.Principal
	err       error
}

type fakePasskeyService struct {
	start        passkeys.RegistrationStart
	metadata     []passkeys.CredentialMetadata
	ownerID      string
	deviceID     string
	device       passkeys.DeviceBinding
	revokedOwner string
	revokedID    string
}

func (f *fakePasskeyService) BeginBootstrapRegistration(context.Context, string, passkeys.DeviceBinding) (passkeys.RegistrationStart, error) {
	return passkeys.RegistrationStart{}, nil
}
func (f *fakePasskeyService) FinishBootstrapRegistration(context.Context, string, string, passkeys.DeviceBinding, []byte) (passkeys.LoginResult, error) {
	return passkeys.LoginResult{}, nil
}
func (f *fakePasskeyService) BeginAdditionalRegistration(_ context.Context, ownerID, deviceID string, device passkeys.DeviceBinding) (passkeys.RegistrationStart, error) {
	f.ownerID, f.deviceID, f.device = ownerID, deviceID, device
	return f.start, nil
}
func (f *fakePasskeyService) FinishAdditionalRegistration(context.Context, string, string, string, passkeys.DeviceBinding, []byte) (passkeys.CredentialMetadata, error) {
	return f.metadata[0], nil
}
func (f *fakePasskeyService) ListCredentials(_ context.Context, ownerID string) ([]passkeys.CredentialMetadata, error) {
	f.ownerID = ownerID
	return append([]passkeys.CredentialMetadata(nil), f.metadata...), nil
}
func (f *fakePasskeyService) RevokeCredential(_ context.Context, ownerID, credentialID string) error {
	f.revokedOwner, f.revokedID = ownerID, credentialID
	return nil
}
func (f *fakePasskeyService) BeginLogin(context.Context, passkeys.DeviceBinding) (passkeys.LoginStart, error) {
	return passkeys.LoginStart{}, nil
}
func (f *fakePasskeyService) FinishLogin(context.Context, string, passkeys.DeviceBinding, []byte) (passkeys.LoginResult, error) {
	return passkeys.LoginResult{}, nil
}

func (f fakeSessionAuthenticator) Authenticate(context.Context, string) (session.Principal, error) {
	return f.principal, f.err
}

type fixedClock struct{ value time.Time }

func (f fixedClock) Now() time.Time { return f.value }

type zeroReader struct{}

func (zeroReader) Read(value []byte) (int, error) {
	for index := range value {
		value[index] = byte(index + 1)
	}
	return len(value), nil
}

type fakeWorkspaceStore struct {
	value          core.Workspace
	values         []core.Workspace
	deleted        bool
	getAfterDelete int
}

type fakeCheckpoints struct {
	createID    string
	createCalls int
	listCalls   int
}

func (f *fakeCheckpoints) CreateRequired(context.Context, string, string, string) (string, bool, bool, error) {
	f.createCalls++
	return f.createID, true, false, nil
}

func (f *fakeCheckpoints) ListVerified(context.Context, string) ([]checkpoint.VerifiedMetadata, error) {
	f.listCalls++
	return []checkpoint.VerifiedMetadata{}, nil
}

func (f *fakeCheckpoints) RestoreFileProtected(context.Context, string, string, string, string, bool) (string, error) {
	return f.createID, nil
}

func (f *fakeCheckpoints) RestoreWorkspace(context.Context, string, string, string, bool) (checkpoint.RestoreWorkspaceResult, error) {
	return checkpoint.RestoreWorkspaceResult{}, nil
}

func (f *fakeWorkspaceStore) Get(_ context.Context, ownerID, workspaceID string) (core.Workspace, error) {
	if f.deleted {
		f.getAfterDelete++
		return core.Workspace{}, core.ErrNotFound
	}
	if f.value.OwnerID != ownerID || f.value.ID != workspaceID {
		return core.Workspace{}, core.ErrNotFound
	}
	return f.value, nil
}
func (f *fakeWorkspaceStore) Save(_ context.Context, value core.Workspace) error {
	f.value = value
	return nil
}

func (f *fakeWorkspaceStore) TouchActivity(_ context.Context, ownerID, workspaceID string, at time.Time) error {
	value, err := f.Get(context.Background(), ownerID, workspaceID)
	if err != nil {
		return err
	}
	value.LastActivityAt = at
	value.UpdatedAt = at
	if value.State == core.WorkspaceIdle {
		value.State = core.WorkspaceRunning
	}
	return f.Save(context.Background(), value)
}

func (f *fakeWorkspaceStore) UpdateGitRisk(_ context.Context, ownerID, workspaceID string, dirty, unpushed bool, at time.Time) error {
	value, err := f.Get(context.Background(), ownerID, workspaceID)
	if err != nil {
		return err
	}
	value.Dirty, value.Unpushed, value.UpdatedAt = dirty, unpushed, at
	return f.Save(context.Background(), value)
}

func (f *fakeWorkspaceStore) List(_ context.Context, ownerID string) ([]core.Workspace, error) {
	if f.values != nil {
		values := make([]core.Workspace, 0, len(f.values))
		for _, value := range f.values {
			if value.OwnerID == ownerID {
				values = append(values, value)
			}
		}
		return values, nil
	}
	return []core.Workspace{f.value}, nil
}

type fakeHealth struct{ err error }

func (f fakeHealth) Ping(context.Context) error { return f.err }

type fakeMaintenanceService struct {
	run              maintenance.Run
	beginUpdateCalls int
}

func (f *fakeMaintenanceService) Status(_ context.Context, ownerID string) (maintenance.Run, error) {
	if f.run.OwnerID != ownerID {
		return maintenance.Run{}, core.ErrNotFound
	}
	return f.run, nil
}
func (f *fakeMaintenanceService) ScheduleWeekly(context.Context, string) (maintenance.Run, error) {
	return f.run, nil
}
func (f *fakeMaintenanceService) ScheduleUrgent(context.Context, string) (maintenance.Run, error) {
	return f.run, nil
}
func (f *fakeMaintenanceService) Cancel(context.Context, string, string) (maintenance.Run, error) {
	return f.run, nil
}
func (f *fakeMaintenanceService) BeginUpdate(_ context.Context, runID string) (maintenance.Run, error) {
	if runID != f.run.ID {
		return maintenance.Run{}, core.ErrNotFound
	}
	f.beginUpdateCalls++
	f.run.State = maintenance.StateUpdating
	return f.run, nil
}
func (f *fakeMaintenanceService) UpdateApplied(context.Context, string, bool) (maintenance.Run, error) {
	return f.run, nil
}
func (f *fakeMaintenanceService) BeginVerification(context.Context, string) (maintenance.Run, error) {
	return f.run, nil
}
func (f *fakeMaintenanceService) Complete(context.Context, string) (maintenance.Run, error) {
	return f.run, nil
}

type fakeWorkspaceOperations struct {
	approved     core.Workspace
	denied       core.Workspace
	retried      core.Workspace
	approveCalls int
	denyCalls    int
	retryCalls   int
	createCalls  int
	deleteHook   func(context.Context, string, string) error
	approveHook  func()
	denyHook     func()
}

func (f *fakeWorkspaceOperations) Create(context.Context, string, core.CreateWorkspaceInput) (core.Workspace, error) {
	f.createCalls++
	return core.Workspace{}, nil
}
func (f *fakeWorkspaceOperations) ApproveSetup(context.Context, string, string) (core.Workspace, error) {
	f.approveCalls++
	if f.approveHook != nil {
		f.approveHook()
	}
	return f.approved, nil
}
func (f *fakeWorkspaceOperations) DenySetup(context.Context, string, string) (core.Workspace, error) {
	f.denyCalls++
	if f.denyHook != nil {
		f.denyHook()
	}
	return f.denied, nil
}
func (f *fakeWorkspaceOperations) Retry(context.Context, string, string) (core.Workspace, error) {
	f.retryCalls++
	return f.retried, nil
}
func (f *fakeWorkspaceOperations) Suspend(context.Context, string, string) (core.Workspace, error) {
	return core.Workspace{}, nil
}
func (f *fakeWorkspaceOperations) Resume(context.Context, string, string) (core.Workspace, error) {
	return core.Workspace{}, nil
}

func (f *fakeWorkspaceOperations) Delete(ctx context.Context, ownerID, workspaceID string, automatic, confirmed bool) error {
	if f.deleteHook != nil {
		if automatic || !confirmed {
			return errors.New("unexpected application delete policy")
		}
		return f.deleteHook(ctx, ownerID, workspaceID)
	}
	return nil
}
func (f *fakeWorkspaceOperations) TouchActivity(context.Context, string, string, time.Time) (core.Workspace, error) {
	return core.Workspace{}, nil
}
func (f *fakeWorkspaceOperations) UpdatePolicy(context.Context, string, string, core.RetentionPolicy, int) (core.Workspace, error) {
	return core.Workspace{}, nil
}
func (f *fakeWorkspaceOperations) UpdateSafetyMode(context.Context, string, string, core.SafetyMode) (core.Workspace, error) {
	return core.Workspace{}, nil
}

type fakeState struct {
	tab                  postgres.TerminalTabRecord
	route                postgres.PreviewRouteRecord
	event                postgres.SafetyEvent
	touches              int
	initialPrompt        string
	promptDelivered      bool
	secretPlaintext      []byte
	audits               []fakeAudit
	grantedSecrets       map[string][]byte
	grantLoads           int
	routes               []postgres.PreviewRouteRecord
	routesSynced         bool
	revokedPreviewRoutes []string
	resolveErrors        []error
	resolveCalls         int
}

type fakeSetupReviews struct {
	calls int
	err   error
}

func (f *fakeSetupReviews) Ensure(context.Context, core.Workspace, time.Time) error {
	f.calls++
	return f.err
}

type fakeAudit struct {
	workspaceID string
	action      string
	result      string
	targetID    string
	details     json.RawMessage
}

func (f *fakeState) CreateSecret(_ context.Context, value secretmodel.Metadata, plaintext []byte, _ time.Time) (secretmodel.Metadata, error) {
	f.secretPlaintext = plaintext
	value.ValueBytes = len(plaintext)
	return value, nil
}
func (f *fakeState) ListSecrets(context.Context, string, *string) ([]secretmodel.Metadata, error) {
	return nil, nil
}
func (f *fakeState) UpdateSecret(_ context.Context, ownerID, secretID string, plaintext []byte, now time.Time) (secretmodel.Metadata, error) {
	f.secretPlaintext = plaintext
	return secretmodel.Metadata{ID: secretID, OwnerID: ownerID, Name: "TOKEN", ValueBytes: len(plaintext), CreatedAt: now, UpdatedAt: now}, nil
}
func (f *fakeState) DeleteSecret(context.Context, string, string, time.Time) error { return nil }
func (f *fakeState) ListSecretWorkspaceIDs(context.Context, string, string) ([]string, error) {
	return nil, nil
}
func (f *fakeState) ListWorkspaceSecretGrants(context.Context, string, string) ([]secretmodel.WorkspaceGrant, error) {
	return nil, nil
}
func (f *fakeState) GrantWorkspaceSecret(context.Context, string, string, string, time.Time) error {
	return nil
}
func (f *fakeState) RevokeWorkspaceSecret(context.Context, string, string, string, time.Time) error {
	return nil
}
func (f *fakeState) LoadGrantedWorkspaceSecrets(context.Context, string, string) (map[string][]byte, error) {
	f.grantLoads++
	result := make(map[string][]byte, len(f.grantedSecrets))
	for name, value := range f.grantedSecrets {
		result[name] = bytes.Clone(value)
	}
	return result, nil
}

func (f *fakeState) GetSettings(context.Context, string) (postgres.Settings, error) {
	return postgres.DefaultSettings(), nil
}
func (f *fakeState) SaveSettings(context.Context, string, postgres.Settings, time.Time) error {
	return nil
}
func (f *fakeState) LoadWorkspaceInitialPrompt(context.Context, string, string, string) (string, error) {
	return f.initialPrompt, nil
}
func (f *fakeState) MarkWorkspaceInitialPromptDelivered(context.Context, string, string, string, time.Time) error {
	f.promptDelivered = true
	return nil
}
func (f *fakeState) CreateTerminalTab(_ context.Context, value postgres.TerminalTabRecord) (postgres.TerminalTabRecord, error) {
	f.tab = value
	return value, nil
}
func (f *fakeState) ListTerminalTabs(context.Context, string, string) ([]postgres.TerminalTabRecord, error) {
	return []postgres.TerminalTabRecord{f.tab}, nil
}
func (f *fakeState) GetTerminalTab(context.Context, string, string, string) (postgres.TerminalTabRecord, error) {
	return f.tab, nil
}
func (f *fakeState) RenameTerminalTab(_ context.Context, _, _, _ string, title string) (postgres.TerminalTabRecord, error) {
	f.tab.Title = title
	return f.tab, nil
}
func (f *fakeState) ReorderTerminalTabs(_ context.Context, _, _ string, tabIDs []string) ([]postgres.TerminalTabRecord, error) {
	f.tab.Order = 0
	if len(tabIDs) == 1 && tabIDs[0] == f.tab.ID {
		return []postgres.TerminalTabRecord{f.tab}, nil
	}
	return nil, core.ErrConflict
}
func (f *fakeState) CloseTerminalTab(_ context.Context, _, _, _ string, now time.Time) (postgres.TerminalTabRecord, bool, error) {
	f.tab.ClosedAt = &now
	return f.tab, true, nil
}
func (f *fakeState) TouchTerminalTab(context.Context, string, string, string, time.Time) error {
	f.touches++
	return nil
}
func (f *fakeState) SetTerminalCodexThreadID(_ context.Context, _, _, _, threadID string) (postgres.TerminalTabRecord, error) {
	f.tab.CodexThreadID = threadID
	return f.tab, nil
}
func (f *fakeState) ListActivity(context.Context, string, int) ([]postgres.ActivityRecord, error) {
	return nil, nil
}
func (f *fakeState) AddActivity(context.Context, string, postgres.ActivityRecord) error { return nil }
func (f *fakeState) GetSafetyEvent(context.Context, string, string) (postgres.SafetyEvent, error) {
	return f.event, nil
}
func (f *fakeState) ResolveSafetyEvent(_ context.Context, _, _ string, decision, _ string, now time.Time) (postgres.SafetyEvent, error) {
	f.resolveCalls++
	if len(f.resolveErrors) != 0 {
		err := f.resolveErrors[0]
		f.resolveErrors = f.resolveErrors[1:]
		if err != nil {
			return postgres.SafetyEvent{}, err
		}
	}
	f.event.Decision = decision
	f.event.ResolvedAt = &now
	return f.event, nil
}

func (f *fakeState) SyncPreviewRoutes(_ context.Context, _, _ string, routes []postgres.PreviewRouteRecord, _ time.Time) error {
	f.routes = append([]postgres.PreviewRouteRecord(nil), routes...)
	f.routesSynced = true
	return nil
}
func (f *fakeState) ListPreviewRoutes(context.Context, string, string) ([]postgres.PreviewRouteRecord, error) {
	if f.routesSynced || f.routes != nil {
		return append([]postgres.PreviewRouteRecord(nil), f.routes...), nil
	}
	return []postgres.PreviewRouteRecord{f.route}, nil
}
func (f *fakeState) GetPreviewRoute(context.Context, string, string, string) (postgres.PreviewRouteRecord, error) {
	return f.route, nil
}
func (f *fakeState) RevokePreviewRoute(_ context.Context, _, _, routeID string, _ time.Time) error {
	f.revokedPreviewRoutes = append(f.revokedPreviewRoutes, routeID)
	return nil
}
func (f *fakeState) RegisterNotification(context.Context, string, string, string, string, string, time.Time) error {
	return nil
}

func (f *fakeState) Audit(_ context.Context, _, _, workspaceID, action, result, _, targetID string, details json.RawMessage, _ time.Time) error {
	f.audits = append(f.audits, fakeAudit{
		workspaceID: workspaceID, action: action, result: result, targetID: targetID,
		details: append(json.RawMessage(nil), details...),
	})
	return nil
}

type fakeRuntime struct {
	output chan []byte
}

func newFakeRuntime() *fakeRuntime                                 { return &fakeRuntime{output: make(chan []byte)} }
func (f *fakeRuntime) Output() <-chan []byte                       { return f.output }
func (f *fakeRuntime) WriteInput(context.Context, []byte) error    { return nil }
func (f *fakeRuntime) Resize(context.Context, terminal.Size) error { return nil }
func (f *fakeRuntime) Close() error                                { return nil }

type fakeCoder struct {
	runtime          terminal.Runtime
	agentID          string
	openCalls        int
	helperRequest    []byte
	runHelper        func([]byte) ([]byte, error)
	runHelperContext func(context.Context, []byte) ([]byte, error)
	config           coder.PTYConfig
}

func (f *fakeCoder) RunHelper(ctx context.Context, _ string, request []byte) ([]byte, error) {
	f.helperRequest = request
	if f.runHelperContext != nil {
		return f.runHelperContext(ctx, request)
	}
	if f.runHelper != nil {
		return f.runHelper(request)
	}
	return nil, errors.New("unexpected helper call")
}
func (f *fakeCoder) AgentID(context.Context, string) (string, error)              { return f.agentID, nil }
func (f *fakeCoder) ListeningPorts(context.Context, string) ([]coder.Port, error) { return nil, nil }
func (f *fakeCoder) OpenPTY(config coder.PTYConfig) (terminal.Runtime, error) {
	f.openCalls++
	f.config = config
	return f.runtime, nil
}

type fakeTerminals struct {
	registerCalls     int
	issueCalls        int
	unregisterCalls   int
	activeTickets     int
	activeReconnects  int
	activeSubscribers int
	unregisterHook    func(terminal.TabID, string) error
	revokeCalls       int
	revokedOwner      string
	revokedDevice     string
	redactor          terminal.OutputRedactor
	registerErr       error
	issueErr          error
}

func (f *fakeTerminals) Register(_ string, _ string, _ terminal.TabID, _ terminal.Runtime, redactor terminal.OutputRedactor, _ bool) error {
	f.registerCalls++
	f.redactor = redactor
	return f.registerErr
}
func (f *fakeTerminals) Unregister(tabID terminal.TabID, reason string) error {
	f.unregisterCalls++
	f.activeTickets = 0
	f.activeReconnects = 0
	f.activeSubscribers = 0
	if f.unregisterHook != nil {
		return f.unregisterHook(tabID, reason)
	}
	return nil
}
func (f *fakeTerminals) Issue(string, string, string, terminal.TabID, uint64, string) (terminal.Connection, error) {
	f.issueCalls++
	if f.issueErr != nil {
		return terminal.Connection{}, f.issueErr
	}
	return terminal.Connection{Ticket: "ticket", ReconnectToken: "reconnect", ProtocolVersion: terminal.Version, MaximumFrameBytes: terminal.MaxPayload}, nil
}
func (f *fakeTerminals) RevokeDevice(ownerID, deviceID string) int {
	f.revokeCalls++
	f.revokedOwner = ownerID
	f.revokedDevice = deviceID
	return 1
}

type fakeGitHub struct {
	token          string
	tokenCalls     int
	installationID int64
	repositoryIDs  []int64
	permissions    map[string]string
}

func (f *fakeGitHub) InstallationToken(_ context.Context, installationID int64, repositoryIDs []int64, permissions map[string]string) (githubapp.InstallationToken, error) {
	f.tokenCalls++
	f.installationID = installationID
	f.repositoryIDs = append([]int64(nil), repositoryIDs...)
	f.permissions = permissions
	return githubapp.InstallationToken{Token: f.token, ExpiresAt: time.Now().Add(time.Hour)}, nil
}
func (f *fakeGitHub) RevokeInstallationToken(context.Context, string) error { return nil }
func (f *fakeGitHub) CreatePullRequest(context.Context, string, string, string, string, string, string, bool) (githubapp.PullRequest, error) {
	return githubapp.PullRequest{}, nil
}

type fakePreviewTokens struct {
	token         string
	expires       time.Time
	route         preview.Route
	revokedRoutes []string
}

func (f *fakePreviewTokens) Issue(route preview.Route, _ string, _ time.Duration) (string, time.Time, error) {
	f.route = route
	return f.token, f.expires, nil
}
func (f *fakePreviewTokens) RevokeRoute(routeID string) int {
	f.revokedRoutes = append(f.revokedRoutes, routeID)
	return 1
}
func (f *fakePreviewTokens) RevokeDevice(string, string) int { return 1 }

type previewTunnelTarget struct {
	workspaceID string
	port        uint16
}

type fakePreviewTunnels struct{ revoked []previewTunnelTarget }

func (f *fakePreviewTunnels) Revoke(workspaceID string, port uint16) {
	f.revoked = append(f.revoked, previewTunnelTarget{workspaceID: workspaceID, port: port})
}
