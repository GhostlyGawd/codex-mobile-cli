package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/session"
)

const testAccessToken = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type testAuthenticator struct {
	principal Principal
	err       error
	calls     int
	token     string
}

func (a *testAuthenticator) Authenticate(_ context.Context, token string) (Principal, error) {
	a.calls++
	a.token = token
	return a.principal, a.err
}

type testTerminalHandler struct {
	calls       int
	subprotocol string
}

func (h *testTerminalHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.calls++
	h.subprotocol = r.Header.Get("Sec-WebSocket-Protocol")
	w.Header().Set("X-Terminal-Reached", "true")
	w.WriteHeader(http.StatusSwitchingProtocols)
}

type testApplication struct {
	called         []operation
	err            error
	principal      Principal
	actionAccepted bool
	capabilities   ClientCapabilities
	savedFileBytes int
	secretValue    SecretValue
	attachmentData []byte
	capabilityHook func(context.Context) error
}

func (a *testApplication) call(name operation, principals ...Principal) error {
	a.called = append(a.called, name)
	if len(principals) != 0 {
		a.principal = principals[0]
	}
	return a.err
}

func (a *testApplication) last() operation {
	if len(a.called) == 0 {
		return ""
	}
	return a.called[len(a.called)-1]
}

func (a *testApplication) Health(context.Context) error { return a.call(opHealth) }
func (a *testApplication) GetCapabilities(ctx context.Context) (ClientCapabilities, error) {
	err := a.call(opGetCapabilities)
	if a.capabilityHook != nil {
		err = a.capabilityHook(ctx)
	}
	return a.capabilities, err
}
func (a *testApplication) BeginPasskeyRegistration(context.Context, BootstrapRegistrationRequest) (PasskeyRegistrationChallenge, error) {
	return PasskeyRegistrationChallenge{}, a.call(opBeginPasskeyRegistration)
}
func (a *testApplication) FinishPasskeyRegistration(context.Context, PasskeyRegistrationCredential) (SessionTokens, error) {
	return SessionTokens{}, a.call(opFinishPasskeyRegistration)
}
func (a *testApplication) BeginPasskeyAuthentication(context.Context, DeviceIdentityRequest) (PasskeyAuthenticationChallenge, error) {
	return PasskeyAuthenticationChallenge{}, a.call(opBeginPasskeyAuthentication)
}
func (a *testApplication) FinishPasskeyAuthentication(context.Context, PasskeyAssertionCredential) (SessionTokens, error) {
	return SessionTokens{}, a.call(opFinishPasskeyAuthentication)
}
func (a *testApplication) BeginAdditionalPasskeyRegistration(_ context.Context, principal Principal, _ DeviceIdentityRequest) (PasskeyRegistrationChallenge, error) {
	return PasskeyRegistrationChallenge{}, a.call(opBeginAdditionalPasskeyRegistration, principal)
}
func (a *testApplication) FinishAdditionalPasskeyRegistration(_ context.Context, principal Principal, _ PasskeyRegistrationCredential) (PasskeyMetadata, error) {
	return PasskeyMetadata{}, a.call(opFinishAdditionalPasskeyRegistration, principal)
}
func (a *testApplication) ListPasskeys(_ context.Context, principal Principal) ([]PasskeyMetadata, error) {
	return []PasskeyMetadata{}, a.call(opListPasskeys, principal)
}
func (a *testApplication) RevokePasskey(_ context.Context, principal Principal, _ string) error {
	return a.call(opRevokePasskey, principal)
}
func (a *testApplication) RefreshSession(context.Context, RefreshSessionRequest) (SessionTokens, error) {
	return SessionTokens{}, a.call(opRefreshSession)
}
func (a *testApplication) RevokeCurrentSession(_ context.Context, principal Principal) error {
	return a.call(opRevokeCurrentSession, principal)
}
func (a *testApplication) ListDevices(_ context.Context, principal Principal) ([]DeviceSummary, error) {
	return []DeviceSummary{}, a.call(opListDevices, principal)
}
func (a *testApplication) RevokeDevice(_ context.Context, principal Principal, _ string) error {
	return a.call(opRevokeDevice, principal)
}
func (a *testApplication) ListSecrets(_ context.Context, principal Principal, _ *string) ([]SecretMetadata, error) {
	return []SecretMetadata{}, a.call(opListSecrets, principal)
}
func (a *testApplication) CreateSecret(_ context.Context, principal Principal, request CreateSecretRequest) (SecretMetadata, error) {
	a.secretValue = request.Value
	return SecretMetadata{}, a.call(opCreateSecret, principal)
}
func (a *testApplication) UpdateSecret(_ context.Context, principal Principal, _ string, request UpdateSecretRequest) (SecretMetadata, error) {
	a.secretValue = request.Value
	return SecretMetadata{}, a.call(opUpdateSecret, principal)
}
func (a *testApplication) DeleteSecret(_ context.Context, principal Principal, _ string) error {
	return a.call(opDeleteSecret, principal)
}
func (a *testApplication) ListWorkspaceSecretGrants(_ context.Context, principal Principal, _ string) ([]WorkspaceSecretGrant, error) {
	return []WorkspaceSecretGrant{}, a.call(opListWorkspaceSecretGrants, principal)
}
func (a *testApplication) GrantWorkspaceSecret(_ context.Context, principal Principal, _, _ string) error {
	return a.call(opGrantWorkspaceSecret, principal)
}
func (a *testApplication) RevokeWorkspaceSecret(_ context.Context, principal Principal, _, _ string) error {
	return a.call(opRevokeWorkspaceSecret, principal)
}
func (a *testApplication) GetConnections(_ context.Context, principal Principal) (ConnectionStatus, error) {
	return ConnectionStatus{}, a.call(opGetConnections, principal)
}
func (a *testApplication) DisconnectGitHub(_ context.Context, principal Principal, _ int64) error {
	return a.call(opDisconnectGitHub, principal)
}
func (a *testApplication) GetCodexConnection(_ context.Context, principal Principal, _ string) (CodexWorkspaceConnection, error) {
	return CodexWorkspaceConnection{}, a.call(opGetCodexConnection, principal)
}
func (a *testApplication) DisconnectCodex(_ context.Context, principal Principal, _ string, _ ConfirmConnectionDisconnectRequest) error {
	return a.call(opDisconnectCodex, principal)
}
func (a *testApplication) ListRepositories(_ context.Context, principal Principal, _ *string) ([]RepositorySummary, error) {
	return []RepositorySummary{}, a.call(opListRepositories, principal)
}
func (a *testApplication) ListWorkspaces(_ context.Context, principal Principal) ([]WorkspaceSummary, error) {
	return []WorkspaceSummary{}, a.call(opListWorkspaces, principal)
}
func (a *testApplication) CreateWorkspace(_ context.Context, principal Principal, _ NewWorkspaceRequest) (WorkspaceDetail, error) {
	return WorkspaceDetail{}, a.call(opCreateWorkspace, principal)
}
func (a *testApplication) GetWorkspace(_ context.Context, principal Principal, _ string) (WorkspaceDetail, error) {
	return WorkspaceDetail{}, a.call(opGetWorkspace, principal)
}
func (a *testApplication) PerformWorkspaceAction(_ context.Context, principal Principal, _ string, _ WorkspaceActionRequest) (WorkspaceActionResult, error) {
	return WorkspaceActionResult{Accepted: a.actionAccepted}, a.call(opPerformWorkspaceAction, principal)
}
func (a *testApplication) ListActivity(_ context.Context, principal Principal) ([]ActivityItem, error) {
	return []ActivityItem{}, a.call(opListActivity, principal)
}
func (a *testApplication) GetApproval(_ context.Context, principal Principal, _ string) (ApprovalReview, error) {
	return ApprovalReview{}, a.call(opGetApproval, principal)
}
func (a *testApplication) ResolveApproval(_ context.Context, principal Principal, _ string, _ ApprovalDecisionRequest) (ApprovalReview, error) {
	return ApprovalReview{}, a.call(opResolveApproval, principal)
}
func (a *testApplication) ListTerminalTabs(_ context.Context, principal Principal, _ string) ([]TerminalTab, error) {
	return []TerminalTab{}, a.call(opListTerminalTabs, principal)
}
func (a *testApplication) CreateTerminalTab(_ context.Context, principal Principal, _ string, _ CreateTerminalTabRequest) (TerminalTab, error) {
	return TerminalTab{}, a.call(opCreateTerminalTab, principal)
}
func (a *testApplication) RenameTerminalTab(_ context.Context, principal Principal, _, _ string, _ RenameTerminalTabRequest) (TerminalTab, error) {
	return TerminalTab{}, a.call(opRenameTerminalTab, principal)
}
func (a *testApplication) ReorderTerminalTabs(_ context.Context, principal Principal, _ string, _ ReorderTerminalTabsRequest) ([]TerminalTab, error) {
	return []TerminalTab{}, a.call(opReorderTerminalTabs, principal)
}
func (a *testApplication) CloseTerminalTab(_ context.Context, principal Principal, _, _ string, _ CloseTerminalTabRequest) error {
	return a.call(opCloseTerminalTab, principal)
}
func (a *testApplication) CreateTerminalConnection(_ context.Context, principal Principal, _, _ string, _ TerminalConnectRequest) (TerminalConnectionDescriptor, error) {
	return TerminalConnectionDescriptor{}, a.call(opCreateTerminalConnection, principal)
}
func (a *testApplication) StageTerminalAttachments(_ context.Context, principal Principal, _, _ string, request StageAttachmentsRequest) (StageAttachmentsResult, error) {
	if len(request.Attachments) != 0 {
		a.attachmentData = request.Attachments[0].Content
	}
	return StageAttachmentsResult{Attachments: []StagedAttachment{}}, a.call(opStageTerminalAttachments, principal)
}
func (a *testApplication) GetFileTree(_ context.Context, principal Principal, _ string) ([]FileEntry, error) {
	return []FileEntry{}, a.call(opGetFileTree, principal)
}
func (a *testApplication) SearchFiles(_ context.Context, principal Principal, _, _ string) ([]FileSearchResult, error) {
	return []FileSearchResult{}, a.call(opSearchFiles, principal)
}
func (a *testApplication) GetFile(_ context.Context, principal Principal, _, _ string) (FileDocument, error) {
	return FileDocument{}, a.call(opGetFile, principal)
}
func (a *testApplication) SaveFile(_ context.Context, principal Principal, _, _ string, input SaveFileRequest) (FileDocument, error) {
	a.savedFileBytes = len(input.Content)
	return FileDocument{}, a.call(opSaveFile, principal)
}
func (a *testApplication) GetGitStatus(_ context.Context, principal Principal, _ string) (GitStatusDetail, error) {
	return GitStatusDetail{}, a.call(opGetGitStatus, principal)
}
func (a *testApplication) GetGitDiff(_ context.Context, principal Principal, _, _ string) (DiffDocument, error) {
	return DiffDocument{}, a.call(opGetGitDiff, principal)
}
func (a *testApplication) SetGitStaged(_ context.Context, principal Principal, _ string, _ StageRequest) (GitStatusDetail, error) {
	return GitStatusDetail{}, a.call(opSetGitStaged, principal)
}
func (a *testApplication) CreateCommit(_ context.Context, principal Principal, _ string, _ CommitRequest) (GitStatusDetail, error) {
	return GitStatusDetail{}, a.call(opCreateCommit, principal)
}
func (a *testApplication) PullWorkspace(_ context.Context, principal Principal, _ string) (GitStatusDetail, error) {
	return GitStatusDetail{}, a.call(opPullWorkspace, principal)
}
func (a *testApplication) PushWorkspace(_ context.Context, principal Principal, _ string) (GitStatusDetail, error) {
	return GitStatusDetail{}, a.call(opPushWorkspace, principal)
}
func (a *testApplication) DiscardGitChanges(_ context.Context, principal Principal, _ string, _ GitDiscardRequest) (GitDiscardResult, error) {
	return GitDiscardResult{}, a.call(opDiscardGitChanges, principal)
}
func (a *testApplication) CreatePullRequest(_ context.Context, principal Principal, _ string, _ PullRequestRequest) (PullRequestResult, error) {
	return PullRequestResult{}, a.call(opCreatePullRequest, principal)
}
func (a *testApplication) ListCheckpoints(_ context.Context, principal Principal, _ string) ([]CheckpointSummary, error) {
	return []CheckpointSummary{}, a.call(opListCheckpoints, principal)
}
func (a *testApplication) RestoreCheckpointFile(_ context.Context, principal Principal, _, _ string, _ CheckpointRestoreFileRequest) (CheckpointRestoreResult, error) {
	return CheckpointRestoreResult{}, a.call(opRestoreCheckpointFile, principal)
}
func (a *testApplication) RestoreCheckpointWorkspace(_ context.Context, principal Principal, _, _ string, _ CheckpointRestoreWorkspaceRequest) (CheckpointRestoreResult, error) {
	return CheckpointRestoreResult{}, a.call(opRestoreCheckpointWorkspace, principal)
}
func (a *testApplication) ListPreviews(_ context.Context, principal Principal, _ string) ([]PreviewEndpoint, error) {
	return []PreviewEndpoint{}, a.call(opListPreviews, principal)
}
func (a *testApplication) CreatePreviewAccess(_ context.Context, principal Principal, _ string, _ PreviewAccessRequest) (PreviewAccess, error) {
	return PreviewAccess{}, a.call(opCreatePreviewAccess, principal)
}
func (a *testApplication) RevokePreviewAccess(_ context.Context, principal Principal, _, _ string) error {
	return a.call(opRevokePreviewAccess, principal)
}
func (a *testApplication) GetMaintenance(_ context.Context, principal Principal) (MaintenanceStatus, error) {
	return MaintenanceStatus{}, a.call(opGetMaintenance, principal)
}
func (a *testApplication) ScheduleMaintenance(_ context.Context, principal Principal, _ ScheduleMaintenanceRequest) (MaintenanceStatus, error) {
	return MaintenanceStatus{}, a.call(opScheduleMaintenance, principal)
}
func (a *testApplication) CancelMaintenance(_ context.Context, principal Principal, _ string) (MaintenanceStatus, error) {
	return MaintenanceStatus{}, a.call(opCancelMaintenance, principal)
}
func (a *testApplication) AdvanceMaintenance(_ context.Context, principal Principal, _ string, _ MaintenanceActionRequest) (MaintenanceStatus, error) {
	return MaintenanceStatus{}, a.call(opAdvanceMaintenance, principal)
}
func (a *testApplication) GetDiagnostics(_ context.Context, principal Principal) (DiagnosticsReport, error) {
	return DiagnosticsReport{}, a.call(opGetDiagnostics, principal)
}
func (a *testApplication) GetSettings(_ context.Context, principal Principal) (UserSettings, error) {
	return UserSettings{}, a.call(opGetSettings, principal)
}
func (a *testApplication) UpdateSettings(_ context.Context, principal Principal, input UserSettings) (UserSettings, error) {
	return input, a.call(opUpdateSettings, principal)
}
func (a *testApplication) RegisterPushDevice(_ context.Context, principal Principal, _ PushDeviceRegistration) error {
	return a.call(opRegisterPushDevice, principal)
}

func newTestHandler(t *testing.T) (*Handler, *testApplication, *testAuthenticator, *testTerminalHandler) {
	t.Helper()
	application := &testApplication{}
	authenticator := &testAuthenticator{principal: Principal{OwnerID: "owner-1", DeviceID: "device-1", FamilyID: "family-1"}}
	terminal := &testTerminalHandler{}
	handler, err := New(Options{Application: application, Authenticator: authenticator, TerminalWebSocket: terminal})
	if err != nil {
		t.Fatal(err)
	}
	return handler, application, authenticator, terminal
}

func TestNewRequiresDependenciesAndBoundedTimeouts(t *testing.T) {
	application := &testApplication{}
	authenticator := &testAuthenticator{}
	terminal := &testTerminalHandler{}
	for _, options := range []Options{
		{},
		{Application: application, Authenticator: authenticator},
		{Application: application, Authenticator: authenticator, TerminalWebSocket: terminal, RESTTimeout: -time.Second},
		{Application: application, Authenticator: authenticator, TerminalWebSocket: terminal, RESTTimeout: 6 * time.Minute},
	} {
		if handler, err := New(options); err == nil || handler != nil {
			t.Fatal("invalid HTTP options were accepted")
		}
	}
}

type routeCase struct {
	name      string
	method    string
	path      string
	body      string
	operation operation
	status    int
	public    bool
}

func TestEveryRESTOperationRoutesAndEnforcesAuthentication(t *testing.T) {
	device := `"device_instance_id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","device_name":"iPhone"`
	passkeyRegistration := `{"ceremony_id":"ceremony-1","credential_id":"YQ","raw_id":"YQ","client_data_json":"YQ","attestation_object":"YQ",` + device + `}`
	passkeyAssertion := `{"ceremony_id":"ceremony-1","credential_id":"YQ","raw_id":"YQ","client_data_json":"YQ","authenticator_data":"YQ","signature":"YQ",` + device + `}`
	cases := []routeCase{
		{"health", "GET", "/healthz", "", opHealth, 200, true},
		{"capabilities", "GET", "/v1/capabilities", "", opGetCapabilities, 200, true},
		{"begin registration", "POST", "/v1/auth/passkeys/registration/options", `{"bootstrap_token":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",` + device + `}`, opBeginPasskeyRegistration, 200, true},
		{"finish registration", "POST", "/v1/auth/passkeys/registration/verify", passkeyRegistration, opFinishPasskeyRegistration, 200, true},
		{"begin authentication", "POST", "/v1/auth/passkeys/authentication/options", `{` + device + `}`, opBeginPasskeyAuthentication, 200, true},
		{"finish authentication", "POST", "/v1/auth/passkeys/authentication/verify", passkeyAssertion, opFinishPasskeyAuthentication, 200, true},
		{"begin additional passkey", "POST", "/v1/passkeys/registration/options", `{` + device + `}`, opBeginAdditionalPasskeyRegistration, 200, false},
		{"finish additional passkey", "POST", "/v1/passkeys/registration/verify", passkeyRegistration, opFinishAdditionalPasskeyRegistration, 201, false},
		{"list passkeys", "GET", "/v1/passkeys", "", opListPasskeys, 200, false},
		{"revoke passkey", "DELETE", "/v1/passkeys/YQ", "", opRevokePasskey, 204, false},
		{"refresh", "POST", "/v1/auth/session/refresh", `{"refresh_token":"rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr"}`, opRefreshSession, 200, true},
		{"revoke session", "DELETE", "/v1/auth/session", "", opRevokeCurrentSession, 204, false},
		{"devices", "GET", "/v1/devices", "", opListDevices, 200, false},
		{"revoke device", "DELETE", "/v1/devices/device-2", "", opRevokeDevice, 204, false},
		{"secrets", "GET", "/v1/secrets?repository_id=repo-1", "", opListSecrets, 200, false},
		{"create secret", "POST", "/v1/secrets", `{"name":"API_TOKEN","value":"secret-value","repository_id":"repo-1"}`, opCreateSecret, 201, false},
		{"update secret", "PUT", "/v1/secrets/secret-1", `{"value":"rotated-value"}`, opUpdateSecret, 200, false},
		{"delete secret", "DELETE", "/v1/secrets/secret-1", "", opDeleteSecret, 204, false},
		{"connections", "GET", "/v1/connections", "", opGetConnections, 200, false},
		{"disconnect GitHub", "DELETE", "/v1/connections/github/42", "", opDisconnectGitHub, 204, false},
		{"repositories", "GET", "/v1/repositories?search=mobile", "", opListRepositories, 200, false},
		{"workspaces", "GET", "/v1/workspaces", "", opListWorkspaces, 200, false},
		{"create workspace", "POST", "/v1/workspaces", `{"repository_id":"repo-1","autonomy":"balanced","nested_docker":false,"retention":"30_days","environment_variables":{}}`, opCreateWorkspace, 202, false},
		{"workspace", "GET", "/v1/workspaces/ws-1", "", opGetWorkspace, 200, false},
		{"workspace action", "POST", "/v1/workspaces/ws-1/actions", `{"action":"update_autonomy","autonomy":"safe"}`, opPerformWorkspaceAction, 200, false},
		{"workspace secret grants", "GET", "/v1/workspaces/ws-1/secret-grants", "", opListWorkspaceSecretGrants, 200, false},
		{"grant workspace secret", "PUT", "/v1/workspaces/ws-1/secret-grants/secret-1", "", opGrantWorkspaceSecret, 204, false},
		{"revoke workspace secret", "DELETE", "/v1/workspaces/ws-1/secret-grants/secret-1", "", opRevokeWorkspaceSecret, 204, false},
		{"Codex connection", "GET", "/v1/workspaces/ws-1/connections/codex", "", opGetCodexConnection, 200, false},
		{"disconnect Codex", "DELETE", "/v1/workspaces/ws-1/connections/codex", `{"confirmed":true}`, opDisconnectCodex, 204, false},
		{"activity", "GET", "/v1/activity", "", opListActivity, 200, false},
		{"approval", "GET", "/v1/approvals/approval-1", "", opGetApproval, 200, false},
		{"approval decision", "POST", "/v1/approvals/approval-1/decision", `{"decision":"approve"}`, opResolveApproval, 200, false},
		{"terminal tabs", "GET", "/v1/workspaces/ws-1/terminal-tabs", "", opListTerminalTabs, 200, false},
		{"create terminal tab", "POST", "/v1/workspaces/ws-1/terminal-tabs", `{"kind":"shell"}`, opCreateTerminalTab, 201, false},
		{"rename terminal tab", "PATCH", "/v1/workspaces/ws-1/terminal-tabs/tab-1", `{"title":"Server logs"}`, opRenameTerminalTab, 200, false},
		{"reorder terminal tabs", "PUT", "/v1/workspaces/ws-1/terminal-tabs/order", `{"tab_ids":["tab-1","tab-2"]}`, opReorderTerminalTabs, 200, false},
		{"close terminal tab", "DELETE", "/v1/workspaces/ws-1/terminal-tabs/tab-1", `{"confirmed":true}`, opCloseTerminalTab, 204, false},
		{"terminal connection", "POST", "/v1/workspaces/ws-1/terminal-tabs/tab-1/connection", `{"after_sequence":0}`, opCreateTerminalConnection, 200, false},
		{"stage terminal attachments", "POST", "/v1/workspaces/ws-1/terminal-tabs/tab-1/attachments", `{"attachments":[{"media_type":"text/plain","content_base64":"aGVsbG8="}]}`, opStageTerminalAttachments, 201, false},
		{"files", "GET", "/v1/workspaces/ws-1/files", "", opGetFileTree, 200, false},
		{"file search", "GET", "/v1/workspaces/ws-1/file-search?query=needle", "", opSearchFiles, 200, false},
		{"file", "GET", "/v1/workspaces/ws-1/file?path=README.md", "", opGetFile, 200, false},
		{"save file", "PUT", "/v1/workspaces/ws-1/file?path=README.md", `{"content":"hello","expected_e_tag":"etag-1"}`, opSaveFile, 200, false},
		{"git status", "GET", "/v1/workspaces/ws-1/git/status", "", opGetGitStatus, 200, false},
		{"git diff", "GET", "/v1/workspaces/ws-1/git/diff?path=README.md", "", opGetGitDiff, 200, false},
		{"git stage", "POST", "/v1/workspaces/ws-1/git/stage", `{"path":"README.md","staged":false}`, opSetGitStaged, 200, false},
		{"commit", "POST", "/v1/workspaces/ws-1/git/commits", `{"message":"message","author_name":"Owner","author_email":"owner@example.com"}`, opCreateCommit, 200, false},
		{"pull", "POST", "/v1/workspaces/ws-1/git/pull", "", opPullWorkspace, 200, false},
		{"push", "POST", "/v1/workspaces/ws-1/git/push", "", opPushWorkspace, 200, false},
		{"discard", "POST", "/v1/workspaces/ws-1/git/discard", `{"paths":["README.md"],"confirmed":true}`, opDiscardGitChanges, 200, false},
		{"pull request", "POST", "/v1/workspaces/ws-1/pull-requests", `{"title":"Title","body":"Body","base_branch":"main"}`, opCreatePullRequest, 201, false},
		{"checkpoints", "GET", "/v1/workspaces/ws-1/checkpoints", "", opListCheckpoints, 200, false},
		{"restore checkpoint file", "POST", "/v1/workspaces/ws-1/checkpoints/cp_20260716T010203.000000000Z_aaaaaaaaaaaaaaaaaaaaaaaa/restore-file", `{"path":"README.md","confirmed":true}`, opRestoreCheckpointFile, 200, false},
		{"restore checkpoint workspace", "POST", "/v1/workspaces/ws-1/checkpoints/cp_20260716T010203.000000000Z_aaaaaaaaaaaaaaaaaaaaaaaa/restore-workspace", `{"confirmed":true}`, opRestoreCheckpointWorkspace, 200, false},
		{"previews", "GET", "/v1/workspaces/ws-1/previews", "", opListPreviews, 200, false},
		{"preview access", "POST", "/v1/workspaces/ws-1/previews/access", `{"preview_id":"preview-1"}`, opCreatePreviewAccess, 201, false},
		{"revoke preview", "DELETE", "/v1/workspaces/ws-1/previews/preview-1/access", "", opRevokePreviewAccess, 204, false},
		{"maintenance", "GET", "/v1/maintenance", "", opGetMaintenance, 200, false},
		{"schedule maintenance", "POST", "/v1/maintenance/schedule", `{"urgent":false}`, opScheduleMaintenance, 202, false},
		{"cancel maintenance", "DELETE", "/v1/maintenance/maint-1", "", opCancelMaintenance, 200, false},
		{"advance maintenance", "POST", "/v1/maintenance/maint-1/actions", `{"action":"begin_update"}`, opAdvanceMaintenance, 200, false},
		{"diagnostics", "GET", "/v1/diagnostics", "", opGetDiagnostics, 200, false},
		{"settings", "GET", "/v1/settings", "", opGetSettings, 200, false},
		{"update settings", "PUT", "/v1/settings", `{"autonomy_default":"balanced","retention_default":"30_days","idle_timeout_minutes":30,"terminal_font_size":14,"terminal_theme":"dark","terminal_cursor_style":"block","quiet_hours_enabled":false,"notification_detail_enabled":false}`, opUpdateSettings, 200, false},
		{"push registration", "PUT", "/v1/devices/push", `{"token":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","environment":"sandbox","locale":"en-US"}`, opRegisterPushDevice, 204, false},
	}
	if len(cases) != 66 || len(routes) != 66 {
		t.Fatalf("route coverage mismatch: cases=%d routes=%d", len(cases), len(routes))
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			handler, application, authenticator, _ := newTestHandler(t)
			if !test.public {
				unauthenticated := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
				if test.body != "" {
					unauthenticated.Header.Set("Content-Type", "application/json")
				}
				unauthenticatedResponse := httptest.NewRecorder()
				handler.ServeHTTP(unauthenticatedResponse, unauthenticated)
				if unauthenticatedResponse.Code != http.StatusUnauthorized || application.last() != "" {
					t.Fatalf("protected operation was reachable without auth: %d %s", unauthenticatedResponse.Code, unauthenticatedResponse.Body.String())
				}
			}
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
			request.Header.Set("Accept", "application/json")
			if test.body != "" {
				request.Header.Set("Content-Type", "application/json")
			}
			if !test.public {
				request.Header.Set("Authorization", "Bearer "+testAccessToken)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || application.last() != test.operation {
				t.Fatalf("status=%d operation=%q body=%s", response.Code, application.last(), response.Body.String())
			}
			if test.operation == opCreateSecret || test.operation == opUpdateSecret {
				for _, value := range application.secretValue {
					if value != 0 {
						t.Fatal("transport retained secret plaintext after dispatch")
					}
				}
			}
			if test.operation == opStageTerminalAttachments {
				for _, value := range application.attachmentData {
					if value != 0 {
						t.Fatal("transport retained attachment bytes after dispatch")
					}
				}
			}
			if test.public && authenticator.calls != 0 {
				t.Fatal("public route invoked session authentication")
			}
			if !test.public {
				if authenticator.calls != 1 || authenticator.token != testAccessToken || application.principal != authenticator.principal {
					t.Fatalf("protected route auth mismatch: auth=%#v principal=%#v", authenticator, application.principal)
				}
			}
			if response.Header().Get("X-Content-Type-Options") != "nosniff" || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Request-ID") == "" {
				t.Fatalf("security headers missing: %#v", response.Header())
			}
			if test.status == http.StatusNoContent {
				if response.Body.Len() != 0 {
					t.Fatal("204 response contained a body")
				}
			} else if response.Header().Get("Content-Type") != "application/json" {
				t.Fatalf("unexpected content type %q", response.Header().Get("Content-Type"))
			}
		})
	}
}

func TestProtectedRoutesRejectMissingMalformedAndInvalidBearer(t *testing.T) {
	for _, test := range []struct {
		name    string
		header  []string
		authErr error
	}{
		{name: "missing"},
		{name: "short", header: []string{"Bearer short"}},
		{name: "basic", header: []string{"Basic " + testAccessToken}},
		{name: "multiple", header: []string{"Bearer " + testAccessToken, "Bearer " + testAccessToken}},
		{name: "rejected", header: []string{"Bearer " + testAccessToken}, authErr: errors.New("secret auth cause")},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler, application, authenticator, _ := newTestHandler(t)
			authenticator.err = test.authErr
			request := httptest.NewRequest(http.MethodGet, "/v1/settings", nil)
			for _, value := range test.header {
				request.Header.Add("Authorization", value)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized || application.last() != "" || !strings.HasPrefix(response.Header().Get("WWW-Authenticate"), "Bearer") {
				t.Fatalf("unexpected unauthorized response: %d %s", response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), "secret auth cause") {
				t.Fatal("authentication error was reflected")
			}
		})
	}
}

func TestPasskeyRevokeRequiresCanonicalBoundedCredentialID(t *testing.T) {
	t.Parallel()
	handler, application, _, _ := newTestHandler(t)
	for _, path := range []string{
		"/v1/passkeys/YQ=",
		"/v1/passkeys/" + strings.Repeat("a", 1_367),
		"/v1/passkeys/%25",
	} {
		request := httptest.NewRequest(http.MethodDelete, path, nil)
		request.Header.Set("Authorization", "Bearer "+testAccessToken)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || application.last() != "" {
			t.Fatalf("invalid credential path reached application: path=%q status=%d body=%s", path, response.Code, response.Body.String())
		}
	}
}

func TestConnectionRevocationRejectsMalformedIdentityAndUnconfirmedOrBroadInput(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		"/v1/connections/github/0",
		"/v1/connections/github/+42",
		"/v1/connections/github/042",
		"/v1/connections/github/9223372036854775808",
	} {
		handler, application, _, _ := newTestHandler(t)
		request := httptest.NewRequest(http.MethodDelete, path, nil)
		request.Header.Set("Authorization", "Bearer "+testAccessToken)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || application.last() != "" {
			t.Fatalf("malformed installation reached application: %s -> %d %s", path, response.Code, response.Body.String())
		}
	}
	for _, body := range []string{`{"confirmed":false}`, `{"confirmed":true,"credential":"secret"}`, `{}`, `null`} {
		handler, application, _, _ := newTestHandler(t)
		request := httptest.NewRequest(http.MethodDelete, "/v1/workspaces/ws-1/connections/codex", strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer "+testAccessToken)
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || application.last() != "" {
			t.Fatalf("invalid Codex disconnect reached application: %s -> %d %s", body, response.Code, response.Body.String())
		}
	}
}

func TestPublicAndTerminalRoutesBypassSessionAuthenticator(t *testing.T) {
	handler, application, authenticator, terminal := newTestHandler(t)
	authenticator.err = errors.New("must not be called")
	public := httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil)
	public.Header.Set("Authorization", "Bearer "+testAccessToken)
	publicResponse := httptest.NewRecorder()
	handler.ServeHTTP(publicResponse, public)
	if publicResponse.Code != http.StatusOK || application.last() != opGetCapabilities || authenticator.calls != 0 {
		t.Fatalf("public route required auth: %d", publicResponse.Code)
	}

	socket := httptest.NewRequest(http.MethodGet, TerminalWebSocketPath, nil)
	socket.Header.Set("Authorization", "Bearer "+strings.Repeat("t", 32))
	socket.Header.Set("Sec-WebSocket-Protocol", "codex-mobile-terminal-v1")
	socketResponse := httptest.NewRecorder()
	handler.ServeHTTP(socketResponse, socket)
	if socketResponse.Code != http.StatusSwitchingProtocols || terminal.calls != 1 || terminal.subprotocol != "codex-mobile-terminal-v1" || authenticator.calls != 0 {
		t.Fatalf("terminal route not reachable: status=%d calls=%d", socketResponse.Code, terminal.calls)
	}

	missingProtocol := httptest.NewRequest(http.MethodGet, TerminalWebSocketPath, nil)
	missingProtocol.Header.Set("Authorization", "Bearer "+strings.Repeat("t", 32))
	missingProtocolResponse := httptest.NewRecorder()
	handler.ServeHTTP(missingProtocolResponse, missingProtocol)
	if missingProtocolResponse.Code != http.StatusUpgradeRequired || terminal.calls != 1 {
		t.Fatalf("terminal subprotocol preflight failed: %d", missingProtocolResponse.Code)
	}
}

func TestMethodUnknownRouteAndUncleanPathUseProblems(t *testing.T) {
	handler, _, _, _ := newTestHandler(t)
	for _, test := range []struct {
		method, path string
		status       int
		allow        string
	}{
		{http.MethodPatch, "/v1/settings", http.StatusMethodNotAllowed, "GET, PUT"},
		{http.MethodHead, "/v1/capabilities", http.StatusMethodNotAllowed, "GET"},
		{http.MethodGet, "/v1/does-not-exist", http.StatusNotFound, ""},
		{http.MethodGet, "/v1//settings", http.StatusNotFound, ""},
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(test.method, test.path, nil))
		if response.Code != test.status || response.Header().Get("Content-Type") != "application/problem+json" || response.Header().Get("Allow") != test.allow {
			t.Fatalf("%s %s: status=%d allow=%q body=%s", test.method, test.path, response.Code, response.Header().Get("Allow"), response.Body.String())
		}
	}
}

func TestContentNegotiationAndRequestIDValidation(t *testing.T) {
	handler, application, _, _ := newTestHandler(t)
	var applicationRequestID string
	application.capabilityHook = func(ctx context.Context) error {
		applicationRequestID = RequestIDFromContext(ctx)
		return nil
	}
	rejected := httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil)
	rejected.Header.Set("Accept", "application/json;q=0, text/plain")
	rejectedResponse := httptest.NewRecorder()
	handler.ServeHTTP(rejectedResponse, rejected)
	if rejectedResponse.Code != http.StatusNotAcceptable || application.last() != "" {
		t.Fatalf("unacceptable response type was served: %d", rejectedResponse.Code)
	}

	accepted := httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil)
	accepted.Header.Set("Accept", "text/plain;q=0.2, application/json;q=0.8")
	accepted.Header.Set("X-Request-ID", "known-request-1")
	acceptedResponse := httptest.NewRecorder()
	handler.ServeHTTP(acceptedResponse, accepted)
	if acceptedResponse.Code != http.StatusOK || acceptedResponse.Header().Get("X-Request-ID") != "known-request-1" || applicationRequestID != "known-request-1" {
		t.Fatalf("valid negotiation/request ID failed: %d %#v", acceptedResponse.Code, acceptedResponse.Header())
	}

	invalidID := httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil)
	invalidID.Header.Set("X-Request-ID", "bad request id with spaces")
	invalidResponse := httptest.NewRecorder()
	handler.ServeHTTP(invalidResponse, invalidID)
	if value := invalidResponse.Header().Get("X-Request-ID"); value == "" || value == "bad request id with spaces" {
		t.Fatalf("unsafe request ID was reflected: %q", value)
	}
}

func TestStrictJSONQueryAndContentTypeValidation(t *testing.T) {
	cases := []struct {
		name        string
		method      string
		path        string
		body        string
		contentType string
	}{
		{"unknown field", "POST", "/v1/workspaces/ws-1/actions", `{"action":"suspend","refresh_token":"do-not-reflect"}`, "application/json"},
		{"duplicate field", "POST", "/v1/workspaces/ws-1/actions", `{"action":"suspend","action":"delete"}`, "application/json"},
		{"nested duplicate field", "POST", "/v1/workspaces", `{"repository_id":"repo-1","autonomy":"balanced","nested_docker":false,"retention":"30_days","environment_variables":{"KEY":"one","KEY":"two"}}`, "application/json"},
		{"missing required boolean", "POST", "/v1/workspaces", `{"repository_id":"repo-1","autonomy":"balanced","retention":"30_days","environment_variables":{}}`, "application/json"},
		{"disk below quota minimum", "POST", "/v1/workspaces", `{"repository_id":"repo-1","autonomy":"balanced","nested_docker":false,"retention":"30_days","environment_variables":{},"requested_disk_gi_b":7}`, "application/json"},
		{"disk above quota maximum", "POST", "/v1/workspaces", `{"repository_id":"repo-1","autonomy":"balanced","nested_docker":false,"retention":"30_days","environment_variables":{},"requested_disk_gi_b":17}`, "application/json"},
		{"trailing value", "POST", "/v1/workspaces/ws-1/actions", `{"action":"suspend"}{}`, "application/json"},
		{"wrong media type", "POST", "/v1/workspaces/ws-1/actions", `{"action":"suspend"}`, "text/plain"},
		{"missing media type", "POST", "/v1/workspaces/ws-1/actions", `{"action":"suspend"}`, ""},
		{"invalid enum", "POST", "/v1/workspaces/ws-1/actions", `{"action":"destroy_everything"}`, "application/json"},
		{"missing autonomy", "POST", "/v1/workspaces/ws-1/actions", `{"action":"update_autonomy"}`, "application/json"},
		{"invalid autonomy", "POST", "/v1/workspaces/ws-1/actions", `{"action":"update_autonomy","autonomy":"unbounded"}`, "application/json"},
		{"mixed autonomy policy", "POST", "/v1/workspaces/ws-1/actions", `{"action":"update_autonomy","autonomy":"safe","retention":"30_days","idle_timeout_minutes":30}`, "application/json"},
		{"unsafe path", "GET", "/v1/workspaces/ws-1/file?path=../secret", "", ""},
		{"unknown query", "GET", "/v1/settings?refresh_token=do-not-reflect", "", ""},
		{"invalid secret name", "POST", "/v1/secrets", `{"name":"BAD-NAME","value":"do-not-reflect-secret"}`, "application/json"},
		{"empty secret value", "POST", "/v1/secrets", `{"name":"TOKEN","value":""}`, "application/json"},
		{"unsafe terminal title", "PATCH", "/v1/workspaces/ws-1/terminal-tabs/tab-1", `{"title":"logs\nspoofed"}`, "application/json"},
		{"duplicate terminal order", "PUT", "/v1/workspaces/ws-1/terminal-tabs/order", `{"tab_ids":["tab-1","tab-1"]}`, "application/json"},
		{"empty terminal order", "PUT", "/v1/workspaces/ws-1/terminal-tabs/order", `{"tab_ids":[]}`, "application/json"},
		{"unconfirmed terminal close", "DELETE", "/v1/workspaces/ws-1/terminal-tabs/tab-1", `{"confirmed":false}`, "application/json"},
		{"missing terminal close confirmation", "DELETE", "/v1/workspaces/ws-1/terminal-tabs/tab-1", `{}`, "application/json"},
		{"attachment unknown field", "POST", "/v1/workspaces/ws-1/terminal-tabs/tab-1/attachments", `{"attachments":[{"media_type":"text/plain","content_base64":"aGVsbG8=","filename":"do-not-reflect"}]}`, "application/json"},
		{"attachment invalid base64", "POST", "/v1/workspaces/ws-1/terminal-tabs/tab-1/attachments", `{"attachments":[{"media_type":"text/plain","content_base64":"not base64"}]}`, "application/json"},
		{"attachment spoofed MIME", "POST", "/v1/workspaces/ws-1/terminal-tabs/tab-1/attachments", `{"attachments":[{"media_type":"image/png","content_base64":"IyEvYmluL3No"}]}`, "application/json"},
		{"attachment executable type", "POST", "/v1/workspaces/ws-1/terminal-tabs/tab-1/attachments", `{"attachments":[{"media_type":"application/x-executable","content_base64":"TVo="}]}`, "application/json"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			handler, application, _, _ := newTestHandler(t)
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
			request.Header.Set("Authorization", "Bearer "+testAccessToken)
			if test.contentType != "" {
				request.Header.Set("Content-Type", test.contentType)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code < 400 || application.last() != "" || response.Header().Get("Content-Type") != "application/problem+json" {
				t.Fatalf("invalid request accepted: %d %s", response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), "do-not-reflect") || strings.Contains(response.Body.String(), "refresh_token") || strings.Contains(response.Body.String(), "BAD-NAME") {
				t.Fatal("request secret or field was reflected")
			}
		})
	}
}

func TestRequestSizeLimitsAndFileException(t *testing.T) {
	handler, application, _, _ := newTestHandler(t)
	oversizedSecret := strings.Repeat("S", int(maximumJSONRequestBytes)+1)
	request := httptest.NewRequest(http.MethodPost, "/v1/auth/session/refresh", strings.NewReader(`{"refresh_token":"`+oversizedSecret+`"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge || strings.Contains(response.Body.String(), "SSSS") || application.last() != "" {
		t.Fatalf("ordinary request limit failed: %d %s", response.Code, response.Body.String())
	}

	fileContent := strings.Repeat("x", maximumFileContentBytes)
	fileBody, err := json.Marshal(SaveFileRequest{Content: fileContent, ExpectedETag: "etag"})
	if err != nil {
		t.Fatal(err)
	}
	fileRequest := httptest.NewRequest(http.MethodPut, "/v1/workspaces/ws-1/file?path=README.md", bytes.NewReader(fileBody))
	fileRequest.Header.Set("Authorization", "Bearer "+testAccessToken)
	fileRequest.Header.Set("Content-Type", "application/json")
	fileResponse := httptest.NewRecorder()
	handler.ServeHTTP(fileResponse, fileRequest)
	if fileResponse.Code != http.StatusOK || application.savedFileBytes != maximumFileContentBytes || application.last() != opSaveFile {
		t.Fatalf("8 MiB file exception failed: status=%d saved=%d body=%s", fileResponse.Code, application.savedFileBytes, fileResponse.Body.String())
	}

	tooLargeBody := strings.Repeat("x", maximumFileContentBytes+8192)
	tooLargeRequest := httptest.NewRequest(http.MethodPut, "/v1/workspaces/ws-1/file?path=README.md", strings.NewReader(`{"content":"`+tooLargeBody+`","expected_e_tag":"etag"}`))
	tooLargeRequest.Header.Set("Authorization", "Bearer "+testAccessToken)
	tooLargeRequest.Header.Set("Content-Type", "application/json")
	tooLargeResponse := httptest.NewRecorder()
	handler.ServeHTTP(tooLargeResponse, tooLargeRequest)
	if tooLargeResponse.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized file accepted: %d", tooLargeResponse.Code)
	}

	attachmentBody, err := json.Marshal(StageAttachmentsRequest{Attachments: []AttachmentUpload{{
		MediaType: "text/plain", Content: bytes.Repeat([]byte("a"), 5*1_024*1_024+1),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	attachmentRequest := httptest.NewRequest(http.MethodPost, "/v1/workspaces/ws-1/terminal-tabs/tab-1/attachments", bytes.NewReader(attachmentBody))
	attachmentRequest.Header.Set("Authorization", "Bearer "+testAccessToken)
	attachmentRequest.Header.Set("Content-Type", "application/json")
	attachmentResponse := httptest.NewRecorder()
	handler.ServeHTTP(attachmentResponse, attachmentRequest)
	if attachmentResponse.Code != http.StatusRequestEntityTooLarge || application.last() != opSaveFile {
		t.Fatalf("oversized attachment accepted: %d %s", attachmentResponse.Code, attachmentResponse.Body.String())
	}
}

func TestProblemMappingIsRFC9457AndDoesNotReflectArbitraryErrors(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"not found", core.ErrNotFound, 404, "not_found"},
		{"unauthorized", core.ErrUnauthorized, 401, "unauthorized"},
		{"refresh replay", session.ErrReplay, 401, "unauthorized"},
		{"forbidden", core.ErrForbidden, 403, "forbidden"},
		{"invalid", core.ErrInvalid, 400, "invalid_request"},
		{"conflict", core.ErrConflict, 409, "conflict"},
		{"precondition", core.ErrPrecondition, 412, "precondition_failed"},
		{"owner action", core.ErrOwnerActionNeeded, 423, "owner_action_required"},
		{"capacity", core.ErrCapacity, 503, "capacity_unavailable"},
		{"external", core.ErrExternal, 502, "external_provider_failure"},
		{"timeout", context.DeadlineExceeded, 504, "timeout"},
		{"generic", errors.New("TOP_SECRET_DATABASE_DETAIL"), 500, "internal_error"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler, application, _, _ := newTestHandler(t)
			application.err = test.err
			request := httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil)
			request.Header.Set("X-Request-ID", "request-123")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			var problem Problem
			if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
				t.Fatal(err)
			}
			if response.Code != test.status || problem.Status != test.status || problem.Code != test.code || problem.Type == "" || problem.Title == "" || problem.Instance != "urn:codex-mobile:request:request-123" {
				t.Fatalf("bad problem mapping: %#v", problem)
			}
			if test.code == "capacity_unavailable" && problem.Detail != "The service is temporarily at its safe capacity." {
				t.Fatalf("capacity response was not stable and resource-neutral: %#v", problem)
			}
			if strings.Contains(response.Body.String(), "TOP_SECRET") {
				t.Fatal("arbitrary internal error was reflected")
			}
		})
	}
}

func TestTerminalConnectionCapacityReturnsStableServiceUnavailable(t *testing.T) {
	handler, application, _, _ := newTestHandler(t)
	application.err = core.ErrCapacity
	request := httptest.NewRequest(http.MethodPost, "/v1/workspaces/ws-1/terminal-tabs/tab-1/connection", strings.NewReader(`{"after_sequence":0}`))
	request.Header.Set("Authorization", "Bearer "+testAccessToken)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	var problem Problem
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusServiceUnavailable || problem.Code != "capacity_unavailable" || problem.Detail != "The service is temporarily at its safe capacity." {
		t.Fatalf("terminal capacity response = status %d problem %#v", response.Code, problem)
	}
}

func TestRequestTimeoutAndResponseEncoding(t *testing.T) {
	handler, application, _, _ := newTestHandler(t)
	handler.restTimeout = 5 * time.Millisecond
	application.capabilityHook = func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil))
	if response.Code != http.StatusGatewayTimeout {
		t.Fatalf("timeout was not mapped: %d %s", response.Code, response.Body.String())
	}

	application.capabilityHook = nil
	application.err = nil
	application.capabilities = ClientCapabilities{GitHubConfigured: true, APNSConfigured: true, MaximumRunningWorkspaces: 2}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil))
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["github_configured"]; !ok {
		t.Fatalf("snake_case response missing: %s", response.Body.String())
	}
	if _, camel := raw["githubConfigured"]; camel {
		t.Fatalf("camelCase leaked onto wire: %s", response.Body.String())
	}
}

func TestApplicationPanicBecomesGenericProblem(t *testing.T) {
	handler, application, _, _ := newTestHandler(t)
	application.capabilityHook = func(context.Context) error {
		panic("TOP_SECRET_PANIC")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil))
	if response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), "TOP_SECRET") || response.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("panic was not contained: %d %s", response.Code, response.Body.String())
	}
}

func TestAllDTOFieldsHaveExplicitFrozenJSONNames(t *testing.T) {
	types := []any{
		Problem{}, HealthResponse{}, ClientCapabilities{}, BootstrapRegistrationRequest{}, DeviceIdentityRequest{}, PasskeyRegistrationChallenge{},
		PasskeyAuthenticationChallenge{}, PasskeyRegistrationCredential{}, PasskeyAssertionCredential{}, SessionTokens{}, PasskeyMetadata{},
		RefreshSessionRequest{}, DeviceSummary{}, RepositorySummary{}, ResourceShare{}, GitSummary{}, WorkspaceSummary{}, ProvisioningStep{},
		WorkspaceDetail{}, NewWorkspaceRequest{}, WorkspaceActionRequest{}, ActivityItem{}, ApprovalReview{},
		ApprovalDecisionRequest{}, TerminalTab{}, CreateTerminalTabRequest{}, RenameTerminalTabRequest{},
		ReorderTerminalTabsRequest{}, CloseTerminalTabRequest{}, TerminalConnectRequest{},
		TerminalConnectionDescriptor{}, FileEntry{}, FileDocument{}, SaveFileRequest{}, FileSearchResult{}, GitFileChange{},
		GitStatusDetail{}, DiffDocument{}, StageRequest{}, CommitRequest{}, PullRequestRequest{}, PullRequestResult{},
		GitOperationPrecondition{}, GitDiscardRequest{}, GitDiscardResult{}, CheckpointSummary{}, CheckpointRestoreFileRequest{},
		CheckpointRestoreWorkspaceRequest{}, CheckpointRestoreResult{},
		PreviewEndpoint{}, PreviewAccessRequest{}, PreviewAccess{}, UserSettings{}, PushDeviceRegistration{},
	}
	seen := make(map[string]string)
	for _, value := range types {
		typeOf := reflect.TypeOf(value)
		for index := 0; index < typeOf.NumField(); index++ {
			field := typeOf.Field(index)
			tag := strings.Split(field.Tag.Get("json"), ",")[0]
			if tag == "" || tag == "-" || tag != strings.ToLower(tag) || strings.Contains(tag, " ") {
				t.Fatalf("%s.%s has invalid JSON tag %q", typeOf.Name(), field.Name, tag)
			}
			key := typeOf.Name() + "." + field.Name
			seen[key] = tag
		}
	}
	expected := map[string]string{
		"SessionTokens.AccessExpiresAt":                  "access_expires_at",
		"WorkspaceSummary.PendingApprovalCount":          "pending_approval_count",
		"NewWorkspaceRequest.EnvironmentVariables":       "environment_variables",
		"TerminalConnectionDescriptor.MaximumFrameBytes": "maximum_frame_bytes",
		"SaveFileRequest.ExpectedETag":                   "expected_e_tag",
		"UserSettings.NotificationDetailEnabled":         "notification_detail_enabled",
	}
	keys := make([]string, 0, len(expected))
	for key := range expected {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if seen[key] != expected[key] {
			t.Fatalf("%s tag=%q want %q", key, seen[key], expected[key])
		}
	}
}

var _ Application = (*testApplication)(nil)
var _ Authenticator = (*testAuthenticator)(nil)
