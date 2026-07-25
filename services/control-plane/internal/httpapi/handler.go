package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	pathpkg "path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/session"
)

const TerminalWebSocketPath = "/v1/terminal"

const (
	defaultRESTTimeout   = 30 * time.Second
	defaultHealthTimeout = 5 * time.Second
)

type operation string

const (
	opHealth                              operation = "health"
	opGetCapabilities                     operation = "getCapabilities"
	opBeginPasskeyRegistration            operation = "beginPasskeyRegistration"
	opFinishPasskeyRegistration           operation = "finishPasskeyRegistration"
	opBeginPasskeyAuthentication          operation = "beginPasskeyAuthentication"
	opFinishPasskeyAuthentication         operation = "finishPasskeyAuthentication"
	opBeginAdditionalPasskeyRegistration  operation = "beginAdditionalPasskeyRegistration"
	opFinishAdditionalPasskeyRegistration operation = "finishAdditionalPasskeyRegistration"
	opListPasskeys                        operation = "listPasskeys"
	opRevokePasskey                       operation = "revokePasskey"
	opRefreshSession                      operation = "refreshSession"
	opRevokeCurrentSession                operation = "revokeCurrentSession"
	opListDevices                         operation = "listDevices"
	opRevokeDevice                        operation = "revokeDevice"
	opListSecrets                         operation = "listSecrets"
	opCreateSecret                        operation = "createSecret"
	opUpdateSecret                        operation = "updateSecret"
	opDeleteSecret                        operation = "deleteSecret"
	opListWorkspaceSecretGrants           operation = "listWorkspaceSecretGrants"
	opGrantWorkspaceSecret                operation = "grantWorkspaceSecret"
	opRevokeWorkspaceSecret               operation = "revokeWorkspaceSecret"
	opGetConnections                      operation = "getConnections"
	opDisconnectGitHub                    operation = "disconnectGitHub"
	opGetCodexConnection                  operation = "getCodexConnection"
	opDisconnectCodex                     operation = "disconnectCodex"
	opListRepositories                    operation = "listRepositories"
	opListWorkspaces                      operation = "listWorkspaces"
	opCreateWorkspace                     operation = "createWorkspace"
	opGetWorkspace                        operation = "getWorkspace"
	opPerformWorkspaceAction              operation = "performWorkspaceAction"
	opListActivity                        operation = "listActivity"
	opGetApproval                         operation = "getApproval"
	opResolveApproval                     operation = "resolveApproval"
	opListTerminalTabs                    operation = "listTerminalTabs"
	opCreateTerminalTab                   operation = "createTerminalTab"
	opRenameTerminalTab                   operation = "renameTerminalTab"
	opReorderTerminalTabs                 operation = "reorderTerminalTabs"
	opCloseTerminalTab                    operation = "closeTerminalTab"
	opCreateTerminalConnection            operation = "createTerminalConnection"
	opStageTerminalAttachments            operation = "stageTerminalAttachments"
	opGetFileTree                         operation = "getFileTree"
	opSearchFiles                         operation = "searchFiles"
	opGetFile                             operation = "getFile"
	opSaveFile                            operation = "saveFile"
	opGetGitStatus                        operation = "getGitStatus"
	opGetGitDiff                          operation = "getGitDiff"
	opSetGitStaged                        operation = "setGitStaged"
	opCreateCommit                        operation = "createCommit"
	opPullWorkspace                       operation = "pullWorkspace"
	opPushWorkspace                       operation = "pushWorkspace"
	opDiscardGitChanges                   operation = "discardGitChanges"
	opCreatePullRequest                   operation = "createPullRequest"
	opListCheckpoints                     operation = "listCheckpoints"
	opRestoreCheckpointFile               operation = "restoreCheckpointFile"
	opRestoreCheckpointWorkspace          operation = "restoreCheckpointWorkspace"
	opListPreviews                        operation = "listPreviews"
	opCreatePreviewAccess                 operation = "createPreviewAccess"
	opRevokePreviewAccess                 operation = "revokePreviewAccess"
	opGetMaintenance                      operation = "getMaintenance"
	opScheduleMaintenance                 operation = "scheduleMaintenance"
	opCancelMaintenance                   operation = "cancelMaintenance"
	opAdvanceMaintenance                  operation = "advanceMaintenance"
	opGetDiagnostics                      operation = "getDiagnostics"
	opGetSettings                         operation = "getSettings"
	opUpdateSettings                      operation = "updateSettings"
	opRegisterPushDevice                  operation = "registerPushDevice"
)

type route struct {
	method    string
	pattern   string
	operation operation
	protected bool
}

var routes = []route{
	{http.MethodGet, "/healthz", opHealth, false},
	{http.MethodGet, "/v1/capabilities", opGetCapabilities, false},
	{http.MethodPost, "/v1/auth/passkeys/registration/options", opBeginPasskeyRegistration, false},
	{http.MethodPost, "/v1/auth/passkeys/registration/verify", opFinishPasskeyRegistration, false},
	{http.MethodPost, "/v1/auth/passkeys/authentication/options", opBeginPasskeyAuthentication, false},
	{http.MethodPost, "/v1/auth/passkeys/authentication/verify", opFinishPasskeyAuthentication, false},
	{http.MethodPost, "/v1/passkeys/registration/options", opBeginAdditionalPasskeyRegistration, true},
	{http.MethodPost, "/v1/passkeys/registration/verify", opFinishAdditionalPasskeyRegistration, true},
	{http.MethodGet, "/v1/passkeys", opListPasskeys, true},
	{http.MethodDelete, "/v1/passkeys/{credential_id}", opRevokePasskey, true},
	{http.MethodPost, "/v1/auth/session/refresh", opRefreshSession, false},
	{http.MethodDelete, "/v1/auth/session", opRevokeCurrentSession, true},
	{http.MethodGet, "/v1/devices", opListDevices, true},
	{http.MethodDelete, "/v1/devices/{device_id}", opRevokeDevice, true},
	{http.MethodGet, "/v1/secrets", opListSecrets, true},
	{http.MethodPost, "/v1/secrets", opCreateSecret, true},
	{http.MethodPut, "/v1/secrets/{secret_id}", opUpdateSecret, true},
	{http.MethodDelete, "/v1/secrets/{secret_id}", opDeleteSecret, true},
	{http.MethodGet, "/v1/connections", opGetConnections, true},
	{http.MethodDelete, "/v1/connections/github/{installation_id}", opDisconnectGitHub, true},
	{http.MethodGet, "/v1/repositories", opListRepositories, true},
	{http.MethodGet, "/v1/workspaces", opListWorkspaces, true},
	{http.MethodPost, "/v1/workspaces", opCreateWorkspace, true},
	{http.MethodGet, "/v1/workspaces/{workspace_id}", opGetWorkspace, true},
	{http.MethodPost, "/v1/workspaces/{workspace_id}/actions", opPerformWorkspaceAction, true},
	{http.MethodGet, "/v1/workspaces/{workspace_id}/secret-grants", opListWorkspaceSecretGrants, true},
	{http.MethodPut, "/v1/workspaces/{workspace_id}/secret-grants/{secret_id}", opGrantWorkspaceSecret, true},
	{http.MethodDelete, "/v1/workspaces/{workspace_id}/secret-grants/{secret_id}", opRevokeWorkspaceSecret, true},
	{http.MethodGet, "/v1/workspaces/{workspace_id}/connections/codex", opGetCodexConnection, true},
	{http.MethodDelete, "/v1/workspaces/{workspace_id}/connections/codex", opDisconnectCodex, true},
	{http.MethodGet, "/v1/activity", opListActivity, true},
	{http.MethodGet, "/v1/approvals/{approval_id}", opGetApproval, true},
	{http.MethodPost, "/v1/approvals/{approval_id}/decision", opResolveApproval, true},
	{http.MethodGet, "/v1/workspaces/{workspace_id}/terminal-tabs", opListTerminalTabs, true},
	{http.MethodPost, "/v1/workspaces/{workspace_id}/terminal-tabs", opCreateTerminalTab, true},
	{http.MethodPut, "/v1/workspaces/{workspace_id}/terminal-tabs/order", opReorderTerminalTabs, true},
	{http.MethodPatch, "/v1/workspaces/{workspace_id}/terminal-tabs/{tab_id}", opRenameTerminalTab, true},
	{http.MethodDelete, "/v1/workspaces/{workspace_id}/terminal-tabs/{tab_id}", opCloseTerminalTab, true},
	{http.MethodPost, "/v1/workspaces/{workspace_id}/terminal-tabs/{tab_id}/connection", opCreateTerminalConnection, true},
	{http.MethodPost, "/v1/workspaces/{workspace_id}/terminal-tabs/{tab_id}/attachments", opStageTerminalAttachments, true},
	{http.MethodGet, "/v1/workspaces/{workspace_id}/files", opGetFileTree, true},
	{http.MethodGet, "/v1/workspaces/{workspace_id}/file-search", opSearchFiles, true},
	{http.MethodGet, "/v1/workspaces/{workspace_id}/file", opGetFile, true},
	{http.MethodPut, "/v1/workspaces/{workspace_id}/file", opSaveFile, true},
	{http.MethodGet, "/v1/workspaces/{workspace_id}/git/status", opGetGitStatus, true},
	{http.MethodGet, "/v1/workspaces/{workspace_id}/git/diff", opGetGitDiff, true},
	{http.MethodPost, "/v1/workspaces/{workspace_id}/git/stage", opSetGitStaged, true},
	{http.MethodPost, "/v1/workspaces/{workspace_id}/git/commits", opCreateCommit, true},
	{http.MethodPost, "/v1/workspaces/{workspace_id}/git/pull", opPullWorkspace, true},
	{http.MethodPost, "/v1/workspaces/{workspace_id}/git/push", opPushWorkspace, true},
	{http.MethodPost, "/v1/workspaces/{workspace_id}/git/discard", opDiscardGitChanges, true},
	{http.MethodPost, "/v1/workspaces/{workspace_id}/pull-requests", opCreatePullRequest, true},
	{http.MethodGet, "/v1/workspaces/{workspace_id}/checkpoints", opListCheckpoints, true},
	{http.MethodPost, "/v1/workspaces/{workspace_id}/checkpoints/{checkpoint_id}/restore-file", opRestoreCheckpointFile, true},
	{http.MethodPost, "/v1/workspaces/{workspace_id}/checkpoints/{checkpoint_id}/restore-workspace", opRestoreCheckpointWorkspace, true},
	{http.MethodGet, "/v1/workspaces/{workspace_id}/previews", opListPreviews, true},
	{http.MethodPost, "/v1/workspaces/{workspace_id}/previews/access", opCreatePreviewAccess, true},
	{http.MethodDelete, "/v1/workspaces/{workspace_id}/previews/{preview_id}/access", opRevokePreviewAccess, true},
	{http.MethodGet, "/v1/maintenance", opGetMaintenance, true},
	{http.MethodPost, "/v1/maintenance/schedule", opScheduleMaintenance, true},
	{http.MethodDelete, "/v1/maintenance/{maintenance_id}", opCancelMaintenance, true},
	{http.MethodPost, "/v1/maintenance/{maintenance_id}/actions", opAdvanceMaintenance, true},
	{http.MethodGet, "/v1/diagnostics", opGetDiagnostics, true},
	{http.MethodGet, "/v1/settings", opGetSettings, true},
	{http.MethodPut, "/v1/settings", opUpdateSettings, true},
	{http.MethodPut, "/v1/devices/push", opRegisterPushDevice, true},
}

type Handler struct {
	application   Application
	authenticator Authenticator
	terminal      http.Handler
	mux           *http.ServeMux
	restTimeout   time.Duration
	healthTimeout time.Duration
	metrics       HTTPMetrics
}

var _ http.Handler = (*Handler)(nil)

func New(options Options) (*Handler, error) {
	if options.Application == nil || options.Authenticator == nil || options.TerminalWebSocket == nil {
		return nil, errors.New("HTTP application, authenticator, and terminal WebSocket handler are required")
	}
	if options.RESTTimeout < 0 || options.HealthTimeout < 0 || options.RESTTimeout > 5*time.Minute || options.HealthTimeout > time.Minute {
		return nil, errors.New("invalid HTTP operation timeout")
	}
	if options.RESTTimeout == 0 {
		options.RESTTimeout = defaultRESTTimeout
	}
	if options.HealthTimeout == 0 {
		options.HealthTimeout = defaultHealthTimeout
	}
	handler := &Handler{
		application: options.Application, authenticator: options.Authenticator, terminal: options.TerminalWebSocket,
		mux: http.NewServeMux(), restTimeout: options.RESTTimeout, healthTimeout: options.HealthTimeout,
		metrics: options.Metrics,
	}
	handler.registerRoutes()
	return handler, nil
}

func (h *Handler) registerRoutes() {
	for _, definition := range routes {
		definition := definition
		h.mux.Handle(definition.method+" "+definition.pattern, h.rest(definition))
	}
	// The static push-registration path is reserved and must never be captured
	// as a device ID by the DELETE wildcard route.
	h.mux.Handle("DELETE /v1/devices/push", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.writeMethodNotAllowed(w, r, []string{http.MethodPut})
	}))
	h.mux.Handle("GET "+TerminalWebSocketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			h.writeMethodNotAllowed(w, r, []string{http.MethodGet})
			return
		}
		if !hasBearerCredential(r.Header.Values("Authorization")) {
			h.writeProblem(w, r, &ProblemError{Status: http.StatusUnauthorized, Code: "unauthorized", Title: "Unauthorized", Detail: "A valid one-use terminal ticket is required."})
			return
		}
		if !hasHeaderToken(r.Header.Values("Sec-WebSocket-Protocol"), "codex-mobile-terminal-v1") {
			h.writeProblem(w, r, &ProblemError{Status: http.StatusUpgradeRequired, Code: "terminal_subprotocol_required", Title: "WebSocket subprotocol required", Detail: "The codex-mobile-terminal-v1 subprotocol is required."})
			return
		}
		h.terminal.ServeHTTP(w, r)
	}))
	h.mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if methods := allowedMethods(r.URL.Path); len(methods) != 0 {
			h.writeMethodNotAllowed(w, r, methods)
			return
		}
		h.writeProblem(w, r, &ProblemError{Status: http.StatusNotFound, Code: "not_found", Title: "Not found", Detail: "The requested API route does not exist."})
	}))
}

func allowedMethods(path string) []string {
	if path == "/v1/devices/push" {
		return []string{http.MethodPut}
	}
	methods := make([]string, 0, 2)
	if path == TerminalWebSocketPath {
		methods = append(methods, http.MethodGet)
	}
	for _, definition := range routes {
		if routePathMatches(definition.pattern, path) {
			methods = append(methods, definition.method)
		}
	}
	return methods
}

func routePathMatches(pattern, path string) bool {
	patternParts := strings.Split(strings.Trim(pattern, "/"), "/")
	pathParts := strings.Split(strings.Trim(path, "/"), "/")
	if len(patternParts) != len(pathParts) {
		return false
	}
	for index := range patternParts {
		part := patternParts[index]
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			if pathParts[index] == "" {
				return false
			}
			continue
		}
		if part != pathParts[index] {
			return false
		}
	}
	return true
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := requestID(r.Header.Values("X-Request-ID"))
	w.Header().Set("X-Request-ID", requestID)
	setSecurityHeaders(w.Header())
	if r.URL.Path == "" || pathpkg.Clean(r.URL.Path) != r.URL.Path || strings.Contains(r.URL.EscapedPath(), "%2f") || strings.Contains(r.URL.EscapedPath(), "%2F") {
		r = r.WithContext(context.WithValue(r.Context(), requestIDContextKey{}, requestID))
		h.writeProblem(w, r, &ProblemError{Status: http.StatusNotFound, Code: "not_found", Title: "Not found", Detail: "The requested API route does not exist."})
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), requestIDContextKey{}, requestID))
	h.mux.ServeHTTP(w, r)
}

type requestIDContextKey struct{}

func RequestIDFromContext(ctx context.Context) string {
	value, _ := ctx.Value(requestIDContextKey{}).(string)
	return value
}

func (h *Handler) rest(definition route) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startedAt := time.Now()
		recorded := &statusRecorder{ResponseWriter: w}
		w = recorded
		defer func() {
			if h.metrics != nil {
				h.metrics.RecordHTTP(string(definition.operation), recorded.Status(), time.Since(startedAt))
			}
		}()
		defer func() {
			if recover() != nil {
				h.writeProblem(w, r, errors.New("application panic"))
			}
		}()
		if r.Method != definition.method {
			h.writeMethodNotAllowed(w, r, []string{definition.method})
			return
		}
		timeout := h.restTimeout
		if definition.operation == opHealth {
			timeout = h.healthTimeout
		}
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		r = r.WithContext(ctx)
		principal := Principal{}
		if definition.protected {
			var err error
			principal, err = h.authenticate(r)
			if err != nil {
				h.writeProblem(w, r, &ProblemError{Status: http.StatusUnauthorized, Code: "unauthorized", Title: "Unauthorized", Detail: "A valid bearer session is required."})
				return
			}
		}
		if !acceptsJSON(r.Header.Values("Accept")) {
			h.writeProblem(w, r, &ProblemError{Status: http.StatusNotAcceptable, Code: "not_acceptable", Title: "Not acceptable", Detail: "This endpoint returns JSON."})
			return
		}
		h.dispatch(w, r, principal, definition.operation)
	})
}

func (h *Handler) authenticate(r *http.Request) (Principal, error) {
	values := r.Header.Values("Authorization")
	if !hasBearerCredential(values) {
		return Principal{}, errors.New("missing bearer credential")
	}
	parts := strings.Fields(values[0])
	principal, err := h.authenticator.Authenticate(r.Context(), parts[1])
	if err != nil || !validIdentifier(principal.OwnerID) || !validIdentifier(principal.DeviceID) {
		return Principal{}, errors.New("invalid session")
	}
	return principal, nil
}

func hasBearerCredential(values []string) bool {
	if len(values) != 1 || strings.ContainsAny(values[0], "\r\n") {
		return false
	}
	parts := strings.Fields(values[0])
	return len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") && validText(parts[1], 32, 512)
}

func hasHeaderToken(values []string, expected string) bool {
	for _, value := range values {
		for _, token := range strings.Split(value, ",") {
			if strings.TrimSpace(token) == expected {
				return true
			}
		}
	}
	return false
}

func (h *Handler) dispatch(w http.ResponseWriter, r *http.Request, principal Principal, operation operation) {
	ctx := r.Context()
	switch operation {
	case opHealth:
		if err := noInput(r); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		if err := h.application.Health(ctx); err != nil {
			h.writeProblem(w, r, &ProblemError{Status: http.StatusServiceUnavailable, Code: "unhealthy", Title: "Service unavailable", Detail: "The control plane is not ready."})
			return
		}
		h.writeJSON(w, r, http.StatusOK, HealthResponse{Status: "ok"})
	case opGetCapabilities:
		if err := noInput(r); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.GetCapabilities(ctx)
		h.respond(w, r, http.StatusOK, value, err)
	case opBeginPasskeyRegistration:
		var input BootstrapRegistrationRequest
		if err := bodyInput(w, r, &input, maximumJSONRequestBytes, "bootstrap_token", "device_instance_id", "device_name"); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.BeginPasskeyRegistration(ctx, input)
		h.respond(w, r, http.StatusOK, value, err)
	case opFinishPasskeyRegistration:
		var input PasskeyRegistrationCredential
		if err := bodyInput(w, r, &input, maximumJSONRequestBytes, "ceremony_id", "credential_id", "raw_id", "client_data_json", "attestation_object", "device_instance_id", "device_name"); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.FinishPasskeyRegistration(ctx, input)
		h.respond(w, r, http.StatusOK, value, err)
	case opBeginPasskeyAuthentication:
		var input DeviceIdentityRequest
		if err := bodyInput(w, r, &input, maximumJSONRequestBytes, "device_instance_id", "device_name"); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.BeginPasskeyAuthentication(ctx, input)
		h.respond(w, r, http.StatusOK, value, err)
	case opFinishPasskeyAuthentication:
		var input PasskeyAssertionCredential
		if err := bodyInput(w, r, &input, maximumJSONRequestBytes, "ceremony_id", "credential_id", "raw_id", "client_data_json", "authenticator_data", "signature", "device_instance_id", "device_name"); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.FinishPasskeyAuthentication(ctx, input)
		h.respond(w, r, http.StatusOK, value, err)
	case opBeginAdditionalPasskeyRegistration:
		var input DeviceIdentityRequest
		if err := bodyInput(w, r, &input, maximumJSONRequestBytes, "device_instance_id", "device_name"); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.BeginAdditionalPasskeyRegistration(ctx, principal, input)
		h.respond(w, r, http.StatusOK, value, err)
	case opFinishAdditionalPasskeyRegistration:
		var input PasskeyRegistrationCredential
		if err := bodyInput(w, r, &input, maximumJSONRequestBytes, "ceremony_id", "credential_id", "raw_id", "client_data_json", "attestation_object", "device_instance_id", "device_name"); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.FinishAdditionalPasskeyRegistration(ctx, principal, input)
		h.respond(w, r, http.StatusCreated, value, err)
	case opListPasskeys:
		if err := noInput(r); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		values, err := h.application.ListPasskeys(ctx, principal)
		if values == nil {
			values = []PasskeyMetadata{}
		}
		h.respond(w, r, http.StatusOK, values, err)
	case opRevokePasskey:
		credentialID, err := pathCredentialID(r, "credential_id")
		if err == nil {
			err = noInput(r)
		}
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		h.respondEmpty(w, r, h.application.RevokePasskey(ctx, principal, credentialID))
	case opRefreshSession:
		var input RefreshSessionRequest
		if err := bodyInput(w, r, &input, maximumJSONRequestBytes, "refresh_token"); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.RefreshSession(ctx, input)
		h.respond(w, r, http.StatusOK, value, err)
	case opRevokeCurrentSession:
		if err := noInput(r); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		h.respondEmpty(w, r, h.application.RevokeCurrentSession(ctx, principal))
	case opListDevices:
		if err := noInput(r); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		values, err := h.application.ListDevices(ctx, principal)
		if values == nil {
			values = []DeviceSummary{}
		}
		h.respond(w, r, http.StatusOK, values, err)
	case opRevokeDevice:
		deviceID, err := pathIdentifier(r, "device_id")
		if err == nil {
			err = noInput(r)
		}
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		h.respondEmpty(w, r, h.application.RevokeDevice(ctx, principal, deviceID))
	case opListSecrets:
		repositoryID, err := optionalQuery(r, "repository_id", 128)
		if err == nil && repositoryID != nil && !validIdentifier(*repositoryID) {
			err = invalidRequest()
		}
		if err == nil {
			err = requireEmptyBody(r)
		}
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		values, err := h.application.ListSecrets(ctx, principal, repositoryID)
		if values == nil {
			values = []SecretMetadata{}
		}
		h.respond(w, r, http.StatusOK, values, err)
	case opCreateSecret:
		var input CreateSecretRequest
		err := bodyInput(w, r, &input, maximumJSONRequestBytes, "name", "value")
		defer input.Value.Wipe()
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.CreateSecret(ctx, principal, input)
		h.respond(w, r, http.StatusCreated, value, err)
	case opUpdateSecret:
		secretID, err := pathIdentifier(r, "secret_id")
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		var input UpdateSecretRequest
		err = bodyInput(w, r, &input, maximumJSONRequestBytes, "value")
		defer input.Value.Wipe()
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.UpdateSecret(ctx, principal, secretID, input)
		h.respond(w, r, http.StatusOK, value, err)
	case opDeleteSecret:
		secretID, err := pathIdentifier(r, "secret_id")
		if err == nil {
			err = noInput(r)
		}
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		h.respondEmpty(w, r, h.application.DeleteSecret(ctx, principal, secretID))
	case opListWorkspaceSecretGrants:
		workspaceID, err := pathIdentifier(r, "workspace_id")
		if err == nil {
			err = noInput(r)
		}
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		values, err := h.application.ListWorkspaceSecretGrants(ctx, principal, workspaceID)
		if values == nil {
			values = []WorkspaceSecretGrant{}
		}
		h.respond(w, r, http.StatusOK, values, err)
	case opGrantWorkspaceSecret, opRevokeWorkspaceSecret:
		workspaceID, err := pathIdentifier(r, "workspace_id")
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		secretID, err := pathIdentifier(r, "secret_id")
		if err == nil {
			err = noInput(r)
		}
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		if operation == opGrantWorkspaceSecret {
			err = h.application.GrantWorkspaceSecret(ctx, principal, workspaceID, secretID)
		} else {
			err = h.application.RevokeWorkspaceSecret(ctx, principal, workspaceID, secretID)
		}
		h.respondEmpty(w, r, err)
	case opGetConnections:
		if err := noInput(r); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.GetConnections(ctx, principal)
		h.respond(w, r, http.StatusOK, value, err)
	case opDisconnectGitHub:
		installationID, err := pathPositiveInt64(r, "installation_id")
		if err == nil {
			err = noInput(r)
		}
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		h.respondEmpty(w, r, h.application.DisconnectGitHub(ctx, principal, installationID))
	case opGetCodexConnection:
		workspaceID, err := pathIdentifier(r, "workspace_id")
		if err == nil {
			err = noInput(r)
		}
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.GetCodexConnection(ctx, principal, workspaceID)
		h.respond(w, r, http.StatusOK, value, err)
	case opDisconnectCodex:
		workspaceID, err := pathIdentifier(r, "workspace_id")
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		var input ConfirmConnectionDisconnectRequest
		if err := bodyInput(w, r, &input, maximumJSONRequestBytes, "confirmed"); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		h.respondEmpty(w, r, h.application.DisconnectCodex(ctx, principal, workspaceID, input))
	case opListRepositories:
		search, err := optionalQuery(r, "search", 200)
		if err == nil {
			err = requireEmptyBody(r)
		}
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		values, err := h.application.ListRepositories(ctx, principal, search)
		if values == nil {
			values = []RepositorySummary{}
		}
		h.respond(w, r, http.StatusOK, values, err)
	case opListWorkspaces:
		if err := noInput(r); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		values, err := h.application.ListWorkspaces(ctx, principal)
		if values == nil {
			values = []WorkspaceSummary{}
		}
		h.respond(w, r, http.StatusOK, values, err)
	case opCreateWorkspace:
		var input NewWorkspaceRequest
		if err := bodyInput(w, r, &input, maximumJSONRequestBytes, "repository_id", "autonomy", "nested_docker", "retention", "environment_variables"); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.CreateWorkspace(ctx, principal, input)
		h.respond(w, r, http.StatusAccepted, value, err)
	case opGetWorkspace:
		workspaceID, err := pathIdentifier(r, "workspace_id")
		if err == nil {
			err = noInput(r)
		}
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.GetWorkspace(ctx, principal, workspaceID)
		h.respond(w, r, http.StatusOK, value, err)
	case opPerformWorkspaceAction:
		workspaceID, err := pathIdentifier(r, "workspace_id")
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		var input WorkspaceActionRequest
		if err := bodyInput(w, r, &input, maximumJSONRequestBytes, "action"); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.PerformWorkspaceAction(ctx, principal, workspaceID, input)
		status := http.StatusOK
		if value.Accepted {
			status = http.StatusAccepted
		}
		h.respond(w, r, status, value.Workspace, err)
	case opListActivity:
		if err := noInput(r); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		values, err := h.application.ListActivity(ctx, principal)
		if values == nil {
			values = []ActivityItem{}
		}
		h.respond(w, r, http.StatusOK, values, err)
	case opGetApproval:
		approvalID, err := pathIdentifier(r, "approval_id")
		if err == nil {
			err = noInput(r)
		}
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.GetApproval(ctx, principal, approvalID)
		h.respond(w, r, http.StatusOK, value, err)
	case opResolveApproval:
		approvalID, err := pathIdentifier(r, "approval_id")
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		var input ApprovalDecisionRequest
		if err := bodyInput(w, r, &input, maximumJSONRequestBytes, "decision"); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.ResolveApproval(ctx, principal, approvalID, input)
		h.respond(w, r, http.StatusOK, value, err)
	case opListTerminalTabs:
		workspaceID, err := pathIdentifier(r, "workspace_id")
		if err == nil {
			err = noInput(r)
		}
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		values, err := h.application.ListTerminalTabs(ctx, principal, workspaceID)
		if values == nil {
			values = []TerminalTab{}
		}
		h.respond(w, r, http.StatusOK, values, err)
	case opCreateTerminalTab:
		workspaceID, err := pathIdentifier(r, "workspace_id")
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		var input CreateTerminalTabRequest
		if err := bodyInput(w, r, &input, maximumJSONRequestBytes, "kind"); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.CreateTerminalTab(ctx, principal, workspaceID, input)
		h.respond(w, r, http.StatusCreated, value, err)
	case opRenameTerminalTab:
		workspaceID, err := pathIdentifier(r, "workspace_id")
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		tabID, err := pathIdentifier(r, "tab_id")
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		var input RenameTerminalTabRequest
		if err := bodyInput(w, r, &input, maximumJSONRequestBytes, "title"); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.RenameTerminalTab(ctx, principal, workspaceID, tabID, input)
		h.respond(w, r, http.StatusOK, value, err)
	case opReorderTerminalTabs:
		workspaceID, err := pathIdentifier(r, "workspace_id")
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		var input ReorderTerminalTabsRequest
		if err := bodyInput(w, r, &input, maximumJSONRequestBytes, "tab_ids"); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		values, err := h.application.ReorderTerminalTabs(ctx, principal, workspaceID, input)
		if values == nil {
			values = []TerminalTab{}
		}
		h.respond(w, r, http.StatusOK, values, err)
	case opCloseTerminalTab:
		workspaceID, err := pathIdentifier(r, "workspace_id")
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		tabID, err := pathIdentifier(r, "tab_id")
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		var input CloseTerminalTabRequest
		if err := bodyInput(w, r, &input, maximumJSONRequestBytes, "confirmed"); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		err = h.application.CloseTerminalTab(ctx, principal, workspaceID, tabID, input)
		h.respondEmpty(w, r, err)
	case opCreateTerminalConnection:
		workspaceID, err := pathIdentifier(r, "workspace_id")
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		tabID, err := pathIdentifier(r, "tab_id")
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		var input TerminalConnectRequest
		if err := bodyInput(w, r, &input, maximumJSONRequestBytes, "after_sequence"); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.CreateTerminalConnection(ctx, principal, workspaceID, tabID, input)
		h.respond(w, r, http.StatusOK, value, err)
	case opStageTerminalAttachments:
		workspaceID, err := pathIdentifier(r, "workspace_id")
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		tabID, err := pathIdentifier(r, "tab_id")
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		var input StageAttachmentsRequest
		defer input.Wipe()
		if err := bodyInput(w, r, &input, maximumAttachmentRequestBytes, "attachments"); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.StageTerminalAttachments(ctx, principal, workspaceID, tabID, input)
		h.respond(w, r, http.StatusCreated, value, err)
	case opGetFileTree:
		workspaceID, err := pathIdentifier(r, "workspace_id")
		if err == nil {
			err = noInput(r)
		}
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		values, err := h.application.GetFileTree(ctx, principal, workspaceID)
		if values == nil {
			values = []FileEntry{}
		}
		h.respond(w, r, http.StatusOK, values, err)
	case opSearchFiles:
		workspaceID, err := pathIdentifier(r, "workspace_id")
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		query, err := requiredQuery(r, "query", 256)
		if err == nil {
			err = requireEmptyBody(r)
		}
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		values, err := h.application.SearchFiles(ctx, principal, workspaceID, query)
		if values == nil {
			values = []FileSearchResult{}
		}
		h.respond(w, r, http.StatusOK, values, err)
	case opGetFile:
		workspaceID, err := pathIdentifier(r, "workspace_id")
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		filePath, err := requiredQuery(r, "path", 4096)
		if err == nil && !validRelativePath(filePath) {
			err = invalidRequest()
		}
		if err == nil {
			err = requireEmptyBody(r)
		}
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.GetFile(ctx, principal, workspaceID, filePath)
		h.respond(w, r, http.StatusOK, value, err)
	case opSaveFile:
		workspaceID, err := pathIdentifier(r, "workspace_id")
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		filePath, err := requiredQuery(r, "path", 4096)
		if err != nil || !validRelativePath(filePath) {
			h.writeProblem(w, r, invalidRequest())
			return
		}
		var input SaveFileRequest
		if err := bodyInputAfterQuery(w, r, &input, maximumFileRequestBytes, "content", "expected_e_tag"); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.SaveFile(ctx, principal, workspaceID, filePath, input)
		h.respond(w, r, http.StatusOK, value, err)
	case opGetGitStatus:
		workspaceID, err := pathIdentifier(r, "workspace_id")
		if err == nil {
			err = noInput(r)
		}
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.GetGitStatus(ctx, principal, workspaceID)
		h.respond(w, r, http.StatusOK, value, err)
	case opGetGitDiff:
		workspaceID, err := pathIdentifier(r, "workspace_id")
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		filePath, err := requiredQuery(r, "path", 4096)
		if err == nil && !validRelativePath(filePath) {
			err = invalidRequest()
		}
		if err == nil {
			err = requireEmptyBody(r)
		}
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.GetGitDiff(ctx, principal, workspaceID, filePath)
		h.respond(w, r, http.StatusOK, value, err)
	case opSetGitStaged:
		workspaceID, err := pathIdentifier(r, "workspace_id")
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		var input StageRequest
		if err := bodyInput(w, r, &input, maximumJSONRequestBytes, "path", "staged"); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.SetGitStaged(ctx, principal, workspaceID, input)
		h.respond(w, r, http.StatusOK, value, err)
	case opCreateCommit:
		workspaceID, err := pathIdentifier(r, "workspace_id")
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		var input CommitRequest
		if err := bodyInput(w, r, &input, maximumJSONRequestBytes, "message", "author_name", "author_email"); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.CreateCommit(ctx, principal, workspaceID, input)
		h.respond(w, r, http.StatusOK, value, err)
	case opPullWorkspace:
		workspaceID, err := pathIdentifier(r, "workspace_id")
		if err == nil {
			err = noInput(r)
		}
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.PullWorkspace(ctx, principal, workspaceID)
		h.respond(w, r, http.StatusOK, value, err)
	case opPushWorkspace:
		workspaceID, err := pathIdentifier(r, "workspace_id")
		if err == nil {
			err = noInput(r)
		}
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.PushWorkspace(ctx, principal, workspaceID)
		h.respond(w, r, http.StatusOK, value, err)
	case opDiscardGitChanges:
		workspaceID, err := pathIdentifier(r, "workspace_id")
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		var input GitDiscardRequest
		if err := bodyInput(w, r, &input, maximumJSONRequestBytes, "paths", "confirmed"); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.DiscardGitChanges(ctx, principal, workspaceID, input)
		h.respond(w, r, http.StatusOK, value, err)
	case opCreatePullRequest:
		workspaceID, err := pathIdentifier(r, "workspace_id")
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		var input PullRequestRequest
		if err := bodyInput(w, r, &input, maximumJSONRequestBytes, "title", "body", "base_branch"); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.CreatePullRequest(ctx, principal, workspaceID, input)
		h.respond(w, r, http.StatusCreated, value, err)
	case opListCheckpoints:
		workspaceID, err := pathIdentifier(r, "workspace_id")
		if err == nil {
			err = noInput(r)
		}
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		values, err := h.application.ListCheckpoints(ctx, principal, workspaceID)
		if values == nil {
			values = []CheckpointSummary{}
		}
		h.respond(w, r, http.StatusOK, values, err)
	case opRestoreCheckpointFile:
		workspaceID, err := pathIdentifier(r, "workspace_id")
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		checkpointID, err := pathIdentifier(r, "checkpoint_id")
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		var input CheckpointRestoreFileRequest
		if err := bodyInput(w, r, &input, maximumJSONRequestBytes, "path", "confirmed"); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.RestoreCheckpointFile(ctx, principal, workspaceID, checkpointID, input)
		h.respond(w, r, http.StatusOK, value, err)
	case opRestoreCheckpointWorkspace:
		workspaceID, err := pathIdentifier(r, "workspace_id")
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		checkpointID, err := pathIdentifier(r, "checkpoint_id")
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		var input CheckpointRestoreWorkspaceRequest
		if err := bodyInput(w, r, &input, maximumJSONRequestBytes, "confirmed"); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.RestoreCheckpointWorkspace(ctx, principal, workspaceID, checkpointID, input)
		h.respond(w, r, http.StatusOK, value, err)
	case opListPreviews:
		workspaceID, err := pathIdentifier(r, "workspace_id")
		if err == nil {
			err = noInput(r)
		}
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		values, err := h.application.ListPreviews(ctx, principal, workspaceID)
		if values == nil {
			values = []PreviewEndpoint{}
		}
		h.respond(w, r, http.StatusOK, values, err)
	case opCreatePreviewAccess:
		workspaceID, err := pathIdentifier(r, "workspace_id")
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		var input PreviewAccessRequest
		if err := bodyInput(w, r, &input, maximumJSONRequestBytes, "preview_id"); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.CreatePreviewAccess(ctx, principal, workspaceID, input)
		h.respond(w, r, http.StatusCreated, value, err)
	case opRevokePreviewAccess:
		workspaceID, err := pathIdentifier(r, "workspace_id")
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		previewID, err := pathIdentifier(r, "preview_id")
		if err == nil {
			err = noInput(r)
		}
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		h.respondEmpty(w, r, h.application.RevokePreviewAccess(ctx, principal, workspaceID, previewID))
	case opGetMaintenance:
		if err := noInput(r); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.GetMaintenance(ctx, principal)
		h.respond(w, r, http.StatusOK, value, err)
	case opScheduleMaintenance:
		var input ScheduleMaintenanceRequest
		if err := bodyInput(w, r, &input, maximumJSONRequestBytes, "urgent"); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.ScheduleMaintenance(ctx, principal, input)
		h.respond(w, r, http.StatusAccepted, value, err)
	case opCancelMaintenance:
		runID, err := pathIdentifier(r, "maintenance_id")
		if err == nil {
			err = noInput(r)
		}
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.CancelMaintenance(ctx, principal, runID)
		h.respond(w, r, http.StatusOK, value, err)
	case opAdvanceMaintenance:
		runID, err := pathIdentifier(r, "maintenance_id")
		if err != nil {
			h.writeProblem(w, r, err)
			return
		}
		var input MaintenanceActionRequest
		if err := bodyInput(w, r, &input, maximumJSONRequestBytes, "action"); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.AdvanceMaintenance(ctx, principal, runID, input)
		h.respond(w, r, http.StatusOK, value, err)
	case opGetDiagnostics:
		if err := noInput(r); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.GetDiagnostics(ctx, principal)
		h.respond(w, r, http.StatusOK, value, err)
	case opGetSettings:
		if err := noInput(r); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.GetSettings(ctx, principal)
		h.respond(w, r, http.StatusOK, value, err)
	case opUpdateSettings:
		var input UserSettings
		if err := bodyInput(w, r, &input, maximumJSONRequestBytes,
			"autonomy_default", "retention_default", "idle_timeout_minutes", "terminal_font_size", "terminal_theme",
			"terminal_cursor_style", "quiet_hours_enabled", "notification_detail_enabled"); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		value, err := h.application.UpdateSettings(ctx, principal, input)
		h.respond(w, r, http.StatusOK, value, err)
	case opRegisterPushDevice:
		var input PushDeviceRegistration
		if err := bodyInput(w, r, &input, maximumJSONRequestBytes, "token", "environment", "locale"); err != nil {
			h.writeProblem(w, r, err)
			return
		}
		h.respondEmpty(w, r, h.application.RegisterPushDevice(ctx, principal, input))
	default:
		h.writeProblem(w, r, errors.New("unknown HTTP operation"))
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (w *statusRecorder) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusRecorder) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

func (w *statusRecorder) Status() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

func noInput(r *http.Request) error {
	if err := validateQuery(r); err != nil {
		return err
	}
	return requireEmptyBody(r)
}

type requestValidator interface {
	validate() error
}

func bodyInput[T requestValidator](w http.ResponseWriter, r *http.Request, destination *T, limit int64, required ...string) error {
	if err := validateQuery(r); err != nil {
		return err
	}
	return bodyInputAfterQuery(w, r, destination, limit, required...)
}

func bodyInputAfterQuery[T requestValidator](w http.ResponseWriter, r *http.Request, destination *T, limit int64, required ...string) error {
	if err := decodeJSON(w, r, destination, limit, required...); err != nil {
		return err
	}
	return (*destination).validate()
}

func pathIdentifier(r *http.Request, name string) (string, error) {
	value := r.PathValue(name)
	if !validIdentifier(value) {
		return "", invalidRequest()
	}
	return value, nil
}

func pathCredentialID(r *http.Request, name string) (string, error) {
	value := r.PathValue(name)
	if !validCredentialID(value) {
		return "", invalidRequest()
	}
	return value, nil
}

func pathPositiveInt64(r *http.Request, name string) (int64, error) {
	value := r.PathValue(name)
	if value == "" || strings.HasPrefix(value, "+") || (len(value) > 1 && value[0] == '0') {
		return 0, invalidRequest()
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 {
		return 0, invalidRequest()
	}
	return parsed, nil
}

func (h *Handler) respond(w http.ResponseWriter, r *http.Request, status int, value any, err error) {
	if err != nil {
		h.writeProblem(w, r, err)
		return
	}
	h.writeJSON(w, r, status, value)
}

func (h *Handler) respondEmpty(w http.ResponseWriter, r *http.Request, err error) {
	if err != nil {
		h.writeProblem(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) writeJSON(w http.ResponseWriter, r *http.Request, status int, value any) {
	encoded, err := json.Marshal(value)
	if err != nil {
		h.writeProblem(w, r, errors.New("encode response"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(encoded)
}

func (h *Handler) writeProblem(w http.ResponseWriter, r *http.Request, err error) {
	problem := mapProblem(err)
	problem.Instance = "urn:codex-mobile:request:" + RequestIDFromContext(r.Context())
	if problem.Status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="codex-mobile"`)
	}
	encoded, marshalErr := json.Marshal(problem)
	if marshalErr != nil {
		encoded = []byte(`{"type":"urn:codex-mobile:problem:internal_error","title":"Internal server error","status":500,"code":"internal_error"}`)
		problem.Status = http.StatusInternalServerError
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(problem.Status)
	_, _ = w.Write(encoded)
}

func (h *Handler) writeMethodNotAllowed(w http.ResponseWriter, r *http.Request, methods []string) {
	w.Header().Set("Allow", strings.Join(methods, ", "))
	h.writeProblem(w, r, &ProblemError{Status: http.StatusMethodNotAllowed, Code: "method_not_allowed", Title: "Method not allowed", Detail: "The requested method is not supported for this route."})
}

func mapProblem(err error) Problem {
	internal := Problem{Type: "urn:codex-mobile:problem:internal_error", Title: "Internal server error", Status: http.StatusInternalServerError, Detail: "The control plane could not complete the request.", Code: "internal_error"}
	if err == nil {
		return internal
	}
	var public *ProblemError
	if errors.As(err, &public) && public.Status >= 400 && public.Status <= 599 && validProblemCode(public.Code) && validText(public.Title, 1, 200) && validText(public.Detail, 0, 4096) && validGitProblem(public.GitPrecondition) {
		return Problem{Type: "urn:codex-mobile:problem:" + public.Code, Title: public.Title, Status: public.Status, Detail: public.Detail, Code: public.Code, GitPrecondition: public.GitPrecondition}
	}
	switch {
	case errors.Is(err, core.ErrNotFound):
		return Problem{Type: "urn:codex-mobile:problem:not_found", Title: "Not found", Status: http.StatusNotFound, Detail: "The requested resource was not found.", Code: "not_found"}
	case errors.Is(err, core.ErrUnauthorized), errors.Is(err, session.ErrReplay):
		return Problem{Type: "urn:codex-mobile:problem:unauthorized", Title: "Unauthorized", Status: http.StatusUnauthorized, Detail: "A valid bearer session is required.", Code: "unauthorized"}
	case errors.Is(err, core.ErrForbidden):
		return Problem{Type: "urn:codex-mobile:problem:forbidden", Title: "Forbidden", Status: http.StatusForbidden, Detail: "The authenticated device cannot perform this operation.", Code: "forbidden"}
	case errors.Is(err, core.ErrInvalid):
		return Problem{Type: "urn:codex-mobile:problem:invalid_request", Title: "Invalid request", Status: http.StatusBadRequest, Detail: "The request did not match the API contract.", Code: "invalid_request"}
	case errors.Is(err, core.ErrConflict):
		return Problem{Type: "urn:codex-mobile:problem:conflict", Title: "Conflict", Status: http.StatusConflict, Detail: "The operation conflicts with the current resource state.", Code: "conflict"}
	case errors.Is(err, core.ErrPrecondition):
		return Problem{Type: "urn:codex-mobile:problem:precondition_failed", Title: "Precondition failed", Status: http.StatusPreconditionFailed, Detail: "A required resource precondition was not met.", Code: "precondition_failed"}
	case errors.Is(err, core.ErrOwnerActionNeeded):
		return Problem{Type: "urn:codex-mobile:problem:owner_action_required", Title: "Owner action required", Status: http.StatusLocked, Detail: "The owner must review this operation before it can continue.", Code: "owner_action_required"}
	case errors.Is(err, core.ErrCapacity):
		return Problem{Type: "urn:codex-mobile:problem:capacity_unavailable", Title: "Capacity unavailable", Status: http.StatusServiceUnavailable, Detail: "The service is temporarily at its safe capacity.", Code: "capacity_unavailable"}
	case errors.Is(err, core.ErrExternal):
		return Problem{Type: "urn:codex-mobile:problem:external_provider_failure", Title: "External provider failure", Status: http.StatusBadGateway, Detail: "An external provider could not complete the operation.", Code: "external_provider_failure"}
	case errors.Is(err, context.DeadlineExceeded):
		return Problem{Type: "urn:codex-mobile:problem:timeout", Title: "Gateway timeout", Status: http.StatusGatewayTimeout, Detail: "The operation exceeded its safe time limit.", Code: "timeout"}
	case errors.Is(err, context.Canceled):
		return Problem{Type: "urn:codex-mobile:problem:request_cancelled", Title: "Request cancelled", Status: http.StatusRequestTimeout, Detail: "The request was cancelled before completion.", Code: "request_cancelled"}
	default:
		return internal
	}
}

func validGitProblem(value *GitOperationPrecondition) bool {
	return value == nil || (value.Ahead >= 0 && value.Behind >= 0 && validText(value.Reason, 1, 100) && validText(value.TerminalFallback, 1, 1000))
}

var problemCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,99}$`)

func validProblemCode(value string) bool { return problemCodePattern.MatchString(value) }

func setSecurityHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("Pragma", "no-cache")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	header.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
	header.Set("Cross-Origin-Resource-Policy", "same-origin")
	header.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
}

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

func requestID(values []string) string {
	if len(values) == 1 && requestIDPattern.MatchString(values[0]) {
		return values[0]
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err == nil {
		return hex.EncodeToString(random)
	}
	return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
}

func acceptsJSON(values []string) bool {
	if len(values) == 0 {
		return true
	}
	for _, header := range values {
		for _, part := range strings.Split(header, ",") {
			mediaType, parameters, err := mime.ParseMediaType(strings.TrimSpace(part))
			if err != nil {
				continue
			}
			if rawQuality, present := parameters["q"]; present {
				quality, err := strconv.ParseFloat(rawQuality, 64)
				if err != nil || quality <= 0 || quality > 1 {
					continue
				}
			}
			if mediaType == "*/*" || mediaType == "application/*" || mediaType == "application/json" || mediaType == "application/problem+json" {
				return true
			}
		}
	}
	return false
}
