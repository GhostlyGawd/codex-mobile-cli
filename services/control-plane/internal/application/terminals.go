package application

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/coder"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/httpapi"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/postgres"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/session"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/terminal"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/workspacehelper"
)

const defaultTerminalRuntimeSetupTimeout = 30 * time.Second

func (a *Application) ListTerminalTabs(ctx context.Context, principal httpapi.Principal, workspaceID string) ([]httpapi.TerminalTab, error) {
	if _, err := a.deps.WorkspaceStore.Get(ctx, principal.OwnerID, workspaceID); err != nil {
		return nil, err
	}
	records, err := a.deps.State.ListTerminalTabs(ctx, principal.OwnerID, workspaceID)
	if err != nil {
		return nil, err
	}
	a.runtimeMu.Lock()
	defer a.runtimeMu.Unlock()
	result := make([]httpapi.TerminalTab, 0, len(records))
	for _, record := range records {
		result = append(result, terminalTab(record, a.running[record.ID]))
	}
	return result, nil
}

func (a *Application) CreateTerminalTab(ctx context.Context, principal httpapi.Principal, workspaceID string, request httpapi.CreateTerminalTabRequest) (httpapi.TerminalTab, error) {
	releaseMutation := a.acquireWorkspaceMutation(workspaceID)
	defer releaseMutation()

	value, err := a.helperWorkspace(ctx, principal.OwnerID, workspaceID)
	if err != nil {
		return httpapi.TerminalTab{}, err
	}
	records, err := a.deps.State.ListTerminalTabs(ctx, principal.OwnerID, workspaceID)
	if err != nil {
		return httpapi.TerminalTab{}, err
	}
	if err := a.touchWorkspace(ctx, value); err != nil {
		return httpapi.TerminalTab{}, err
	}
	if len(records) >= 64 {
		return httpapi.TerminalTab{}, fmt.Errorf("%w: terminal tab limit reached", core.ErrCapacity)
	}
	if !validTerminalKind(request.Kind) {
		return httpapi.TerminalTab{}, invalid(errors.New("unsupported terminal kind"))
	}
	tabID, err := terminal.NewTabID()
	if err != nil {
		return httpapi.TerminalTab{}, err
	}
	reconnectID, err := terminal.NewTabID()
	if err != nil {
		return httpapi.TerminalTab{}, err
	}
	record, err := a.deps.State.CreateTerminalTab(ctx, postgres.TerminalTabRecord{
		ID:               tabID.String(),
		OwnerID:          principal.OwnerID,
		WorkspaceID:      workspaceID,
		Title:            terminalTitle(request.Kind),
		Kind:             string(request.Kind),
		CoderReconnectID: reconnectID.String(),
		CreatedAt:        a.deps.Clock.Now(),
	})
	if err != nil {
		return httpapi.TerminalTab{}, err
	}
	a.audit(principal, workspaceID, "terminal_tab.create", "success", "terminal_tab", record.ID, map[string]any{"kind": record.Kind})
	return terminalTab(record, false), nil
}

func (a *Application) RenameTerminalTab(ctx context.Context, principal httpapi.Principal, workspaceID, tabID string, request httpapi.RenameTerminalTabRequest) (httpapi.TerminalTab, error) {
	title, err := canonicalTerminalTitle(request.Title)
	if err != nil {
		return httpapi.TerminalTab{}, err
	}
	releaseMutation := a.acquireWorkspaceMutation(workspaceID)
	defer releaseMutation()
	if _, err := a.deps.WorkspaceStore.Get(ctx, principal.OwnerID, workspaceID); err != nil {
		return httpapi.TerminalTab{}, err
	}
	record, err := a.deps.State.RenameTerminalTab(ctx, principal.OwnerID, workspaceID, tabID, title)
	if err != nil {
		return httpapi.TerminalTab{}, err
	}
	a.runtimeMu.Lock()
	running := a.running[record.ID]
	a.runtimeMu.Unlock()
	a.audit(principal, workspaceID, "terminal_tab.rename", "success", "terminal_tab", record.ID, map[string]any{"title_characters": utf8.RuneCountInString(title)})
	return terminalTab(record, running), nil
}

func (a *Application) ReorderTerminalTabs(ctx context.Context, principal httpapi.Principal, workspaceID string, request httpapi.ReorderTerminalTabsRequest) ([]httpapi.TerminalTab, error) {
	if err := validateTerminalTabOrder(request.TabIDs); err != nil {
		return nil, err
	}
	releaseMutation := a.acquireWorkspaceMutation(workspaceID)
	defer releaseMutation()
	if _, err := a.deps.WorkspaceStore.Get(ctx, principal.OwnerID, workspaceID); err != nil {
		return nil, err
	}
	records, err := a.deps.State.ReorderTerminalTabs(ctx, principal.OwnerID, workspaceID, request.TabIDs)
	if err != nil {
		return nil, err
	}
	a.runtimeMu.Lock()
	result := make([]httpapi.TerminalTab, 0, len(records))
	for _, record := range records {
		result = append(result, terminalTab(record, a.running[record.ID]))
	}
	a.runtimeMu.Unlock()
	a.audit(principal, workspaceID, "terminal_tab.reorder", "success", "workspace", workspaceID, map[string]any{"tab_count": len(result)})
	return result, nil
}

func (a *Application) CloseTerminalTab(ctx context.Context, principal httpapi.Principal, workspaceID, tabID string, request httpapi.CloseTerminalTabRequest) error {
	if !request.Confirmed {
		return invalid(errors.New("terminal close confirmation is required"))
	}
	releaseMutation := a.acquireWorkspaceMutation(workspaceID)
	defer releaseMutation()
	if _, err := a.deps.WorkspaceStore.Get(ctx, principal.OwnerID, workspaceID); err != nil {
		return err
	}
	record, changed, err := a.deps.State.CloseTerminalTab(ctx, principal.OwnerID, workspaceID, tabID, a.deps.Clock.Now())
	if err != nil {
		return err
	}
	parsedID, err := terminal.ParseTabID(record.ID)
	if err != nil {
		return external(errors.New("stored terminal tab has an invalid identity"))
	}
	a.runtimeMu.Lock()
	delete(a.running, record.ID)
	a.runtimeMu.Unlock()
	if err := a.deps.Terminals.Unregister(parsedID, "owner_closed"); err != nil {
		a.audit(principal, workspaceID, "terminal_tab.close", "failed", "terminal_tab", record.ID, map[string]any{"state_closed": true, "failure_stage": "runtime"})
		return external(err)
	}
	a.audit(principal, workspaceID, "terminal_tab.close", "success", "terminal_tab", record.ID, map[string]any{"state_changed": changed, "kind": record.Kind})
	return nil
}

func (a *Application) createPrimaryCodexTab(ctx context.Context, value core.Workspace) error {
	tabID, err := terminal.NewTabID()
	if err != nil {
		return err
	}
	reconnectID, err := terminal.NewTabID()
	if err != nil {
		return err
	}
	_, err = a.deps.State.CreateTerminalTab(ctx, postgres.TerminalTabRecord{
		ID:               tabID.String(),
		OwnerID:          value.OwnerID,
		WorkspaceID:      value.ID,
		Title:            "Codex",
		Kind:             string(httpapi.TerminalCodex),
		CoderReconnectID: reconnectID.String(),
		CreatedAt:        a.deps.Clock.Now(),
	})
	return err
}

func (a *Application) CreateTerminalConnection(ctx context.Context, principal httpapi.Principal, workspaceID, tabID string, request httpapi.TerminalConnectRequest) (httpapi.TerminalConnectionDescriptor, error) {
	releaseMutation := a.acquireWorkspaceMutation(workspaceID)
	defer releaseMutation()
	releaseAdmission := a.acquireTerminalAdmission(principal.OwnerID, principal.DeviceID)
	defer releaseAdmission()
	setupLimit := a.terminalSetupLimit
	if setupLimit <= 0 {
		setupLimit = defaultTerminalRuntimeSetupTimeout
	}
	setupContext, cancelSetup := context.WithTimeout(ctx, setupLimit)
	defer cancelSetup()
	// Durable session authority must be established before lazy runtime setup.
	// Otherwise a request authenticated before revocation could register a
	// persistent PTY (and deliver a stored Codex prompt) after revocation had
	// already returned, even though ticket issuance was later rejected.
	if err := a.deps.Sessions.ValidatePrincipal(setupContext, session.Principal{
		OwnerID: principal.OwnerID, DeviceID: principal.DeviceID, FamilyID: principal.FamilyID,
	}); err != nil {
		return httpapi.TerminalConnectionDescriptor{}, unauthorized(err)
	}

	record, err := a.deps.State.GetTerminalTab(setupContext, principal.OwnerID, workspaceID, tabID)
	if err != nil {
		return httpapi.TerminalConnectionDescriptor{}, err
	}
	value, err := a.helperWorkspace(setupContext, principal.OwnerID, workspaceID)
	if err != nil {
		return httpapi.TerminalConnectionDescriptor{}, err
	}
	parsedID, err := terminal.ParseTabID(record.ID)
	if err != nil {
		return httpapi.TerminalConnectionDescriptor{}, external(errors.New("stored terminal tab has an invalid identity"))
	}
	if err := a.ensureTerminalRuntime(setupContext, value, record, parsedID); err != nil {
		return httpapi.TerminalConnectionDescriptor{}, err
	}
	if err := setupContext.Err(); err != nil {
		return httpapi.TerminalConnectionDescriptor{}, err
	}
	// Complete all context-bound persistence before minting the one-use ticket.
	// A timeout must never leave an undisclosed live credential behind.
	_ = a.deps.State.TouchTerminalTab(setupContext, principal.OwnerID, workspaceID, tabID, a.deps.Clock.Now())
	if err := a.touchWorkspace(setupContext, value); err != nil {
		return httpapi.TerminalConnectionDescriptor{}, err
	}
	if err := setupContext.Err(); err != nil {
		return httpapi.TerminalConnectionDescriptor{}, err
	}
	reconnect := ""
	if request.ReconnectToken != nil {
		reconnect = *request.ReconnectToken
	}
	connection, err := a.deps.Terminals.Issue(principal.OwnerID, principal.DeviceID, workspaceID, parsedID, request.AfterSequence, reconnect)
	if err != nil {
		if errors.Is(err, terminal.ErrTerminalCapacity) {
			return httpapi.TerminalConnectionDescriptor{}, fmt.Errorf("%w: terminal connection capacity reached", core.ErrCapacity)
		}
		return httpapi.TerminalConnectionDescriptor{}, fmt.Errorf("%w: terminal connection could not be issued", core.ErrUnauthorized)
	}
	// Ticket issuance is authoritative; no fallible context-bound operation is
	// performed after this point, so the credential is either returned or swept
	// by a device revocation waiting on the same admission gate.
	reconnectToken := connection.ReconnectToken
	var leaseHolder *string
	if connection.LeaseHolderDeviceID != "" {
		leaseHolder = &connection.LeaseHolderDeviceID
	}
	a.audit(principal, workspaceID, "terminal.connect", "success", "terminal_tab", tabID, nil)
	return httpapi.TerminalConnectionDescriptor{
		WebSocketURL:        a.config.TerminalWebSocketURL,
		ConnectionTicket:    connection.Ticket,
		DeviceID:            principal.DeviceID,
		ReconnectToken:      &reconnectToken,
		ProtocolVersion:     connection.ProtocolVersion,
		MaximumFrameBytes:   connection.MaximumFrameBytes,
		LeaseHolderDeviceID: leaseHolder,
	}, nil
}

func canonicalTerminalTitle(input string) (string, error) {
	title := strings.TrimSpace(input)
	if !utf8.ValidString(title) || utf8.RuneCountInString(title) < 1 || utf8.RuneCountInString(title) > 120 {
		return "", invalid(errors.New("terminal title must contain between 1 and 120 characters"))
	}
	for _, character := range title {
		if unicode.IsControl(character) || character == '\u2028' || character == '\u2029' ||
			(character >= '\u202a' && character <= '\u202e') || (character >= '\u2066' && character <= '\u2069') {
			return "", invalid(errors.New("terminal title contains unsafe control characters"))
		}
	}
	return title, nil
}

func validateTerminalTabOrder(tabIDs []string) error {
	if len(tabIDs) < 1 || len(tabIDs) > 64 {
		return invalid(errors.New("terminal order must contain between 1 and 64 tabs"))
	}
	seen := make(map[string]struct{}, len(tabIDs))
	for _, value := range tabIDs {
		if _, err := terminal.ParseTabID(value); err != nil {
			return invalid(errors.New("terminal order contains an invalid tab identity"))
		}
		if _, duplicate := seen[value]; duplicate {
			return invalid(errors.New("terminal order contains a duplicate tab identity"))
		}
		seen[value] = struct{}{}
	}
	return nil
}

func (a *Application) ensureTerminalRuntime(ctx context.Context, value core.Workspace, record postgres.TerminalTabRecord, tabID terminal.TabID) error {
	for {
		a.runtimeMu.Lock()
		if a.running[record.ID] {
			a.runtimeMu.Unlock()
			return nil
		}
		if wait := a.starting[record.ID]; wait != nil {
			a.runtimeMu.Unlock()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-wait:
				continue
			}
		}
		wait := make(chan struct{})
		a.starting[record.ID] = wait
		a.runtimeMu.Unlock()

		err := a.startTerminalRuntime(ctx, value, record, tabID)
		a.runtimeMu.Lock()
		delete(a.starting, record.ID)
		if err == nil {
			a.running[record.ID] = true
		}
		close(wait)
		a.runtimeMu.Unlock()
		return err
	}
}

func (a *Application) startTerminalRuntime(ctx context.Context, value core.Workspace, record postgres.TerminalTabRecord, tabID terminal.TabID) error {
	agentID, err := a.deps.Coder.AgentID(ctx, value.ProviderResourceID)
	if err != nil {
		return external(err)
	}
	kind := coder.TerminalKind(record.Kind)
	if !validCoderTerminalKind(kind) {
		return external(errors.New("stored terminal tab has an invalid kind"))
	}
	if kind == coder.TerminalCodex {
		mapping, mappingErr := a.runHelper(ctx, value, workspacehelper.Request{
			Version: workspacehelper.Version, Operation: workspacehelper.OpCodexThreadLookup, TerminalTabID: record.ID,
		})
		if mappingErr != nil {
			return mappingErr
		}
		if mapping.CodexThreadID != "" && mapping.CodexThreadID != record.CodexThreadID {
			record, err = a.deps.State.SetTerminalCodexThreadID(ctx, record.OwnerID, record.WorkspaceID, record.ID, mapping.CodexThreadID)
			if err != nil {
				return external(err)
			}
		}
	}
	initialPrompt := ""
	if kind == coder.TerminalCodex {
		initialPrompt, err = a.deps.State.LoadWorkspaceInitialPrompt(ctx, value.OwnerID, value.Repository.ID, value.ID)
		if err != nil {
			return external(err)
		}
	}
	var delivered func()
	if initialPrompt != "" {
		ownerID, repositoryID, workspaceID := value.OwnerID, value.Repository.ID, value.ID
		delivered = func() {
			markContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = a.deps.State.MarkWorkspaceInitialPromptDelivered(markContext, ownerID, repositoryID, workspaceID, a.deps.Clock.Now())
		}
	}
	// Grant mutations and terminal starts share the workspace mutation lock.
	// Re-synchronizing at this last boundary prevents a newly launched process
	// from inheriting an older tmpfs grant set after a control-plane restart or
	// a previously failed live synchronization.
	if err := a.syncWorkspaceRuntimeSecrets(ctx, value); err != nil {
		initialPrompt = ""
		return err
	}
	granted, err := a.deps.State.LoadGrantedWorkspaceSecrets(ctx, value.OwnerID, value.ID)
	if err != nil {
		initialPrompt = ""
		return external(errors.New("active workspace secret grants are unavailable for terminal redaction"))
	}
	secretValues := make([][]byte, 0, len(granted))
	for _, secret := range granted {
		secretValues = append(secretValues, secret)
	}
	outputRedactor, redactionErr := terminal.NewOutputRedactor(secretValues...)
	for name, secret := range granted {
		zero(secret)
		delete(granted, name)
	}
	clear(secretValues)
	if redactionErr != nil {
		initialPrompt = ""
		return external(errors.New("active workspace secrets cannot be safely redacted from terminal output"))
	}
	runtime, err := a.deps.Coder.OpenPTY(coder.PTYConfig{
		AgentID:                agentID,
		ReconnectID:            record.CoderReconnectID,
		SessionName:            "cm-" + strings.ToLower(tabID.String()),
		Kind:                   kind,
		CodexTabID:             record.ID,
		CodexThreadID:          record.CodexThreadID,
		InitialPrompt:          initialPrompt,
		InitialPromptDelivered: delivered,
		InitialSize:            a.config.InitialTerminalSize,
	})
	initialPrompt = ""
	if err != nil {
		outputRedactor.Close()
		return external(err)
	}
	if err := a.deps.Terminals.Register(record.OwnerID, record.WorkspaceID, tabID, runtime, outputRedactor, kind == coder.TerminalCodex); err != nil {
		outputRedactor.Close()
		_ = runtime.Close()
		if errors.Is(err, terminal.ErrTerminalCapacity) {
			return fmt.Errorf("%w: registered terminal capacity reached", core.ErrCapacity)
		}
		return external(err)
	}
	return nil
}

func terminalTab(record postgres.TerminalTabRecord, running bool) httpapi.TerminalTab {
	return httpapi.TerminalTab{
		ID:          record.ID,
		WorkspaceID: record.WorkspaceID,
		Title:       record.Title,
		Kind:        httpapi.TerminalTabKind(record.Kind),
		Order:       record.Order,
		IsRunning:   running,
	}
}

func validTerminalKind(kind httpapi.TerminalTabKind) bool {
	return kind == httpapi.TerminalCodex || kind == httpapi.TerminalShell || kind == httpapi.TerminalServer || kind == httpapi.TerminalTest || kind == httpapi.TerminalLog
}

func validCoderTerminalKind(kind coder.TerminalKind) bool {
	return kind == coder.TerminalCodex || kind == coder.TerminalShell || kind == coder.TerminalServer || kind == coder.TerminalTest || kind == coder.TerminalLog
}

func terminalTitle(kind httpapi.TerminalTabKind) string {
	switch kind {
	case httpapi.TerminalCodex:
		return "Codex"
	case httpapi.TerminalShell:
		return "Shell"
	case httpapi.TerminalServer:
		return "Server"
	case httpapi.TerminalTest:
		return "Tests"
	case httpapi.TerminalLog:
		return "Logs"
	default:
		return "Terminal"
	}
}
