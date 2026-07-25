package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/httpapi"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/postgres"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/preview"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/session"
)

func (a *Application) ListPreviews(ctx context.Context, principal httpapi.Principal, workspaceID string) ([]httpapi.PreviewEndpoint, error) {
	if !a.config.PreviewsConfigured || a.deps.PreviewTokens == nil {
		return nil, fmt.Errorf("%w: previews are not configured", core.ErrPrecondition)
	}
	releaseMutation := a.acquireWorkspaceMutation(workspaceID)
	defer releaseMutation()
	value, err := a.helperWorkspace(ctx, principal.OwnerID, workspaceID)
	if err != nil {
		return nil, err
	}
	agentID, err := a.deps.Coder.AgentID(ctx, value.ProviderResourceID)
	if err != nil {
		return nil, external(err)
	}
	ports, err := a.deps.Coder.ListeningPorts(ctx, agentID)
	if err != nil {
		return nil, external(err)
	}
	existing, err := a.deps.State.ListPreviewRoutes(ctx, principal.OwnerID, workspaceID)
	if err != nil {
		return nil, err
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i].Port < ports[j].Port })
	now := a.deps.Clock.Now()
	routes := make([]postgres.PreviewRouteRecord, 0, len(ports))
	seen := make(map[int]bool)
	for _, port := range ports {
		if port.Port < 1024 || port.Port > 65535 || seen[port.Port] {
			continue
		}
		seen[port.Port] = true
		routes = append(routes, postgres.PreviewRouteRecord{
			ID:          previewRouteID(workspaceID, port.Port),
			OwnerID:     principal.OwnerID,
			WorkspaceID: workspaceID,
			Port:        port.Port,
			ProcessName: safeProcessName(port.ProcessName, port.Port),
			// The preview gateway interprets this as the private Coder
			// workspace identity and performs the tunnel itself.
			WorkspaceHost: value.ProviderResourceID,
			CreatedAt:     now,
		})
	}
	if err := a.deps.State.SyncPreviewRoutes(ctx, principal.OwnerID, workspaceID, routes, now); err != nil {
		return nil, err
	}
	current := make(map[string]postgres.PreviewRouteRecord, len(routes))
	for _, route := range routes {
		current[route.ID] = route
	}
	for _, route := range existing {
		updated, ok := current[route.ID]
		if !ok || updated.WorkspaceHost != route.WorkspaceHost || updated.Port != route.Port {
			a.revokePreviewRouteRuntime(route)
		}
	}
	stored, err := a.deps.State.ListPreviewRoutes(ctx, principal.OwnerID, workspaceID)
	if err != nil {
		return nil, err
	}
	if err := a.touchWorkspace(ctx, value); err != nil {
		return nil, err
	}
	result := make([]httpapi.PreviewEndpoint, 0, len(stored))
	for _, route := range stored {
		result = append(result, httpapi.PreviewEndpoint{
			ID:          route.ID,
			Port:        route.Port,
			ProcessName: route.ProcessName,
			WorkspaceID: route.WorkspaceID,
			Status:      "ready",
		})
	}
	return result, nil
}

func (a *Application) CreatePreviewAccess(ctx context.Context, principal httpapi.Principal, workspaceID string, request httpapi.PreviewAccessRequest) (httpapi.PreviewAccess, error) {
	if !a.config.PreviewsConfigured || a.deps.PreviewTokens == nil {
		return httpapi.PreviewAccess{}, fmt.Errorf("%w: previews are not configured", core.ErrPrecondition)
	}
	releaseMutation := a.acquireWorkspaceMutation(workspaceID)
	defer releaseMutation()
	value, err := a.helperWorkspace(ctx, principal.OwnerID, workspaceID)
	if err != nil {
		return httpapi.PreviewAccess{}, err
	}
	route, err := a.deps.State.GetPreviewRoute(ctx, principal.OwnerID, workspaceID, request.PreviewID)
	if err != nil {
		return httpapi.PreviewAccess{}, err
	}
	if route.WorkspaceHost != value.ProviderResourceID || route.Port < 1024 || route.Port > 65535 {
		return httpapi.PreviewAccess{}, external(errors.New("stored preview route has an invalid workspace target"))
	}
	releaseAdmission := a.acquireTerminalAdmission(principal.OwnerID, principal.DeviceID)
	defer releaseAdmission()
	if err := a.deps.Sessions.ValidatePrincipal(ctx, session.Principal{
		OwnerID: principal.OwnerID, DeviceID: principal.DeviceID, FamilyID: principal.FamilyID,
	}); err != nil {
		return httpapi.PreviewAccess{}, unauthorized(err)
	}
	// Complete fallible persistence before minting the fragment credential. A
	// failed response must not leave an undisclosed live preview grant behind.
	if err := a.touchWorkspace(ctx, value); err != nil {
		return httpapi.PreviewAccess{}, err
	}
	token, expiresAt, err := a.deps.PreviewTokens.Issue(preview.Route{
		ID:          route.ID,
		OwnerID:     route.OwnerID,
		WorkspaceID: route.WorkspaceID,
		Port:        uint16(route.Port),
		Process:     route.ProcessName,
		Host:        route.WorkspaceHost,
		CreatedAt:   route.CreatedAt,
		RevokedAt:   route.RevokedAt,
	}, principal.DeviceID, a.config.PreviewAccessTTL)
	if err != nil {
		return httpapi.PreviewAccess{}, external(err)
	}
	host := route.ID + "." + a.config.PreviewDomain
	accessURL := (&url.URL{Scheme: "https", Host: host, Path: "/", Fragment: token}).String()
	a.audit(principal, workspaceID, "preview.access.create", "success", "preview_route", route.ID, nil)
	return httpapi.PreviewAccess{URL: accessURL, ExpiresAt: expiresAt, AllowedHost: host}, nil
}

func (a *Application) RevokePreviewAccess(ctx context.Context, principal httpapi.Principal, workspaceID, previewID string) error {
	if !a.config.PreviewsConfigured || a.deps.PreviewTokens == nil {
		return fmt.Errorf("%w: previews are not configured", core.ErrPrecondition)
	}
	releaseMutation := a.acquireWorkspaceMutation(workspaceID)
	defer releaseMutation()
	if _, err := a.deps.WorkspaceStore.Get(ctx, principal.OwnerID, workspaceID); err != nil {
		return err
	}
	route, err := a.deps.State.GetPreviewRoute(ctx, principal.OwnerID, workspaceID, previewID)
	if err != nil {
		return err
	}
	a.revokePreviewRouteRuntime(route)
	if err := a.deps.State.RevokePreviewRoute(ctx, principal.OwnerID, workspaceID, previewID, a.deps.Clock.Now()); err != nil {
		return err
	}
	if err := a.deps.WorkspaceStore.TouchActivity(ctx, principal.OwnerID, workspaceID, a.deps.Clock.Now()); err != nil {
		return err
	}
	a.audit(principal, workspaceID, "preview.access.revoke", "success", "preview_route", previewID, nil)
	return nil
}

func (a *Application) revokePreviewRouteRuntime(route postgres.PreviewRouteRecord) {
	a.deps.PreviewTokens.RevokeRoute(route.ID)
	if a.deps.PreviewTunnels != nil && route.WorkspaceHost != "" && route.Port >= 1024 && route.Port <= 65535 {
		a.deps.PreviewTunnels.Revoke(route.WorkspaceHost, uint16(route.Port))
	}
}

func previewRouteID(workspaceID string, port int) string {
	digest := sha256.Sum256([]byte("codex-mobile:preview-route:v1:" + workspaceID + ":" + strconv.Itoa(port)))
	return "pv-" + hex.EncodeToString(digest[:16])
}

func safeProcessName(value string, port int) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 500 || !utf8.ValidString(value) {
		return "Process on port " + strconv.Itoa(port)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return "Process on port " + strconv.Itoa(port)
		}
	}
	return value
}

func (a *Application) GetSettings(ctx context.Context, principal httpapi.Principal) (httpapi.UserSettings, error) {
	value, err := a.deps.State.GetSettings(ctx, principal.OwnerID)
	if err != nil {
		return httpapi.UserSettings{}, err
	}
	return userSettings(value), nil
}

func (a *Application) UpdateSettings(ctx context.Context, principal httpapi.Principal, request httpapi.UserSettings) (httpapi.UserSettings, error) {
	value := postgres.Settings{
		AutonomyDefault:           string(request.AutonomyDefault),
		RetentionDefault:          string(request.RetentionDefault),
		IdleTimeoutMinutes:        request.IdleTimeoutMinutes,
		TerminalFontSize:          request.TerminalFontSize,
		TerminalTheme:             request.TerminalTheme,
		TerminalCursorStyle:       string(request.TerminalCursorStyle),
		QuietHoursEnabled:         request.QuietHoursEnabled,
		NotificationDetailEnabled: request.NotificationDetailEnabled,
	}
	if err := a.deps.State.SaveSettings(ctx, principal.OwnerID, value, a.deps.Clock.Now()); err != nil {
		return httpapi.UserSettings{}, err
	}
	a.audit(principal, "", "settings.update", "success", "owner", principal.OwnerID, nil)
	return userSettings(value), nil
}

func (a *Application) RegisterPushDevice(ctx context.Context, principal httpapi.Principal, request httpapi.PushDeviceRegistration) error {
	if !a.config.APNSConfigured {
		return fmt.Errorf("%w: APNs is not configured", core.ErrPrecondition)
	}
	releaseAdmission := a.acquireTerminalAdmission(principal.OwnerID, principal.DeviceID)
	defer releaseAdmission()
	if err := a.deps.Sessions.ValidatePrincipal(ctx, session.Principal{
		OwnerID: principal.OwnerID, DeviceID: principal.DeviceID, FamilyID: principal.FamilyID,
	}); err != nil {
		return unauthorized(err)
	}
	if err := a.deps.State.RegisterNotification(ctx, principal.OwnerID, principal.DeviceID, string(request.Environment), request.Token, a.config.APNSTopic, a.deps.Clock.Now()); err != nil {
		return err
	}
	a.audit(principal, "", "notification.register", "success", "device", principal.DeviceID, map[string]any{"environment": request.Environment})
	return nil
}

func userSettings(value postgres.Settings) httpapi.UserSettings {
	return httpapi.UserSettings{
		AutonomyDefault:           httpapi.AutonomyMode(value.AutonomyDefault),
		RetentionDefault:          httpapi.RetentionPolicy(value.RetentionDefault),
		IdleTimeoutMinutes:        value.IdleTimeoutMinutes,
		TerminalFontSize:          value.TerminalFontSize,
		TerminalTheme:             value.TerminalTheme,
		TerminalCursorStyle:       httpapi.TerminalCursorStyle(value.TerminalCursorStyle),
		QuietHoursEnabled:         value.QuietHoursEnabled,
		NotificationDetailEnabled: value.NotificationDetailEnabled,
	}
}
