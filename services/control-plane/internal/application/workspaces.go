package application

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/gitops"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/httpapi"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/postgres"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/terminal"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/workspacehelper"
)

type workspaceActivityCounts struct {
	unread  int
	pending int
}

func (a *Application) ListRepositories(ctx context.Context, principal httpapi.Principal, query *string) ([]httpapi.RepositorySummary, error) {
	views, err := a.deps.Repositories.ListViews(ctx, principal.OwnerID)
	if err != nil {
		return nil, err
	}
	needle := ""
	if query != nil {
		needle = strings.ToLower(strings.TrimSpace(*query))
	}
	result := make([]httpapi.RepositorySummary, 0, len(views))
	for _, view := range views {
		owner, name, ok := strings.Cut(view.Repository.FullName, "/")
		if !ok || owner == "" || name == "" {
			continue
		}
		if needle != "" && !strings.Contains(strings.ToLower(view.Repository.FullName), needle) {
			continue
		}
		result = append(result, httpapi.RepositorySummary{
			ID:                  view.Repository.ID,
			Owner:               owner,
			Name:                name,
			DefaultBranch:       view.Repository.DefaultBranch,
			IsPrivate:           view.Repository.Private,
			InstallationAccount: view.InstallationAccount,
			IsFavorite:          view.Favorite,
			LastUsedAt:          view.LastUsedAt,
		})
	}
	return result, nil
}

func (a *Application) ListWorkspaces(ctx context.Context, principal httpapi.Principal) ([]httpapi.WorkspaceSummary, error) {
	values, err := a.deps.WorkspaceStore.List(ctx, principal.OwnerID)
	if err != nil {
		return nil, err
	}
	counts, err := a.workspaceActivityCounts(ctx, principal.OwnerID)
	if err != nil {
		return nil, err
	}
	sort.Slice(values, func(i, j int) bool {
		if values[i].UpdatedAt.Equal(values[j].UpdatedAt) {
			return values[i].ID < values[j].ID
		}
		return values[i].UpdatedAt.After(values[j].UpdatedAt)
	})
	result := make([]httpapi.WorkspaceSummary, 0, len(values))
	for _, value := range values {
		status := a.bestEffortGitStatus(ctx, value)
		result = append(result, a.workspaceSummary(value, status, counts[value.ID]))
	}
	return result, nil
}

func (a *Application) CreateWorkspace(ctx context.Context, principal httpapi.Principal, request httpapi.NewWorkspaceRequest) (httpapi.WorkspaceDetail, error) {
	defer clearStrings(request.EnvironmentVariables)
	if request.NestedDocker {
		a.audit(principal, "", "workspace.create", "denied", "repository", request.RepositoryID, map[string]any{"reason": "nested_container_spike_required"})
		return httpapi.WorkspaceDetail{}, fmt.Errorf("nested Docker compatibility is unavailable until the rootless isolation spike passes: %w", core.ErrInvalid)
	}
	name := "New task"
	if request.TaskName != nil {
		name = strings.TrimSpace(*request.TaskName)
	}
	baseBranch := ""
	if request.BaseBranch != nil {
		baseBranch = *request.BaseBranch
	}
	initialPrompt := ""
	if request.InitialPrompt != nil {
		initialPrompt = *request.InitialPrompt
	}
	requestedDiskGiB := int64(0)
	if request.RequestedDiskGiB != nil {
		requestedDiskGiB = int64(*request.RequestedDiskGiB)
	}
	value, err := a.deps.Workspaces.Create(ctx, principal.OwnerID, core.CreateWorkspaceInput{
		RepositoryID:         request.RepositoryID,
		Name:                 name,
		BaseBranch:           baseBranch,
		InitialPrompt:        initialPrompt,
		SafetyMode:           core.SafetyMode(request.Autonomy),
		Retention:            core.RetentionPolicy(request.Retention),
		NestedContainers:     request.NestedDocker,
		EnvironmentVariables: cloneStrings(request.EnvironmentVariables),
		RequestedDiskGiB:     requestedDiskGiB,
	})
	initialPrompt = ""
	clearStrings(value.EnvironmentVariables)
	value.EnvironmentVariables = nil
	value.InitialPrompt = ""
	if err != nil {
		a.audit(principal, "", "workspace.create", "failed", "repository", request.RepositoryID, nil)
		return httpapi.WorkspaceDetail{}, err
	}
	// Repository recency is a preference. A transient preference write must not
	// turn an already-created workspace into an apparent failed create.
	_ = a.deps.Repositories.MarkUsed(ctx, principal.OwnerID, request.RepositoryID, a.deps.Clock.Now())
	if err := a.createPrimaryCodexTab(ctx, value); err != nil {
		return httpapi.WorkspaceDetail{}, err
	}
	if value.State == core.WorkspaceAwaitingSetupApproval {
		if err := a.addSetupApproval(ctx, value); err != nil {
			return httpapi.WorkspaceDetail{}, err
		}
	}
	a.audit(principal, value.ID, "workspace.create", "success", "workspace", value.ID, map[string]any{"repository_id": request.RepositoryID})
	return a.workspaceDetail(ctx, principal.OwnerID, value)
}

func (a *Application) GetWorkspace(ctx context.Context, principal httpapi.Principal, workspaceID string) (httpapi.WorkspaceDetail, error) {
	value, err := a.deps.WorkspaceStore.Get(ctx, principal.OwnerID, workspaceID)
	if err != nil {
		return httpapi.WorkspaceDetail{}, err
	}
	if value.State == core.WorkspaceAwaitingSetupApproval {
		if err := a.addSetupApproval(ctx, value); err != nil {
			return httpapi.WorkspaceDetail{}, err
		}
	}
	return a.workspaceDetail(ctx, principal.OwnerID, value)
}

func (a *Application) PerformWorkspaceAction(ctx context.Context, principal httpapi.Principal, workspaceID string, request httpapi.WorkspaceActionRequest) (httpapi.WorkspaceActionResult, error) {
	current, err := a.deps.WorkspaceStore.Get(ctx, principal.OwnerID, workspaceID)
	if err != nil {
		return httpapi.WorkspaceActionResult{}, err
	}
	var value core.Workspace
	var deletionDetail *httpapi.WorkspaceDetail
	switch request.Action {
	case httpapi.ActionStart:
		switch current.State {
		case core.WorkspaceSuspended:
			value, err = a.deps.Workspaces.Resume(ctx, principal.OwnerID, workspaceID)
		case core.WorkspaceQueued, core.WorkspaceFailed:
			value, err = a.deps.Workspaces.Retry(ctx, principal.OwnerID, workspaceID)
		case core.WorkspaceRunning, core.WorkspaceReady, core.WorkspaceIdle, core.WorkspaceNeedsAttention:
			value = current
		default:
			err = fmt.Errorf("%w: workspace cannot start from %s", core.ErrConflict, current.State)
		}
	case httpapi.ActionSuspend, httpapi.ActionStop:
		value, err = a.deps.Workspaces.Suspend(ctx, principal.OwnerID, workspaceID)
	case httpapi.ActionResume:
		value, err = a.deps.Workspaces.Resume(ctx, principal.OwnerID, workspaceID)
	case httpapi.ActionRetryProvisioning:
		value, err = a.deps.Workspaces.Retry(ctx, principal.OwnerID, workspaceID)
	case httpapi.ActionDelete:
		// Build the response before deletion. Successful finalization removes the
		// authoritative row and its activity children, so no post-delete read may
		// turn a completed destructive mutation into an apparent failure.
		detail, detailErr := a.workspaceDetail(ctx, principal.OwnerID, current)
		if detailErr != nil {
			err = detailErr
			break
		}
		err = a.deps.Workspaces.Delete(ctx, principal.OwnerID, workspaceID, false, true)
		if err == nil {
			value = current
			value.State = core.WorkspaceDeleting
			value.SuspendedAt = nil
			value.FailureCode = ""
			value.UpdatedAt = a.deps.Clock.Now()
			detail.Summary.Lifecycle = httpapi.WorkspaceDeleting
			detail.Summary.Connectivity = httpapi.ConnectivityUnavailable
			detail.Summary.FailureMessage = nil
			detail.Summary.UpdatedAt = value.UpdatedAt
			detail.ProvisioningSteps = provisioningSteps(value)
			deletionDetail = &detail
		}
	case httpapi.ActionKeepAlive:
		value, err = a.deps.Workspaces.TouchActivity(ctx, principal.OwnerID, workspaceID, a.deps.Clock.Now())
	case httpapi.ActionUpdatePolicy:
		if request.Retention == nil || request.IdleTimeoutMinutes == nil {
			err = invalid(errors.New("workspace policy is required"))
			break
		}
		value, err = a.deps.Workspaces.UpdatePolicy(ctx, principal.OwnerID, workspaceID, core.RetentionPolicy(*request.Retention), *request.IdleTimeoutMinutes)
	case httpapi.ActionUpdateAutonomy:
		if request.Autonomy == nil {
			err = invalid(errors.New("workspace autonomy is required"))
			break
		}
		value, err = a.deps.Workspaces.UpdateSafetyMode(ctx, principal.OwnerID, workspaceID, core.SafetyMode(*request.Autonomy))
	default:
		err = invalid(errors.New("unsupported workspace action"))
	}
	if err != nil {
		a.audit(principal, workspaceID, "workspace."+string(request.Action), "failed", "workspace", workspaceID, nil)
		a.addFailureActivity(ctx, principal.OwnerID, workspaceID, "Workspace action could not be completed.")
		return httpapi.WorkspaceActionResult{}, err
	}
	// This is an idempotent reconciliation, not a one-shot transition side
	// effect. A prior request may have committed the workspace boundary before
	// persistence of the review was retried.
	if value.State == core.WorkspaceAwaitingSetupApproval {
		if err := a.addSetupApproval(ctx, value); err != nil {
			return httpapi.WorkspaceActionResult{}, err
		}
	}
	auditWorkspaceID := workspaceID
	if request.Action == httpapi.ActionDelete {
		// The FK-linked workspace row is gone. Keep the immutable target identity
		// while intentionally writing a NULL workspace_id audit linkage.
		auditWorkspaceID = ""
	}
	a.audit(principal, auditWorkspaceID, "workspace."+string(request.Action), "success", "workspace", workspaceID, nil)
	accepted := value.State == core.WorkspaceQueued || value.State == core.WorkspaceProvisioning || value.State == core.WorkspaceSuspending || value.State == core.WorkspaceDeleting
	if deletionDetail != nil {
		// Delete does not return until provider absence, runtime cleanup, and the
		// exact database finalization are complete. The bounded tombstone is an
		// acknowledgement snapshot, not an asynchronous 202 operation.
		return httpapi.WorkspaceActionResult{Workspace: *deletionDetail, Accepted: false}, nil
	}
	detail, err := a.workspaceDetail(ctx, principal.OwnerID, value)
	if err != nil {
		return httpapi.WorkspaceActionResult{}, err
	}
	return httpapi.WorkspaceActionResult{Workspace: detail, Accepted: accepted}, nil
}

// BeginWorkspaceDeleteFinalization implements workspace.DeletionBoundary for
// both owner-triggered and automatic retention deletion. It snapshots and
// drains process-local terminal and preview authorities while holding the same
// mutation gate used to create them. The workspace service retains the
// returned gate through its exact-row database delete.
func (a *Application) BeginWorkspaceDeleteFinalization(ctx context.Context, value core.Workspace) (func(), error) {
	if ctx == nil || value.OwnerID == "" || value.ID == "" {
		return nil, fmt.Errorf("workspace delete cleanup: %w", core.ErrInvalid)
	}
	return a.beginWorkspaceRuntimeDrain(ctx, value, "workspace_deleted", false)
}

// BeginWorkspaceSuspension implements workspace.SuspensionBoundary for owner,
// lifecycle, and maintenance suspension. The workspace service persists the
// suspending state before entering this boundary and retains the returned gate
// through provider stop and the final suspended-state write.
func (a *Application) BeginWorkspaceSuspension(ctx context.Context, value core.Workspace) (func(), error) {
	if ctx == nil || value.OwnerID == "" || value.ID == "" || value.State != core.WorkspaceSuspending {
		return nil, fmt.Errorf("workspace suspension cleanup: %w", core.ErrInvalid)
	}
	return a.beginWorkspaceRuntimeDrain(ctx, value, "workspace_suspended", true)
}

func (a *Application) beginWorkspaceRuntimeDrain(ctx context.Context, value core.Workspace, terminalReason string, persistPreviewRevocation bool) (func(), error) {
	releaseMutation := a.acquireWorkspaceMutation(value.ID)
	fail := func(err error) (func(), error) {
		releaseMutation()
		return nil, err
	}

	tabs, err := a.deps.State.ListTerminalTabs(ctx, value.OwnerID, value.ID)
	if err != nil {
		return fail(fmt.Errorf("list terminal runtimes before workspace delete: %w", err))
	}
	routes := []postgres.PreviewRouteRecord(nil)
	if a.deps.PreviewTokens != nil {
		routes, err = a.deps.State.ListPreviewRoutes(ctx, value.OwnerID, value.ID)
		if err != nil {
			return fail(fmt.Errorf("list preview runtimes before workspace delete: %w", err))
		}
	}

	var cleanupErr error
	for _, record := range tabs {
		a.runtimeMu.Lock()
		delete(a.running, record.ID)
		a.runtimeMu.Unlock()
		parsed, parseErr := terminal.ParseTabID(record.ID)
		if parseErr != nil {
			// An invalid persisted ID could never have been registered with the
			// terminal manager, so there is no process-local authority to drain.
			continue
		}
		if unregisterErr := a.deps.Terminals.Unregister(parsed, terminalReason); unregisterErr != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("unregister terminal runtime: %w", unregisterErr))
		}
	}
	for _, route := range routes {
		a.revokePreviewRouteRuntime(route)
		if persistPreviewRevocation {
			if revokeErr := a.deps.State.RevokePreviewRoute(ctx, value.OwnerID, value.ID, route.ID, a.deps.Clock.Now()); revokeErr != nil {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("revoke preview route: %w", revokeErr))
			}
		}
	}
	if cleanupErr != nil {
		return fail(cleanupErr)
	}

	var once sync.Once
	return func() { once.Do(releaseMutation) }, nil
}

func (a *Application) ListActivity(ctx context.Context, principal httpapi.Principal) ([]httpapi.ActivityItem, error) {
	records, err := a.deps.State.ListActivity(ctx, principal.OwnerID, 200)
	if err != nil {
		return nil, err
	}
	result := make([]httpapi.ActivityItem, 0, len(records))
	for _, record := range records {
		result = append(result, a.activityItem(ctx, principal.OwnerID, record))
	}
	return result, nil
}

func (a *Application) GetApproval(ctx context.Context, principal httpapi.Principal, approvalID string) (httpapi.ApprovalReview, error) {
	event, err := a.deps.State.GetSafetyEvent(ctx, principal.OwnerID, approvalID)
	if err != nil {
		return httpapi.ApprovalReview{}, err
	}
	return a.approvalReview(event), nil
}

func (a *Application) ResolveApproval(ctx context.Context, principal httpapi.Principal, approvalID string, request httpapi.ApprovalDecisionRequest) (httpapi.ApprovalReview, error) {
	decision := ""
	switch request.Decision {
	case httpapi.DecisionApprove:
		decision = "approved"
	case httpapi.DecisionDeny:
		decision = "denied"
	default:
		return httpapi.ApprovalReview{}, invalid(errors.New("unsupported approval decision"))
	}
	event, err := a.deps.State.GetSafetyEvent(ctx, principal.OwnerID, approvalID)
	if err != nil {
		a.audit(principal, "", "approval.resolve", "failed", "safety_event", approvalID, nil)
		return httpapi.ApprovalReview{}, err
	}
	if event.Action != "approve_repository_setup" {
		return httpapi.ApprovalReview{}, fmt.Errorf("%w: unsupported approval action", core.ErrInvalid)
	}
	if event.Decision != "requested" || event.ResolvedAt != nil {
		if event.Decision == decision {
			return a.approvalReview(event), nil
		}
		return httpapi.ApprovalReview{}, fmt.Errorf("resolve setup approval: %w", core.ErrConflict)
	}
	value, err := a.deps.WorkspaceStore.Get(ctx, principal.OwnerID, event.WorkspaceID)
	if err != nil {
		return httpapi.ApprovalReview{}, err
	}
	if decision == "approved" {
		if !value.SetupApproved {
			if _, approveErr := a.deps.Workspaces.ApproveSetup(ctx, principal.OwnerID, event.WorkspaceID); approveErr != nil {
				// ApproveSetup persists SetupApproved before starting repository
				// setup. If a later provider step failed, the owner decision still
				// took effect and this retryable event may be finalized safely.
				persisted, getErr := a.deps.WorkspaceStore.Get(ctx, principal.OwnerID, event.WorkspaceID)
				if getErr != nil || !persisted.SetupApproved {
					a.addFailureActivity(ctx, principal.OwnerID, event.WorkspaceID, "Approved workspace setup could not be completed.")
					a.audit(principal, event.WorkspaceID, "approval.resolve", "failed", "safety_event", approvalID, map[string]any{"decision": decision})
					return httpapi.ApprovalReview{}, approveErr
				}
			}
		}
	} else {
		if value.State != core.WorkspaceFailed || value.FailureCode != "setup_approval_denied" {
			if _, denyErr := a.deps.Workspaces.DenySetup(ctx, principal.OwnerID, event.WorkspaceID); denyErr != nil {
				return httpapi.ApprovalReview{}, denyErr
			}
		}
	}
	// The application gate protects only event compare-and-set work. Workspace
	// service mutations run first under their own gate, avoiding the inverse
	// service-delete -> application-boundary lock order.
	releaseMutation := a.acquireWorkspaceMutation(event.WorkspaceID)
	defer releaseMutation()
	event, err = a.deps.State.GetSafetyEvent(ctx, principal.OwnerID, approvalID)
	if err != nil {
		return httpapi.ApprovalReview{}, err
	}
	if event.Decision != "requested" || event.ResolvedAt != nil {
		if event.Decision == decision {
			return a.approvalReview(event), nil
		}
		return httpapi.ApprovalReview{}, fmt.Errorf("resolve setup approval: %w", core.ErrConflict)
	}
	// Resolve only after the workspace-side decision is durable. If this write
	// fails, a repeated request recognizes SetupApproved/setup_approval_denied
	// and retries only this final compare-and-set.
	event, err = a.deps.State.ResolveSafetyEvent(ctx, principal.OwnerID, approvalID, decision, principal.DeviceID, a.deps.Clock.Now())
	if err != nil {
		a.audit(principal, event.WorkspaceID, "approval.resolve", "failed", "safety_event", approvalID, map[string]any{"decision": decision})
		return httpapi.ApprovalReview{}, err
	}
	a.addCompletionActivity(ctx, principal.OwnerID, event.WorkspaceID, "Workspace setup review was resolved.")
	a.audit(principal, event.WorkspaceID, "approval.resolve", "success", "safety_event", approvalID, map[string]any{"decision": decision})
	return a.approvalReview(event), nil
}

func (a *Application) addSetupApproval(ctx context.Context, value core.Workspace) error {
	if a.deps.SetupReviews == nil {
		return errors.New("setup review reconciler is required")
	}
	return a.deps.SetupReviews.Ensure(ctx, value, a.deps.Clock.Now())
}

func (a *Application) addFailureActivity(ctx context.Context, ownerID, workspaceID, summary string) {
	a.addActivity(ctx, ownerID, workspaceID, "failed", summary)
}

func (a *Application) addCompletionActivity(ctx context.Context, ownerID, workspaceID, summary string) {
	a.addActivity(ctx, ownerID, workspaceID, "completed", summary)
}

func (a *Application) addActivity(ctx context.Context, ownerID, workspaceID, kind, summary string) {
	id, err := a.newID("activity")
	if err != nil {
		return
	}
	_ = a.deps.State.AddActivity(ctx, ownerID, postgres.ActivityRecord{
		ID:          id,
		WorkspaceID: &workspaceID,
		Kind:        kind,
		Summary:     summary,
		Unread:      true,
		Metadata:    json.RawMessage(`{}`),
		CreatedAt:   a.deps.Clock.Now(),
	})
}

func (a *Application) activityItem(ctx context.Context, ownerID string, record postgres.ActivityRecord) httpapi.ActivityItem {
	kind := httpapi.ActivityKind(record.Kind)
	switch record.Kind {
	case "completed":
		kind = httpapi.ActivityCompletion
	case "failed":
		kind = httpapi.ActivityFailure
	}
	state := httpapi.ActivityRead
	if record.Unread {
		state = httpapi.ActivityUnread
	}
	structured := false
	var deepLink *string
	if record.WorkspaceID != nil {
		value := "/workspaces/" + *record.WorkspaceID
		deepLink = &value
	}
	if record.Kind == "approval" {
		// Setup approvals originate inside the control plane and always carry
		// bounded structured fields. They must remain actionable even when the
		// optional Codex event provider exposes only generic attention events.
		structured = true
		var metadata struct {
			ApprovalID string `json:"approval_id"`
		}
		if json.Unmarshal(record.Metadata, &metadata) == nil && metadata.ApprovalID != "" {
			value := "/approvals/" + metadata.ApprovalID
			deepLink = &value
			if event, err := a.deps.State.GetSafetyEvent(ctx, ownerID, metadata.ApprovalID); err == nil {
				state = approvalState(event, a.deps.Clock.Now())
			}
		}
	}
	return httpapi.ActivityItem{
		ID:                        record.ID,
		WorkspaceID:               record.WorkspaceID,
		Kind:                      kind,
		State:                     state,
		Title:                     activityTitle(kind),
		GenericSummary:            truncateText(record.Summary, 500),
		CreatedAt:                 record.CreatedAt,
		DeepLinkPath:              deepLink,
		StructuredDetailAvailable: structured,
	}
}

func activityTitle(kind httpapi.ActivityKind) string {
	switch kind {
	case httpapi.ActivityApproval:
		return "Approval required"
	case httpapi.ActivityQuestion:
		return "Question"
	case httpapi.ActivityCompletion:
		return "Task completed"
	case httpapi.ActivityFailure:
		return "Action failed"
	case httpapi.ActivityMaintenance:
		return "Maintenance"
	default:
		return "Workspace activity"
	}
}

func (a *Application) approvalReview(event postgres.SafetyEvent) httpapi.ApprovalReview {
	action := "Run repository-provided setup"
	reason := event.Reason
	risk := "Repository setup may execute code and access the workspace network under the selected autonomy policy."
	return httpapi.ApprovalReview{
		ID:                        event.ID,
		WorkspaceID:               event.WorkspaceID,
		WorkspaceName:             event.WorkspaceName,
		RequestedAction:           &action,
		Reason:                    &reason,
		FilesystemScope:           []string{"/workspaces/repository"},
		NetworkScope:              []string{"workspace egress"},
		AffectedPaths:             []string{".devcontainer"},
		RiskExplanation:           &risk,
		StructuredDetailAvailable: true,
		State:                     approvalState(event, a.deps.Clock.Now()),
	}
}

func approvalState(event postgres.SafetyEvent, now time.Time) httpapi.ActivityState {
	if event.Action != "approve_repository_setup" && event.Decision == "requested" && event.ExpiresAt != nil && !now.Before(*event.ExpiresAt) {
		return httpapi.ActivityExpired
	}
	if event.Decision == "requested" && event.ResolvedAt == nil {
		return httpapi.ActivityPending
	}
	return httpapi.ActivityResolved
}

func (a *Application) workspaceActivityCounts(ctx context.Context, ownerID string) (map[string]workspaceActivityCounts, error) {
	records, err := a.deps.State.ListActivity(ctx, ownerID, 500)
	if err != nil {
		return nil, err
	}
	result := make(map[string]workspaceActivityCounts)
	for _, record := range records {
		if record.WorkspaceID == nil {
			continue
		}
		counts := result[*record.WorkspaceID]
		if record.Unread {
			counts.unread++
		}
		if record.Kind == "approval" {
			var metadata struct {
				ApprovalID string `json:"approval_id"`
			}
			if json.Unmarshal(record.Metadata, &metadata) == nil && metadata.ApprovalID != "" {
				if event, eventErr := a.deps.State.GetSafetyEvent(ctx, ownerID, metadata.ApprovalID); eventErr == nil && approvalState(event, a.deps.Clock.Now()) == httpapi.ActivityPending {
					counts.pending++
				}
			}
		}
		result[*record.WorkspaceID] = counts
	}
	return result, nil
}

func (a *Application) workspaceDetail(ctx context.Context, ownerID string, value core.Workspace) (httpapi.WorkspaceDetail, error) {
	counts, err := a.workspaceActivityCounts(ctx, ownerID)
	if err != nil {
		return httpapi.WorkspaceDetail{}, err
	}
	settings, err := a.deps.State.GetSettings(ctx, ownerID)
	if err != nil {
		return httpapi.WorkspaceDetail{}, err
	}
	status := a.bestEffortGitStatus(ctx, value)
	return httpapi.WorkspaceDetail{
		ID:                  value.ID,
		Summary:             a.workspaceSummary(value, status, counts[value.ID]),
		BaseBranch:          value.BaseBranch,
		Autonomy:            httpapi.AutonomyMode(value.SafetyMode),
		Retention:           httpapi.RetentionPolicy(value.Retention),
		IdleTimeoutMinutes:  effectiveIdleTimeout(value, settings.IdleTimeoutMinutes),
		NestedDockerEnabled: value.NestedContainers,
		ProvisioningSteps:   provisioningSteps(value),
	}, nil
}

func effectiveIdleTimeout(value core.Workspace, global int) int {
	if value.IdleTimeoutMinutes != 0 {
		return value.IdleTimeoutMinutes
	}
	return global
}

func (a *Application) workspaceSummary(value core.Workspace, status *gitops.Status, counts workspaceActivityCounts) httpapi.WorkspaceSummary {
	repositoryOwner, repositoryName, _ := strings.Cut(value.Repository.FullName, "/")
	git := gitSummary(value, status)
	var failure *string
	if value.State == core.WorkspaceFailed {
		message := safeFailureMessage(value.FailureCode)
		failure = &message
	}
	elapsed := int(a.deps.Clock.Now().Sub(value.CreatedAt).Seconds())
	if elapsed < 0 {
		elapsed = 0
	}
	return httpapi.WorkspaceSummary{
		ID:                   value.ID,
		RepositoryOwner:      repositoryOwner,
		RepositoryName:       repositoryName,
		TaskName:             value.Name,
		Branch:               value.Branch,
		WorktreeLabel:        value.Name,
		Lifecycle:            httpapi.WorkspaceLifecycle(value.State),
		Connectivity:         connectivity(value),
		UnreadActivityCount:  counts.unread,
		PendingApprovalCount: counts.pending,
		FailureMessage:       failure,
		Git:                  git,
		ResourceShare:        resourceShare(value),
		UpdatedAt:            value.UpdatedAt,
		ElapsedSeconds:       elapsed,
	}
}

func connectivity(value core.Workspace) httpapi.ConnectivityState {
	switch value.State {
	case core.WorkspaceRunning, core.WorkspaceReady, core.WorkspaceIdle, core.WorkspaceNeedsAttention:
		if value.ProviderResourceID != "" {
			return httpapi.ConnectivityConnected
		}
		return httpapi.ConnectivityUnavailable
	case core.WorkspaceProvisioning, core.WorkspaceSuspending, core.WorkspaceMaintenance:
		return httpapi.ConnectivityReconnecting
	case core.WorkspaceSuspended:
		return httpapi.ConnectivityOffline
	default:
		return httpapi.ConnectivityUnavailable
	}
}

func resourceShare(value core.Workspace) httpapi.ResourceShare {
	pressure := httpapi.PressureNominal
	if value.Quota.CPUMilli == 0 || value.Quota.MemoryMiB == 0 {
		pressure = httpapi.PressureConstrained
	} else if value.Quota.CPUMilli < 1000 || value.Quota.MemoryMiB < 2048 {
		pressure = httpapi.PressureElevated
	}
	return httpapi.ResourceShare{
		CPUCores:        float64(value.Quota.CPUMilli) / 1000,
		MemoryGiB:       float64(value.Quota.MemoryMiB) / 1024,
		WritableDiskGiB: float64(value.Quota.DiskGiB),
		Pressure:        pressure,
	}
}

func gitSummary(value core.Workspace, status *gitops.Status) httpapi.GitSummary {
	result := httpapi.GitSummary{HasUnpushedCommits: value.Unpushed}
	if status == nil {
		if value.Dirty {
			result.UnstagedCount = 1
		}
		return result
	}
	result.Ahead = status.Ahead
	result.Behind = status.Behind
	result.HasUnpushedCommits = status.Unpushed
	for _, change := range status.Changes {
		if change.Conflict {
			result.HasConflicts = true
		}
		if change.Staged {
			result.StagedCount++
		}
		if change.Untracked {
			result.UntrackedCount++
		} else if change.Unstaged {
			result.UnstagedCount++
		}
	}
	return result
}

func (a *Application) bestEffortGitStatus(ctx context.Context, value core.Workspace) *gitops.Status {
	if value.ProviderResourceID == "" || (value.State != core.WorkspaceRunning && value.State != core.WorkspaceReady && value.State != core.WorkspaceIdle && value.State != core.WorkspaceNeedsAttention) {
		return nil
	}
	response, err := a.runHelper(ctx, value, workspacehelper.Request{Version: workspacehelper.Version, Operation: workspacehelper.OpGitStatus})
	if err != nil {
		return nil
	}
	return response.GitStatus
}

func provisioningSteps(value core.Workspace) []httpapi.ProvisioningStep {
	steps := []httpapi.ProvisioningStep{
		{ID: "repository", Title: "Validate repository", State: httpapi.StepSucceeded},
		{ID: "environment", Title: "Detect environment", State: httpapi.StepSucceeded},
		{ID: "capacity", Title: "Reserve safe capacity", State: httpapi.StepPending},
		{ID: "workspace", Title: "Provision workspace", State: httpapi.StepPending},
	}
	switch value.State {
	case core.WorkspaceAwaitingSetupApproval:
		steps[2].State = httpapi.StepAwaitingApproval
	case core.WorkspaceQueued:
		steps[2].State = httpapi.StepPending
	case core.WorkspaceProvisioning:
		steps[2].State = httpapi.StepSucceeded
		steps[3].State = httpapi.StepRunning
	case core.WorkspaceReady, core.WorkspaceRunning, core.WorkspaceNeedsAttention, core.WorkspaceIdle, core.WorkspaceSuspending, core.WorkspaceSuspended:
		steps[2].State = httpapi.StepSucceeded
		steps[3].State = httpapi.StepSucceeded
	case core.WorkspaceFailed:
		steps[2].State = httpapi.StepSucceeded
		steps[3].State = httpapi.StepFailed
		detail := safeFailureMessage(value.FailureCode)
		steps[3].Detail = &detail
	case core.WorkspaceMaintenance:
		steps[2].State = httpapi.StepSucceeded
		steps[3].State = httpapi.StepRunning
	case core.WorkspaceDeleting:
		steps[2].State = httpapi.StepSucceeded
		steps[3].State = httpapi.StepSucceeded
	}
	return steps
}

func safeFailureMessage(code string) string {
	switch code {
	case "setup_approval_denied":
		return "Repository setup was denied."
	case "devcontainer_secure_recreate_required":
		return "This saved workspace predates the secure setup flow. Delete and recreate it before running repository setup."
	case "environment_persistence_failed", "private_inputs_recreate_required":
		return "Private workspace inputs were not saved completely. Delete and recreate this workspace."
	case "workspace_initialize_failed":
		return "The private repository checkout could not be initialized."
	case "provider_provision_failed", "provider_start_failed", "provider_stop_failed":
		return "The workspace provider could not complete the operation."
	default:
		return "Workspace provisioning failed."
	}
}

func cloneStrings(source map[string]string) map[string]string {
	if len(source) == 0 {
		return nil
	}
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func clearStrings(source map[string]string) {
	for key := range source {
		source[key] = ""
	}
}

func truncateText(value string, maximumRunes int) string {
	if maximumRunes < 1 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= maximumRunes {
		return value
	}
	return string(runes[:maximumRunes])
}

func fileName(value string) string { return path.Base(value) }
