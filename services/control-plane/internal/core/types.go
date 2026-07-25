package core

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	ErrNotFound          = errors.New("not found")
	ErrConflict          = errors.New("conflict")
	ErrUnauthorized      = errors.New("unauthorized")
	ErrForbidden         = errors.New("forbidden")
	ErrInvalid           = errors.New("invalid input")
	ErrCapacity          = errors.New("insufficient safe capacity")
	ErrPrecondition      = errors.New("precondition failed")
	ErrExternal          = errors.New("external provider failure")
	ErrOwnerActionNeeded = errors.New("owner action required")
)

type WorkspaceState string

const (
	WorkspaceQueued                WorkspaceState = "queued"
	WorkspaceProvisioning          WorkspaceState = "provisioning"
	WorkspaceAwaitingSetupApproval WorkspaceState = "awaiting_setup_approval"
	WorkspaceReady                 WorkspaceState = "ready"
	WorkspaceRunning               WorkspaceState = "running"
	WorkspaceNeedsAttention        WorkspaceState = "needs_attention"
	WorkspaceIdle                  WorkspaceState = "idle"
	WorkspaceSuspending            WorkspaceState = "suspending"
	WorkspaceSuspended             WorkspaceState = "suspended"
	WorkspaceFailed                WorkspaceState = "failed"
	WorkspaceMaintenance           WorkspaceState = "maintenance"
	WorkspaceDeleting              WorkspaceState = "deleting"
)

var workspaceTransitions = map[WorkspaceState]map[WorkspaceState]bool{
	WorkspaceQueued:                {WorkspaceProvisioning: true, WorkspaceDeleting: true, WorkspaceFailed: true},
	WorkspaceProvisioning:          {WorkspaceAwaitingSetupApproval: true, WorkspaceReady: true, WorkspaceFailed: true, WorkspaceDeleting: true},
	WorkspaceAwaitingSetupApproval: {WorkspaceProvisioning: true, WorkspaceFailed: true, WorkspaceDeleting: true},
	WorkspaceReady:                 {WorkspaceRunning: true, WorkspaceSuspending: true, WorkspaceDeleting: true, WorkspaceFailed: true, WorkspaceMaintenance: true},
	WorkspaceRunning:               {WorkspaceNeedsAttention: true, WorkspaceIdle: true, WorkspaceSuspending: true, WorkspaceFailed: true, WorkspaceMaintenance: true},
	WorkspaceNeedsAttention:        {WorkspaceRunning: true, WorkspaceSuspending: true, WorkspaceFailed: true, WorkspaceMaintenance: true},
	WorkspaceIdle:                  {WorkspaceRunning: true, WorkspaceSuspending: true, WorkspaceFailed: true, WorkspaceMaintenance: true},
	WorkspaceSuspending:            {WorkspaceSuspended: true, WorkspaceFailed: true},
	WorkspaceSuspended:             {WorkspaceProvisioning: true, WorkspaceDeleting: true, WorkspaceMaintenance: true},
	WorkspaceFailed:                {WorkspaceProvisioning: true, WorkspaceDeleting: true},
	WorkspaceMaintenance:           {WorkspaceProvisioning: true, WorkspaceSuspended: true, WorkspaceFailed: true},
	WorkspaceDeleting:              {},
}

func (s WorkspaceState) Valid() bool {
	_, ok := workspaceTransitions[s]
	return ok
}

func (s WorkspaceState) CanTransition(to WorkspaceState) bool {
	return s == to || workspaceTransitions[s][to]
}

func (s WorkspaceState) CountsAsRunning() bool {
	switch s {
	case WorkspaceProvisioning, WorkspaceReady, WorkspaceRunning, WorkspaceNeedsAttention, WorkspaceIdle, WorkspaceSuspending, WorkspaceMaintenance, WorkspaceDeleting:
		return true
	default:
		return false
	}
}

type SafetyMode string

const (
	SafetySafe       SafetyMode = "safe"
	SafetyBalanced   SafetyMode = "balanced"
	SafetyFullAccess SafetyMode = "full_access"
)

func (m SafetyMode) Valid() bool {
	return m == SafetySafe || m == SafetyBalanced || m == SafetyFullAccess
}

type RetentionPolicy string

const (
	Retention7Days   RetentionPolicy = "7_days"
	Retention30Days  RetentionPolicy = "30_days"
	Retention90Days  RetentionPolicy = "90_days"
	RetentionForever RetentionPolicy = "keep_forever"
)

func (p RetentionPolicy) Valid() bool {
	return p == Retention7Days || p == Retention30Days || p == Retention90Days || p == RetentionForever
}

type Quota struct {
	CPUMilli  int64 `json:"cpu_milli"`
	MemoryMiB int64 `json:"memory_mib"`
	DiskGiB   int64 `json:"disk_gib"`
}

const (
	MinimumWorkspaceDiskGiB = int64(8)
	DefaultWorkspaceDiskGiB = int64(12)
	MaximumWorkspaceDiskGiB = int64(16)
)

type Repository struct {
	ID             string    `json:"id"`
	InstallationID int64     `json:"installation_id"`
	FullName       string    `json:"full_name"`
	DefaultBranch  string    `json:"default_branch"`
	Private        bool      `json:"private"`
	Organization   bool      `json:"organization"`
	Permission     string    `json:"permission"`
	UpdatedAt      time.Time `json:"updated_at"`
}

func (r Repository) Validate() error {
	if r.ID == "" || r.InstallationID <= 0 || strings.Count(r.FullName, "/") != 1 || r.DefaultBranch == "" {
		return fmt.Errorf("%w: invalid repository identity", ErrInvalid)
	}
	return nil
}

type Workspace struct {
	ID           string          `json:"id"`
	OwnerID      string          `json:"owner_id"`
	Repository   Repository      `json:"repository"`
	Name         string          `json:"name"`
	Branch       string          `json:"branch"`
	BaseBranch   string          `json:"base_branch"`
	WorktreePath string          `json:"-"`
	State        WorkspaceState  `json:"state"`
	SafetyMode   SafetyMode      `json:"safety_mode"`
	Retention    RetentionPolicy `json:"retention"`
	// IdleTimeoutMinutes is zero when the workspace inherits the owner's
	// current global timeout.
	IdleTimeoutMinutes int  `json:"idle_timeout_minutes,omitempty"`
	NestedContainers   bool `json:"nested_containers"`
	SetupApproved      bool `json:"setup_approved"`
	// DevcontainerDir is the exact standard directory detected before the
	// plain bootstrap. It is deliberately not returned to clients, but it must
	// survive queues and process restarts so approval never re-detects a moving
	// upstream branch. The only valid non-empty values are "." (the root
	// .devcontainer.json form) and ".devcontainer".
	DevcontainerDir       string `json:"-"`
	DevcontainerSupported bool   `json:"-"`
	// PrivateInputsPending is a durable fail-closed marker. It is set in the
	// initial workspace row whenever creation included environment variables or
	// an initial prompt, and is cleared only after every private input has been
	// encrypted and durably persisted. It is never exposed to clients.
	PrivateInputsPending bool              `json:"-"`
	Dirty                bool              `json:"dirty"`
	Unpushed             bool              `json:"unpushed"`
	Quota                Quota             `json:"quota"`
	RequestedDiskGiB     int64             `json:"-"`
	ProviderResourceID   string            `json:"provider_resource_id,omitempty"`
	FailureCode          string            `json:"failure_code,omitempty"`
	CreatedAt            time.Time         `json:"created_at"`
	UpdatedAt            time.Time         `json:"updated_at"`
	LastActivityAt       time.Time         `json:"last_activity_at"`
	SuspendedAt          *time.Time        `json:"suspended_at,omitempty"`
	EnvironmentVariables map[string]string `json:"-"`
	InitialPrompt        string            `json:"-"`
}

func (w Workspace) MayAutoDelete() bool {
	return !w.Dirty && !w.Unpushed && w.Retention != RetentionForever
}

type CreateWorkspaceInput struct {
	RepositoryID         string            `json:"repository_id"`
	Name                 string            `json:"name"`
	BaseBranch           string            `json:"base_branch,omitempty"`
	InitialPrompt        string            `json:"initial_prompt,omitempty"`
	SafetyMode           SafetyMode        `json:"safety_mode,omitempty"`
	Retention            RetentionPolicy   `json:"retention,omitempty"`
	NestedContainers     bool              `json:"nested_containers"`
	EnvironmentVariables map[string]string `json:"-"`
	RequestedDiskGiB     int64             `json:"requested_disk_gib,omitempty"`
}

func (in *CreateWorkspaceInput) ApplyDefaults(defaultBranch string) {
	if in.BaseBranch == "" {
		in.BaseBranch = defaultBranch
	}
	if in.SafetyMode == "" {
		in.SafetyMode = SafetyBalanced
	}
	if in.Retention == "" {
		in.Retention = Retention30Days
	}
	if in.RequestedDiskGiB == 0 {
		in.RequestedDiskGiB = DefaultWorkspaceDiskGiB
	}
}

func (in CreateWorkspaceInput) Validate() error {
	if in.RepositoryID == "" || strings.TrimSpace(in.Name) == "" || len(in.Name) > 120 || in.BaseBranch == "" {
		return fmt.Errorf("%w: missing or invalid workspace identity", ErrInvalid)
	}
	if !in.SafetyMode.Valid() || !in.Retention.Valid() {
		return fmt.Errorf("%w: invalid safety mode or retention", ErrInvalid)
	}
	if len(in.InitialPrompt) > 100000 || !utf8.ValidString(in.InitialPrompt) || strings.ContainsRune(in.InitialPrompt, '\x00') {
		return fmt.Errorf("%w: initial prompt exceeds 100,000 bytes", ErrInvalid)
	}
	if in.RequestedDiskGiB < MinimumWorkspaceDiskGiB || in.RequestedDiskGiB > MaximumWorkspaceDiskGiB {
		return fmt.Errorf("%w: requested disk must be between %d and %d GiB", ErrInvalid, MinimumWorkspaceDiskGiB, MaximumWorkspaceDiskGiB)
	}
	if len(in.EnvironmentVariables) > 100 {
		return fmt.Errorf("%w: too many environment variables", ErrInvalid)
	}
	total := 0
	for name, value := range in.EnvironmentVariables {
		if !validEnvironmentName(name) || reservedEnvironmentName(name) || len(value) > 8192 || strings.ContainsRune(value, '\x00') {
			return fmt.Errorf("%w: invalid or reserved environment variable", ErrInvalid)
		}
		total += len(name) + len(value)
	}
	if total > 256*1024 {
		return fmt.Errorf("%w: environment variables exceed aggregate limit", ErrInvalid)
	}
	return nil
}

func validEnvironmentName(value string) bool {
	if value == "" || len(value) > 128 || !((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z') || value[0] == '_') {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if !((character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '_') {
			return false
		}
	}
	return true
}

func reservedEnvironmentName(value string) bool {
	upper := strings.ToUpper(value)
	if strings.HasPrefix(upper, "LD_") || strings.HasPrefix(upper, "DYLD_") || strings.HasPrefix(upper, "GIT_CONFIG_") || strings.HasPrefix(upper, "CODER_") || strings.HasPrefix(upper, "CODEX_MOBILE_") {
		return true
	}
	for _, reserved := range []string{"PATH", "HOME", "SHELL", "USER", "LOGNAME", "PWD", "OLDPWD", "CODEX_HOME", "BASH_ENV", "ENV", "GIT_ASKPASS", "GIT_SSH", "SSH_AUTH_SOCK"} {
		if upper == reserved {
			return true
		}
	}
	return false
}

type Device struct {
	ID         string     `json:"id"`
	OwnerID    string     `json:"owner_id"`
	Name       string     `json:"name"`
	Platform   string     `json:"platform"`
	CreatedAt  time.Time  `json:"created_at"`
	LastSeenAt time.Time  `json:"last_seen_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

type ActivityKind string

const (
	ActivityApproval    ActivityKind = "approval"
	ActivityQuestion    ActivityKind = "question"
	ActivityCompleted   ActivityKind = "completed"
	ActivityFailed      ActivityKind = "failed"
	ActivityMaintenance ActivityKind = "maintenance"
)

type Activity struct {
	ID          string       `json:"id"`
	OwnerID     string       `json:"owner_id"`
	WorkspaceID string       `json:"workspace_id,omitempty"`
	Kind        ActivityKind `json:"kind"`
	Summary     string       `json:"summary"`
	Unread      bool         `json:"unread"`
	CreatedAt   time.Time    `json:"created_at"`
}
