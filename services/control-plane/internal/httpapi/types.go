package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// Principal is the authenticated owner/device session identity. FamilyID is
// included so the current refresh family can be revoked without passing an
// opaque bearer credential into business logic.
type Principal struct {
	OwnerID  string
	DeviceID string
	FamilyID string
}

// Authenticator validates an opaque access credential. Implementations must
// return only a server-derived principal and must not retain the raw token.
type Authenticator interface {
	Authenticate(context.Context, string) (Principal, error)
}

// Application is the business-logic boundary for every REST operation in the
// frozen OpenAPI contract. Transport concerns (JSON, auth headers, status
// codes, limits) remain in this package.
type Application interface {
	Health(context.Context) error
	GetCapabilities(context.Context) (ClientCapabilities, error)
	BeginPasskeyRegistration(context.Context, BootstrapRegistrationRequest) (PasskeyRegistrationChallenge, error)
	FinishPasskeyRegistration(context.Context, PasskeyRegistrationCredential) (SessionTokens, error)
	BeginPasskeyAuthentication(context.Context, DeviceIdentityRequest) (PasskeyAuthenticationChallenge, error)
	FinishPasskeyAuthentication(context.Context, PasskeyAssertionCredential) (SessionTokens, error)
	BeginAdditionalPasskeyRegistration(context.Context, Principal, DeviceIdentityRequest) (PasskeyRegistrationChallenge, error)
	FinishAdditionalPasskeyRegistration(context.Context, Principal, PasskeyRegistrationCredential) (PasskeyMetadata, error)
	ListPasskeys(context.Context, Principal) ([]PasskeyMetadata, error)
	RevokePasskey(context.Context, Principal, string) error
	RefreshSession(context.Context, RefreshSessionRequest) (SessionTokens, error)
	RevokeCurrentSession(context.Context, Principal) error
	ListDevices(context.Context, Principal) ([]DeviceSummary, error)
	RevokeDevice(context.Context, Principal, string) error
	ListSecrets(context.Context, Principal, *string) ([]SecretMetadata, error)
	CreateSecret(context.Context, Principal, CreateSecretRequest) (SecretMetadata, error)
	UpdateSecret(context.Context, Principal, string, UpdateSecretRequest) (SecretMetadata, error)
	DeleteSecret(context.Context, Principal, string) error
	ListWorkspaceSecretGrants(context.Context, Principal, string) ([]WorkspaceSecretGrant, error)
	GrantWorkspaceSecret(context.Context, Principal, string, string) error
	RevokeWorkspaceSecret(context.Context, Principal, string, string) error
	GetConnections(context.Context, Principal) (ConnectionStatus, error)
	DisconnectGitHub(context.Context, Principal, int64) error
	GetCodexConnection(context.Context, Principal, string) (CodexWorkspaceConnection, error)
	DisconnectCodex(context.Context, Principal, string, ConfirmConnectionDisconnectRequest) error

	ListRepositories(context.Context, Principal, *string) ([]RepositorySummary, error)
	ListWorkspaces(context.Context, Principal) ([]WorkspaceSummary, error)
	CreateWorkspace(context.Context, Principal, NewWorkspaceRequest) (WorkspaceDetail, error)
	GetWorkspace(context.Context, Principal, string) (WorkspaceDetail, error)
	PerformWorkspaceAction(context.Context, Principal, string, WorkspaceActionRequest) (WorkspaceActionResult, error)

	ListActivity(context.Context, Principal) ([]ActivityItem, error)
	GetApproval(context.Context, Principal, string) (ApprovalReview, error)
	ResolveApproval(context.Context, Principal, string, ApprovalDecisionRequest) (ApprovalReview, error)

	ListTerminalTabs(context.Context, Principal, string) ([]TerminalTab, error)
	CreateTerminalTab(context.Context, Principal, string, CreateTerminalTabRequest) (TerminalTab, error)
	RenameTerminalTab(context.Context, Principal, string, string, RenameTerminalTabRequest) (TerminalTab, error)
	ReorderTerminalTabs(context.Context, Principal, string, ReorderTerminalTabsRequest) ([]TerminalTab, error)
	CloseTerminalTab(context.Context, Principal, string, string, CloseTerminalTabRequest) error
	CreateTerminalConnection(context.Context, Principal, string, string, TerminalConnectRequest) (TerminalConnectionDescriptor, error)
	StageTerminalAttachments(context.Context, Principal, string, string, StageAttachmentsRequest) (StageAttachmentsResult, error)

	GetFileTree(context.Context, Principal, string) ([]FileEntry, error)
	SearchFiles(context.Context, Principal, string, string) ([]FileSearchResult, error)
	GetFile(context.Context, Principal, string, string) (FileDocument, error)
	SaveFile(context.Context, Principal, string, string, SaveFileRequest) (FileDocument, error)

	GetGitStatus(context.Context, Principal, string) (GitStatusDetail, error)
	GetGitDiff(context.Context, Principal, string, string) (DiffDocument, error)
	SetGitStaged(context.Context, Principal, string, StageRequest) (GitStatusDetail, error)
	CreateCommit(context.Context, Principal, string, CommitRequest) (GitStatusDetail, error)
	PullWorkspace(context.Context, Principal, string) (GitStatusDetail, error)
	PushWorkspace(context.Context, Principal, string) (GitStatusDetail, error)
	DiscardGitChanges(context.Context, Principal, string, GitDiscardRequest) (GitDiscardResult, error)
	CreatePullRequest(context.Context, Principal, string, PullRequestRequest) (PullRequestResult, error)
	ListCheckpoints(context.Context, Principal, string) ([]CheckpointSummary, error)
	RestoreCheckpointFile(context.Context, Principal, string, string, CheckpointRestoreFileRequest) (CheckpointRestoreResult, error)
	RestoreCheckpointWorkspace(context.Context, Principal, string, string, CheckpointRestoreWorkspaceRequest) (CheckpointRestoreResult, error)

	ListPreviews(context.Context, Principal, string) ([]PreviewEndpoint, error)
	CreatePreviewAccess(context.Context, Principal, string, PreviewAccessRequest) (PreviewAccess, error)
	RevokePreviewAccess(context.Context, Principal, string, string) error
	GetMaintenance(context.Context, Principal) (MaintenanceStatus, error)
	ScheduleMaintenance(context.Context, Principal, ScheduleMaintenanceRequest) (MaintenanceStatus, error)
	CancelMaintenance(context.Context, Principal, string) (MaintenanceStatus, error)
	AdvanceMaintenance(context.Context, Principal, string, MaintenanceActionRequest) (MaintenanceStatus, error)
	GetDiagnostics(context.Context, Principal) (DiagnosticsReport, error)

	GetSettings(context.Context, Principal) (UserSettings, error)
	UpdateSettings(context.Context, Principal, UserSettings) (UserSettings, error)
	RegisterPushDevice(context.Context, Principal, PushDeviceRegistration) error
}

// WorkspaceActionResult distinguishes the contract's synchronous 200 response
// from an accepted asynchronous 202 response without exposing raw status codes
// to application implementations.
type WorkspaceActionResult struct {
	Workspace WorkspaceDetail
	Accepted  bool
}

type Options struct {
	Application   Application
	Authenticator Authenticator
	// TerminalWebSocket must perform one-use ticket redemption and origin
	// validation. The outer transport checks bearer shape and subprotocol before
	// delegating so malformed handshakes cannot consume a ticket.
	TerminalWebSocket http.Handler
	RESTTimeout       time.Duration
	HealthTimeout     time.Duration
	Metrics           HTTPMetrics
}

type HTTPMetrics interface {
	RecordHTTP(operation string, status int, duration time.Duration)
}

// ProblemError lets application code return a safe, public problem detail.
// Arbitrary errors are never reflected to clients.
type ProblemError struct {
	Status          int
	Code            string
	Title           string
	Detail          string
	Err             error
	GitPrecondition *GitOperationPrecondition
}

func (e *ProblemError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return e.Code
}

func (e *ProblemError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func NewProblemError(status int, code, title, detail string, cause error) error {
	if status < 400 || status > 599 || code == "" || title == "" {
		return errors.New("invalid problem error")
	}
	return &ProblemError{Status: status, Code: code, Title: title, Detail: detail, Err: cause}
}

type Problem struct {
	Type            string                    `json:"type"`
	Title           string                    `json:"title"`
	Status          int                       `json:"status"`
	Detail          string                    `json:"detail,omitempty"`
	Instance        string                    `json:"instance,omitempty"`
	Code            string                    `json:"code,omitempty"`
	GitPrecondition *GitOperationPrecondition `json:"git_precondition,omitempty"`
}

type GitOperationPrecondition struct {
	Reason           string `json:"reason"`
	Ahead            int    `json:"ahead"`
	Behind           int    `json:"behind"`
	HasConflicts     bool   `json:"has_conflicts"`
	Dirty            bool   `json:"dirty"`
	TerminalFallback string `json:"terminal_fallback"`
}

type HealthResponse struct {
	Status string `json:"status"`
}

type ClientCapabilities struct {
	GitHubConfigured             bool `json:"github_configured"`
	PasskeyBootstrapAvailable    bool `json:"passkey_bootstrap_available"`
	APNSConfigured               bool `json:"apns_configured"`
	PreviewsConfigured           bool `json:"previews_configured"`
	StructuredApprovalsAvailable bool `json:"structured_approvals_available"`
	MaximumRunningWorkspaces     int  `json:"maximum_running_workspaces"`
}

type ConnectionStatus struct {
	GitHub GitHubConnectionStatus `json:"github"`
	Codex  CodexConnectionStatus  `json:"codex"`
}

type GitHubConnectionStatus struct {
	Configured    bool                           `json:"configured"`
	Connected     bool                           `json:"connected"`
	Installations []GitHubInstallationConnection `json:"installations"`
}

type GitHubInstallationConnection struct {
	InstallationID      int64     `json:"installation_id"`
	AccountLogin        string    `json:"account_login"`
	AccountType         string    `json:"account_type"`
	RepositorySelection string    `json:"repository_selection"`
	UpdatedAt           time.Time `json:"updated_at"`
}

type CodexConnectionStatus struct {
	Scope                        string                     `json:"scope"`
	ConnectedWorkspaceCount      int                        `json:"connected_workspace_count"`
	AuthenticatingWorkspaceCount int                        `json:"authenticating_workspace_count"`
	DisconnectedWorkspaceCount   int                        `json:"disconnected_workspace_count"`
	UnavailableWorkspaceCount    int                        `json:"unavailable_workspace_count"`
	Workspaces                   []CodexWorkspaceConnection `json:"workspaces"`
}

type CodexConnectionState string

const (
	CodexConnectionConnected      CodexConnectionState = "connected"
	CodexConnectionAuthenticating CodexConnectionState = "authenticating"
	CodexConnectionDisconnected   CodexConnectionState = "disconnected"
	CodexConnectionUnavailable    CodexConnectionState = "unavailable"
)

type CodexWorkspaceConnection struct {
	WorkspaceID   string               `json:"workspace_id"`
	WorkspaceName string               `json:"workspace_name"`
	State         CodexConnectionState `json:"state"`
	CheckedAt     time.Time            `json:"checked_at"`
}

type ConfirmConnectionDisconnectRequest struct {
	Confirmed bool `json:"confirmed"`
}

type BootstrapRegistrationRequest struct {
	BootstrapToken   string `json:"bootstrap_token"`
	DeviceInstanceID string `json:"device_instance_id"`
	DeviceName       string `json:"device_name"`
}

type DeviceIdentityRequest struct {
	DeviceInstanceID string `json:"device_instance_id"`
	DeviceName       string `json:"device_name"`
}

type PasskeyRegistrationChallenge struct {
	CeremonyID            string   `json:"ceremony_id"`
	Challenge             string   `json:"challenge"`
	RelyingPartyID        string   `json:"relying_party_id"`
	UserID                string   `json:"user_id"`
	UserName              string   `json:"user_name"`
	UserDisplayName       string   `json:"user_display_name"`
	ExcludedCredentialIDs []string `json:"excluded_credential_ids"`
}

type PasskeyAuthenticationChallenge struct {
	CeremonyID           string   `json:"ceremony_id"`
	Challenge            string   `json:"challenge"`
	RelyingPartyID       string   `json:"relying_party_id"`
	AllowedCredentialIDs []string `json:"allowed_credential_ids"`
}

type PasskeyRegistrationCredential struct {
	CeremonyID        string `json:"ceremony_id"`
	CredentialID      string `json:"credential_id"`
	RawID             string `json:"raw_id"`
	ClientDataJSON    string `json:"client_data_json"`
	AttestationObject string `json:"attestation_object"`
	DeviceInstanceID  string `json:"device_instance_id"`
	DeviceName        string `json:"device_name"`
}

type PasskeyAssertionCredential struct {
	CeremonyID        string  `json:"ceremony_id"`
	CredentialID      string  `json:"credential_id"`
	RawID             string  `json:"raw_id"`
	ClientDataJSON    string  `json:"client_data_json"`
	AuthenticatorData string  `json:"authenticator_data"`
	Signature         string  `json:"signature"`
	UserHandle        *string `json:"user_handle,omitempty"`
	DeviceInstanceID  string  `json:"device_instance_id"`
	DeviceName        string  `json:"device_name"`
}

type SessionTokens struct {
	AccessToken      string    `json:"access_token"`
	AccessExpiresAt  time.Time `json:"access_expires_at"`
	RefreshToken     string    `json:"refresh_token"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
	DeviceID         string    `json:"device_id"`
}

// PasskeyMetadata deliberately excludes credential material and device IDs.
// The credential ID is an opaque handle suitable only for owner-scoped revoke.
type PasskeyMetadata struct {
	ID         string     `json:"id"`
	DeviceName string     `json:"device_name"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

type RefreshSessionRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type DeviceSummary struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Platform   string    `json:"platform"`
	Current    bool      `json:"current"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
}

type SecretMetadata struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Scope        string    `json:"scope"`
	RepositoryID *string   `json:"repository_id,omitempty"`
	ValueBytes   int       `json:"value_bytes"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type CreateSecretRequest struct {
	Name         string      `json:"name"`
	Value        SecretValue `json:"value"`
	RepositoryID *string     `json:"repository_id,omitempty"`
}

type UpdateSecretRequest struct {
	Value SecretValue `json:"value"`
}

// SecretValue decodes JSON strings into a mutable buffer so transport and
// application layers can scrub plaintext deterministically after use.
type SecretValue []byte

func (v *SecretValue) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*v = append((*v)[:0], value...)
	return nil
}

func (v SecretValue) Wipe() {
	for index := range v {
		v[index] = 0
	}
}

type WorkspaceSecretGrant struct {
	Secret    SecretMetadata `json:"secret"`
	Granted   bool           `json:"granted"`
	GrantedAt *time.Time     `json:"granted_at,omitempty"`
}

type RepositorySummary struct {
	ID                  string     `json:"id"`
	Owner               string     `json:"owner"`
	Name                string     `json:"name"`
	DefaultBranch       string     `json:"default_branch"`
	IsPrivate           bool       `json:"is_private"`
	InstallationAccount string     `json:"installation_account"`
	IsFavorite          bool       `json:"is_favorite"`
	LastUsedAt          *time.Time `json:"last_used_at,omitempty"`
}

type WorkspaceLifecycle string

const (
	WorkspaceQueued                WorkspaceLifecycle = "queued"
	WorkspaceProvisioning          WorkspaceLifecycle = "provisioning"
	WorkspaceAwaitingSetupApproval WorkspaceLifecycle = "awaiting_setup_approval"
	WorkspaceReady                 WorkspaceLifecycle = "ready"
	WorkspaceRunning               WorkspaceLifecycle = "running"
	WorkspaceNeedsAttention        WorkspaceLifecycle = "needs_attention"
	WorkspaceIdle                  WorkspaceLifecycle = "idle"
	WorkspaceSuspending            WorkspaceLifecycle = "suspending"
	WorkspaceSuspended             WorkspaceLifecycle = "suspended"
	WorkspaceFailed                WorkspaceLifecycle = "failed"
	WorkspaceMaintenance           WorkspaceLifecycle = "maintenance"
	WorkspaceDeleting              WorkspaceLifecycle = "deleting"
)

type ConnectivityState string

const (
	ConnectivityConnected    ConnectivityState = "connected"
	ConnectivityReconnecting ConnectivityState = "reconnecting"
	ConnectivityOffline      ConnectivityState = "offline"
	ConnectivityUnavailable  ConnectivityState = "unavailable"
)

type ResourcePressure string

const (
	PressureNominal     ResourcePressure = "nominal"
	PressureElevated    ResourcePressure = "elevated"
	PressureConstrained ResourcePressure = "constrained"
)

type AutonomyMode string

const (
	AutonomySafe       AutonomyMode = "safe"
	AutonomyBalanced   AutonomyMode = "balanced"
	AutonomyFullAccess AutonomyMode = "full_access"
)

type RetentionPolicy string

const (
	RetentionSevenDays   RetentionPolicy = "7_days"
	RetentionThirtyDays  RetentionPolicy = "30_days"
	RetentionNinetyDays  RetentionPolicy = "90_days"
	RetentionKeepForever RetentionPolicy = "keep_forever"
)

type ResourceShare struct {
	CPUCores        float64          `json:"cpu_cores"`
	MemoryGiB       float64          `json:"memory_gi_b"`
	WritableDiskGiB float64          `json:"writable_disk_gi_b"`
	Pressure        ResourcePressure `json:"pressure"`
}

type GitSummary struct {
	StagedCount        int  `json:"staged_count"`
	UnstagedCount      int  `json:"unstaged_count"`
	UntrackedCount     int  `json:"untracked_count"`
	Ahead              int  `json:"ahead"`
	Behind             int  `json:"behind"`
	HasConflicts       bool `json:"has_conflicts"`
	HasUnpushedCommits bool `json:"has_unpushed_commits"`
}

type WorkspaceSummary struct {
	ID                   string             `json:"id"`
	RepositoryOwner      string             `json:"repository_owner"`
	RepositoryName       string             `json:"repository_name"`
	TaskName             string             `json:"task_name"`
	Branch               string             `json:"branch"`
	WorktreeLabel        string             `json:"worktree_label"`
	TaskSummary          *string            `json:"task_summary,omitempty"`
	Lifecycle            WorkspaceLifecycle `json:"lifecycle"`
	Connectivity         ConnectivityState  `json:"connectivity"`
	UnreadActivityCount  int                `json:"unread_activity_count"`
	PendingApprovalCount int                `json:"pending_approval_count"`
	FailureMessage       *string            `json:"failure_message,omitempty"`
	Git                  GitSummary         `json:"git"`
	ResourceShare        ResourceShare      `json:"resource_share"`
	UpdatedAt            time.Time          `json:"updated_at"`
	ElapsedSeconds       int                `json:"elapsed_seconds"`
}

type ProvisioningStepState string

const (
	StepPending          ProvisioningStepState = "pending"
	StepRunning          ProvisioningStepState = "running"
	StepSucceeded        ProvisioningStepState = "succeeded"
	StepFailed           ProvisioningStepState = "failed"
	StepAwaitingApproval ProvisioningStepState = "awaiting_approval"
)

type ProvisioningStep struct {
	ID     string                `json:"id"`
	Title  string                `json:"title"`
	State  ProvisioningStepState `json:"state"`
	Detail *string               `json:"detail,omitempty"`
}

type WorkspaceDetail struct {
	ID                  string             `json:"id"`
	Summary             WorkspaceSummary   `json:"summary"`
	BaseBranch          string             `json:"base_branch"`
	Autonomy            AutonomyMode       `json:"autonomy"`
	Retention           RetentionPolicy    `json:"retention"`
	IdleTimeoutMinutes  int                `json:"idle_timeout_minutes"`
	NestedDockerEnabled bool               `json:"nested_docker_enabled"`
	EnvironmentDetected *string            `json:"environment_detected,omitempty"`
	ProvisioningSteps   []ProvisioningStep `json:"provisioning_steps"`
}

type NewWorkspaceRequest struct {
	RepositoryID         string            `json:"repository_id"`
	InitialPrompt        *string           `json:"initial_prompt,omitempty"`
	BaseBranch           *string           `json:"base_branch,omitempty"`
	TaskName             *string           `json:"task_name,omitempty"`
	Autonomy             AutonomyMode      `json:"autonomy"`
	NestedDocker         bool              `json:"nested_docker"`
	Retention            RetentionPolicy   `json:"retention"`
	EnvironmentVariables map[string]string `json:"environment_variables"`
	RequestedDiskGiB     *int              `json:"requested_disk_gi_b,omitempty"`
}

type WorkspaceAction string

const (
	ActionStart             WorkspaceAction = "start"
	ActionSuspend           WorkspaceAction = "suspend"
	ActionResume            WorkspaceAction = "resume"
	ActionStop              WorkspaceAction = "stop"
	ActionRetryProvisioning WorkspaceAction = "retry_provisioning"
	ActionDelete            WorkspaceAction = "delete"
	ActionKeepAlive         WorkspaceAction = "keep_alive"
	ActionUpdatePolicy      WorkspaceAction = "update_policy"
	ActionUpdateAutonomy    WorkspaceAction = "update_autonomy"
)

type WorkspaceActionRequest struct {
	Action             WorkspaceAction  `json:"action"`
	Retention          *RetentionPolicy `json:"retention,omitempty"`
	IdleTimeoutMinutes *int             `json:"idle_timeout_minutes,omitempty"`
	Autonomy           *AutonomyMode    `json:"autonomy,omitempty"`
}

type ActivityKind string
type ActivityState string

const (
	ActivityApproval    ActivityKind  = "approval"
	ActivityQuestion    ActivityKind  = "question"
	ActivityCompletion  ActivityKind  = "completion"
	ActivityFailure     ActivityKind  = "failure"
	ActivityMaintenance ActivityKind  = "maintenance"
	ActivitySecurity    ActivityKind  = "security"
	ActivityUnread      ActivityState = "unread"
	ActivityRead        ActivityState = "read"
	ActivityPending     ActivityState = "pending"
	ActivityResolved    ActivityState = "resolved"
	ActivityExpired     ActivityState = "expired"
)

type ActivityItem struct {
	ID                        string        `json:"id"`
	WorkspaceID               *string       `json:"workspace_id,omitempty"`
	Kind                      ActivityKind  `json:"kind"`
	State                     ActivityState `json:"state"`
	Title                     string        `json:"title"`
	GenericSummary            string        `json:"generic_summary"`
	CreatedAt                 time.Time     `json:"created_at"`
	DeepLinkPath              *string       `json:"deep_link_path,omitempty"`
	StructuredDetailAvailable bool          `json:"structured_detail_available"`
}

type ApprovalReview struct {
	ID                        string        `json:"id"`
	WorkspaceID               string        `json:"workspace_id"`
	WorkspaceName             string        `json:"workspace_name"`
	RequestedAction           *string       `json:"requested_action,omitempty"`
	Reason                    *string       `json:"reason,omitempty"`
	FilesystemScope           []string      `json:"filesystem_scope"`
	NetworkScope              []string      `json:"network_scope"`
	AffectedPaths             []string      `json:"affected_paths"`
	RiskExplanation           *string       `json:"risk_explanation,omitempty"`
	StructuredDetailAvailable bool          `json:"structured_detail_available"`
	State                     ActivityState `json:"state"`
}

type ApprovalDecision string

const (
	DecisionApprove ApprovalDecision = "approve"
	DecisionDeny    ApprovalDecision = "deny"
)

type ApprovalDecisionRequest struct {
	Decision ApprovalDecision `json:"decision"`
}

type TerminalTabKind string

const (
	TerminalCodex  TerminalTabKind = "codex"
	TerminalShell  TerminalTabKind = "shell"
	TerminalServer TerminalTabKind = "server"
	TerminalTest   TerminalTabKind = "test"
	TerminalLog    TerminalTabKind = "log"
)

type TerminalTab struct {
	ID          string          `json:"id"`
	WorkspaceID string          `json:"workspace_id"`
	Title       string          `json:"title"`
	Kind        TerminalTabKind `json:"kind"`
	Order       int             `json:"order"`
	IsRunning   bool            `json:"is_running"`
}

type CreateTerminalTabRequest struct {
	Kind TerminalTabKind `json:"kind"`
}

type RenameTerminalTabRequest struct {
	Title string `json:"title"`
}

type ReorderTerminalTabsRequest struct {
	TabIDs []string `json:"tab_ids"`
}

type CloseTerminalTabRequest struct {
	Confirmed bool `json:"confirmed"`
}

type TerminalConnectRequest struct {
	AfterSequence  uint64  `json:"after_sequence"`
	ReconnectToken *string `json:"reconnect_token,omitempty"`
}

type TerminalConnectionDescriptor struct {
	WebSocketURL        string  `json:"websocket_url"`
	ConnectionTicket    string  `json:"connection_ticket"`
	DeviceID            string  `json:"device_id"`
	ReconnectToken      *string `json:"reconnect_token,omitempty"`
	ProtocolVersion     uint8   `json:"protocol_version"`
	MaximumFrameBytes   int     `json:"maximum_frame_bytes"`
	LeaseHolderDeviceID *string `json:"lease_holder_device_id,omitempty"`
}

type AttachmentUpload struct {
	MediaType string `json:"media_type"`
	Content   []byte `json:"content_base64"`
}

type StageAttachmentsRequest struct {
	Attachments []AttachmentUpload `json:"attachments"`
}

func (r *StageAttachmentsRequest) Wipe() {
	if r == nil {
		return
	}
	for index := range r.Attachments {
		for byteIndex := range r.Attachments[index].Content {
			r.Attachments[index].Content[byteIndex] = 0
		}
		r.Attachments[index].Content = nil
	}
}

type StagedAttachment struct {
	ID        string    `json:"id"`
	Path      string    `json:"path"`
	MediaType string    `json:"media_type"`
	SizeBytes int       `json:"size_bytes"`
	ExpiresAt time.Time `json:"expires_at"`
}

type StageAttachmentsResult struct {
	Attachments []StagedAttachment `json:"attachments"`
}

type FileKind string
type CacheDirective string

const (
	FileDirectory FileKind       = "directory"
	FileText      FileKind       = "text"
	FileImage     FileKind       = "image"
	FileBinary    FileKind       = "binary"
	FileTooLarge  FileKind       = "too_large"
	FileSensitive FileKind       = "sensitive"
	CacheOrdinary CacheDirective = "ordinary"
	CacheNever    CacheDirective = "never"
)

type FileEntry struct {
	Path      string       `json:"path"`
	Name      string       `json:"name"`
	Kind      FileKind     `json:"kind"`
	IsIgnored bool         `json:"is_ignored"`
	SizeBytes *int64       `json:"size_bytes,omitempty"`
	Children  *[]FileEntry `json:"children,omitempty"`
}

type FileDocument struct {
	Path           string         `json:"path"`
	Content        string         `json:"content"`
	ETag           string         `json:"etag"`
	LanguageHint   *string        `json:"language_hint,omitempty"`
	Kind           FileKind       `json:"kind"`
	IsReadOnly     bool           `json:"is_read_only"`
	CacheDirective CacheDirective `json:"cache_directive"`
}

type SaveFileRequest struct {
	Content      string `json:"content"`
	ExpectedETag string `json:"expected_e_tag"`
}

type FileSearchResult struct {
	Path    string `json:"path"`
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Preview string `json:"preview"`
}

type GitChangeGroup string

const (
	GitStaged     GitChangeGroup = "staged"
	GitUnstaged   GitChangeGroup = "unstaged"
	GitUntracked  GitChangeGroup = "untracked"
	GitConflicted GitChangeGroup = "conflicted"
)

type GitFileChange struct {
	Path     string         `json:"path"`
	Status   string         `json:"status"`
	Group    GitChangeGroup `json:"group"`
	IsBinary bool           `json:"is_binary"`
}

type GitStatusDetail struct {
	Branch              string          `json:"branch"`
	Upstream            *string         `json:"upstream,omitempty"`
	Ahead               int             `json:"ahead"`
	Behind              int             `json:"behind"`
	Changes             []GitFileChange `json:"changes"`
	OperationInProgress *string         `json:"operation_in_progress,omitempty"`
}

type DiffDocument struct {
	Path           string         `json:"path"`
	UnifiedDiff    *string        `json:"unified_diff,omitempty"`
	ImageBeforeURL *string        `json:"image_before_url,omitempty"`
	ImageAfterURL  *string        `json:"image_after_url,omitempty"`
	IsBinary       bool           `json:"is_binary"`
	CacheDirective CacheDirective `json:"cache_directive"`
}

type StageRequest struct {
	Path   string `json:"path"`
	Staged bool   `json:"staged"`
}

type CommitRequest struct {
	Message     string `json:"message"`
	AuthorName  string `json:"author_name"`
	AuthorEmail string `json:"author_email"`
}

type PullRequestRequest struct {
	Title      string `json:"title"`
	Body       string `json:"body"`
	BaseBranch string `json:"base_branch"`
}

type PullRequestResult struct {
	Number int    `json:"number"`
	URL    string `json:"url"`
	State  string `json:"state"`
}

type GitDiscardRequest struct {
	Paths     []string `json:"paths"`
	Confirmed bool     `json:"confirmed"`
}

type GitDiscardResult struct {
	RecoveryCheckpointID string          `json:"recovery_checkpoint_id"`
	Status               GitStatusDetail `json:"status"`
	RestoreURL           string          `json:"restore_url"`
}

type CheckpointSummary struct {
	ID                        string    `json:"id"`
	Reason                    string    `json:"reason"`
	CreatedAt                 time.Time `json:"created_at"`
	ArchiveSHA256             string    `json:"archive_sha256"`
	HashStatus                string    `json:"hash_status"`
	ArchiveVersion            int       `json:"archive_version"`
	WorkspaceRestoreSupported bool      `json:"workspace_restore_supported"`
	CompressedBytes           int64     `json:"compressed_bytes"`
	ExpandedBytes             int64     `json:"expanded_bytes"`
	FileCount                 int       `json:"file_count"`
	DeletedCount              int       `json:"deleted_count"`
	OmittedSensitive          int       `json:"omitted_sensitive"`
	OmittedUnsafe             int       `json:"omitted_unsafe"`
	Head                      string    `json:"head,omitempty"`
}

type CheckpointRestoreFileRequest struct {
	Path      string `json:"path"`
	Confirmed bool   `json:"confirmed"`
}

type CheckpointRestoreWorkspaceRequest struct {
	Confirmed bool `json:"confirmed"`
}

type CheckpointRestoreResult struct {
	RestoredCheckpointID   string           `json:"restored_checkpoint_id"`
	PreRestoreCheckpointID string           `json:"pre_restore_checkpoint_id"`
	RestoreSemantics       string           `json:"restore_semantics"`
	Status                 *GitStatusDetail `json:"status,omitempty"`
}

type PreviewEndpoint struct {
	ID          string `json:"id"`
	Port        int    `json:"port"`
	ProcessName string `json:"process_name"`
	WorkspaceID string `json:"workspace_id"`
	Status      string `json:"status"`
}

type PreviewAccessRequest struct {
	PreviewID string `json:"preview_id"`
}

type PreviewAccess struct {
	URL         string    `json:"url"`
	ExpiresAt   time.Time `json:"expires_at"`
	AllowedHost string    `json:"allowed_host"`
}

type MaintenanceStatus struct {
	ID                     string     `json:"id"`
	State                  string     `json:"state"`
	Urgent                 bool       `json:"urgent"`
	BestEffort             bool       `json:"best_effort"`
	ScheduledFor           time.Time  `json:"scheduled_for"`
	WarningAt              time.Time  `json:"warning_at"`
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
	StartedAt              *time.Time `json:"started_at,omitempty"`
	CompletedAt            *time.Time `json:"completed_at,omitempty"`
	CheckpointedWorkspaces int        `json:"checkpointed_workspaces"`
	DrainedWorkspaces      int        `json:"drained_workspaces"`
	FailedWorkspaces       int        `json:"failed_workspaces"`
	RebootRequired         bool       `json:"reboot_required"`
	Message                string     `json:"message"`
}

type ScheduleMaintenanceRequest struct {
	Urgent bool `json:"urgent"`
}

type MaintenanceActionRequest struct {
	Action         string `json:"action"`
	RebootRequired *bool  `json:"reboot_required,omitempty"`
}

type DiagnosticsReport struct {
	GeneratedAt              time.Time `json:"generated_at"`
	ServiceVersion           string    `json:"service_version"`
	MetadataOnly             bool      `json:"metadata_only"`
	IncludesSensitiveData    bool      `json:"includes_sensitive_data"`
	Health                   string    `json:"health"`
	GitHubConfigured         bool      `json:"github_configured"`
	APNSConfigured           bool      `json:"apns_configured"`
	PreviewsConfigured       bool      `json:"previews_configured"`
	MaximumRunningWorkspaces int       `json:"maximum_running_workspaces"`
	WorkspaceTotal           int       `json:"workspace_total"`
	WorkspaceRunning         int       `json:"workspace_running"`
	WorkspaceQueued          int       `json:"workspace_queued"`
	WorkspaceSuspended       int       `json:"workspace_suspended"`
	WorkspaceNeedsAttention  int       `json:"workspace_needs_attention"`
	WorkspaceFailed          int       `json:"workspace_failed"`
	MaintenanceState         string    `json:"maintenance_state"`
}

type TerminalCursorStyle string

const (
	CursorBlock     TerminalCursorStyle = "block"
	CursorBeam      TerminalCursorStyle = "beam"
	CursorUnderline TerminalCursorStyle = "underline"
)

type UserSettings struct {
	AutonomyDefault           AutonomyMode        `json:"autonomy_default"`
	RetentionDefault          RetentionPolicy     `json:"retention_default"`
	IdleTimeoutMinutes        int                 `json:"idle_timeout_minutes"`
	TerminalFontSize          float64             `json:"terminal_font_size"`
	TerminalTheme             string              `json:"terminal_theme"`
	TerminalCursorStyle       TerminalCursorStyle `json:"terminal_cursor_style"`
	QuietHoursEnabled         bool                `json:"quiet_hours_enabled"`
	NotificationDetailEnabled bool                `json:"notification_detail_enabled"`
}

type PushEnvironment string

const (
	PushSandbox    PushEnvironment = "sandbox"
	PushProduction PushEnvironment = "production"
)

type PushDeviceRegistration struct {
	Token       string          `json:"token"`
	Environment PushEnvironment `json:"environment"`
	Locale      string          `json:"locale"`
}
