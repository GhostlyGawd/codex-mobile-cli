package application

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/checkpoint"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/coder"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/githubapp"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/maintenance"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/passkeys"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/postgres"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/preview"
	secretmodel "github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/secrets"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/session"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/terminal"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/workspace"
)

// Config contains only public application policy. Provider credentials remain
// in their owning clients and are never copied into the application layer.
type Config struct {
	GitHubConfigured         bool
	APNSConfigured           bool
	PreviewsConfigured       bool
	MaximumRunningWorkspaces int

	TerminalWebSocketURL string
	PreviewDomain        string
	PreviewAccessTTL     time.Duration
	APNSTopic            string
	DefaultDeviceName    string
	FileSearchLimit      int
	InitialTerminalSize  terminal.Size
}

type HealthChecker interface {
	Ping(context.Context) error
}

type PasskeyService interface {
	BeginBootstrapRegistration(context.Context, string, passkeys.DeviceBinding) (passkeys.RegistrationStart, error)
	FinishBootstrapRegistration(context.Context, string, string, passkeys.DeviceBinding, []byte) (passkeys.LoginResult, error)
	BeginAdditionalRegistration(context.Context, string, string, passkeys.DeviceBinding) (passkeys.RegistrationStart, error)
	FinishAdditionalRegistration(context.Context, string, string, string, passkeys.DeviceBinding, []byte) (passkeys.CredentialMetadata, error)
	ListCredentials(context.Context, string) ([]passkeys.CredentialMetadata, error)
	RevokeCredential(context.Context, string, string) error
	BeginLogin(context.Context, passkeys.DeviceBinding) (passkeys.LoginStart, error)
	FinishLogin(context.Context, string, passkeys.DeviceBinding, []byte) (passkeys.LoginResult, error)
}

type BootstrapAvailability interface {
	Available(context.Context) (bool, error)
}

type SessionService interface {
	Issue(context.Context, string, string) (session.Pair, error)
	RefreshPrincipal(context.Context, string) (session.Principal, error)
	Rotate(context.Context, string) (session.Pair, error)
	RevokeFamily(context.Context, string) error
	Authenticate(context.Context, string) (session.Principal, error)
	ValidatePrincipal(context.Context, session.Principal) error
	ListDevices(context.Context, string) ([]session.Device, error)
	RevokeDevice(context.Context, string, string) error
}

type SessionAuthenticator interface {
	Authenticate(context.Context, string) (session.Principal, error)
}

type RepositoryStore interface {
	Get(context.Context, string, string) (core.Repository, error)
	ListViews(context.Context, string) ([]postgres.RepositoryView, error)
	MarkUsed(context.Context, string, string, time.Time) error
}

type ConnectionStore interface {
	githubapp.TokenUseStore
	ListGitHubInstallations(context.Context, string) ([]postgres.GitHubInstallationConnection, error)
	WithGitHubInstallationLease(context.Context, string, int64, func(context.Context) error) error
	DisconnectGitHubInstallation(context.Context, string, int64, time.Time) error
}

type WorkspaceOperations interface {
	Create(context.Context, string, core.CreateWorkspaceInput) (core.Workspace, error)
	ApproveSetup(context.Context, string, string) (core.Workspace, error)
	DenySetup(context.Context, string, string) (core.Workspace, error)
	Retry(context.Context, string, string) (core.Workspace, error)
	Suspend(context.Context, string, string) (core.Workspace, error)
	Resume(context.Context, string, string) (core.Workspace, error)
	Delete(context.Context, string, string, bool, bool) error
	TouchActivity(context.Context, string, string, time.Time) (core.Workspace, error)
	UpdatePolicy(context.Context, string, string, core.RetentionPolicy, int) (core.Workspace, error)
	UpdateSafetyMode(context.Context, string, string, core.SafetyMode) (core.Workspace, error)
}

type WorkspaceStore interface {
	Get(context.Context, string, string) (core.Workspace, error)
	Save(context.Context, core.Workspace) error
	List(context.Context, string) ([]core.Workspace, error)
	TouchActivity(context.Context, string, string, time.Time) error
	UpdateGitRisk(context.Context, string, string, bool, bool, time.Time) error
}

type SetupReviewReconciler interface {
	Ensure(context.Context, core.Workspace, time.Time) error
}

type ApplicationStore interface {
	GetSettings(context.Context, string) (postgres.Settings, error)
	SaveSettings(context.Context, string, postgres.Settings, time.Time) error
	CreateSecret(context.Context, secretmodel.Metadata, []byte, time.Time) (secretmodel.Metadata, error)
	ListSecrets(context.Context, string, *string) ([]secretmodel.Metadata, error)
	UpdateSecret(context.Context, string, string, []byte, time.Time) (secretmodel.Metadata, error)
	DeleteSecret(context.Context, string, string, time.Time) error
	ListSecretWorkspaceIDs(context.Context, string, string) ([]string, error)
	ListWorkspaceSecretGrants(context.Context, string, string) ([]secretmodel.WorkspaceGrant, error)
	GrantWorkspaceSecret(context.Context, string, string, string, time.Time) error
	RevokeWorkspaceSecret(context.Context, string, string, string, time.Time) error
	LoadGrantedWorkspaceSecrets(context.Context, string, string) (map[string][]byte, error)
	LoadWorkspaceInitialPrompt(context.Context, string, string, string) (string, error)
	MarkWorkspaceInitialPromptDelivered(context.Context, string, string, string, time.Time) error

	CreateTerminalTab(context.Context, postgres.TerminalTabRecord) (postgres.TerminalTabRecord, error)
	ListTerminalTabs(context.Context, string, string) ([]postgres.TerminalTabRecord, error)
	GetTerminalTab(context.Context, string, string, string) (postgres.TerminalTabRecord, error)
	RenameTerminalTab(context.Context, string, string, string, string) (postgres.TerminalTabRecord, error)
	ReorderTerminalTabs(context.Context, string, string, []string) ([]postgres.TerminalTabRecord, error)
	CloseTerminalTab(context.Context, string, string, string, time.Time) (postgres.TerminalTabRecord, bool, error)
	TouchTerminalTab(context.Context, string, string, string, time.Time) error
	SetTerminalCodexThreadID(context.Context, string, string, string, string) (postgres.TerminalTabRecord, error)

	ListActivity(context.Context, string, int) ([]postgres.ActivityRecord, error)
	AddActivity(context.Context, string, postgres.ActivityRecord) error
	GetSafetyEvent(context.Context, string, string) (postgres.SafetyEvent, error)
	ResolveSafetyEvent(context.Context, string, string, string, string, time.Time) (postgres.SafetyEvent, error)

	SyncPreviewRoutes(context.Context, string, string, []postgres.PreviewRouteRecord, time.Time) error
	ListPreviewRoutes(context.Context, string, string) ([]postgres.PreviewRouteRecord, error)
	GetPreviewRoute(context.Context, string, string, string) (postgres.PreviewRouteRecord, error)
	RevokePreviewRoute(context.Context, string, string, string, time.Time) error

	RegisterNotification(context.Context, string, string, string, string, string, time.Time) error
	Audit(context.Context, string, string, string, string, string, string, string, json.RawMessage, time.Time) error
}

type GitHubService interface {
	InstallationToken(context.Context, int64, []int64, map[string]string) (githubapp.InstallationToken, error)
	RevokeInstallationToken(context.Context, string) error
	CreatePullRequest(context.Context, string, string, string, string, string, string, bool) (githubapp.PullRequest, error)
}

type MaintenanceService interface {
	Status(context.Context, string) (maintenance.Run, error)
	ScheduleWeekly(context.Context, string) (maintenance.Run, error)
	ScheduleUrgent(context.Context, string) (maintenance.Run, error)
	Cancel(context.Context, string, string) (maintenance.Run, error)
	BeginUpdate(context.Context, string) (maintenance.Run, error)
	UpdateApplied(context.Context, string, bool) (maintenance.Run, error)
	BeginVerification(context.Context, string) (maintenance.Run, error)
	Complete(context.Context, string) (maintenance.Run, error)
}

// WorkspaceRuntime is the single privileged boundary into a Coder workspace.
// Its helper input is a bounded JSON protocol and terminal creation returns the
// narrow terminal.Runtime contract rather than exposing the Coder PTY object.
type WorkspaceRuntime interface {
	RunHelper(context.Context, string, []byte) ([]byte, error)
	AgentID(context.Context, string) (string, error)
	ListeningPorts(context.Context, string) ([]coder.Port, error)
	OpenPTY(coder.PTYConfig) (terminal.Runtime, error)
}

type TerminalManager interface {
	Register(string, string, terminal.TabID, terminal.Runtime, terminal.OutputRedactor, bool) error
	Unregister(terminal.TabID, string) error
	Issue(string, string, string, terminal.TabID, uint64, string) (terminal.Connection, error)
	RevokeDevice(string, string) int
}

type PreviewTokens interface {
	Issue(preview.Route, string, time.Duration) (string, time.Time, error)
	RevokeRoute(string) int
	RevokeDevice(string, string) int
}

// PreviewTunnels owns the private Coder TCP forward associated with a preview
// route. Revocation must tear down this process as well as invalidating tokens
// so stopped routes cannot consume the bounded forward pool indefinitely.
type PreviewTunnels interface {
	Revoke(string, uint16)
}

// ActivityNotifier queues only generic delivery metadata for an activity that
// is already durably stored by the application.
type ActivityNotifier interface {
	NotifyActivity(ownerID, activityID, kind, deepLinkPath string) bool
}

// CheckpointOperations keeps local recovery persistence and hostile-archive
// validation behind a narrow, fakeable boundary.
type CheckpointOperations interface {
	CreateRequired(context.Context, string, string, string) (string, bool, bool, error)
	ListVerified(context.Context, string) ([]checkpoint.VerifiedMetadata, error)
	RestoreFileProtected(context.Context, string, string, string, string, bool) (string, error)
	RestoreWorkspace(context.Context, string, string, string, bool) (checkpoint.RestoreWorkspaceResult, error)
}

type Clock interface {
	Now() time.Time
}

type Dependencies struct {
	Health         HealthChecker
	Passkeys       PasskeyService
	Bootstrap      BootstrapAvailability
	Sessions       SessionService
	Repositories   RepositoryStore
	Connections    ConnectionStore
	Workspaces     WorkspaceOperations
	WorkspaceStore WorkspaceStore
	SetupReviews   SetupReviewReconciler
	State          ApplicationStore
	GitHub         GitHubService
	Coder          WorkspaceRuntime
	Terminals      TerminalManager
	PreviewTokens  PreviewTokens
	PreviewTunnels PreviewTunnels
	Notifications  ActivityNotifier
	Maintenance    MaintenanceService
	Checkpoints    CheckpointOperations
	Clock          Clock
	Random         io.Reader
}

// CoderAdapter makes the concrete Coder client satisfy the fakeable
// WorkspaceRuntime boundary without weakening its PTY return type.
type CoderAdapter struct {
	client *coder.Client
}

func NewCoderAdapter(client *coder.Client) (*CoderAdapter, error) {
	if client == nil {
		return nil, errors.New("Coder client is required")
	}
	return &CoderAdapter{client: client}, nil
}

func (a *CoderAdapter) RunHelper(ctx context.Context, workspaceID string, request []byte) ([]byte, error) {
	return a.client.RunHelper(ctx, workspaceID, request)
}

func (a *CoderAdapter) AgentID(ctx context.Context, workspaceID string) (string, error) {
	return a.client.AgentID(ctx, workspaceID)
}

func (a *CoderAdapter) ListeningPorts(ctx context.Context, agentID string) ([]coder.Port, error) {
	return a.client.ListeningPorts(ctx, agentID)
}

func (a *CoderAdapter) OpenPTY(config coder.PTYConfig) (terminal.Runtime, error) {
	return a.client.OpenPTY(config)
}

var _ WorkspaceRuntime = (*CoderAdapter)(nil)
var _ PasskeyService = (*passkeys.Service)(nil)
var _ BootstrapAvailability = (*passkeys.BootstrapManager)(nil)
var _ SessionService = (*session.Manager)(nil)
var _ RepositoryStore = (*postgres.RepositoryStore)(nil)
var _ WorkspaceOperations = (*workspace.Service)(nil)
var _ WorkspaceStore = (*postgres.WorkspaceStore)(nil)
var _ ApplicationStore = (*postgres.ApplicationStore)(nil)
var _ GitHubService = (*githubapp.Client)(nil)
var _ TerminalManager = (*terminal.Manager)(nil)
var _ PreviewTokens = (*preview.TokenManager)(nil)
var _ PreviewTunnels = (*coder.PortForwardManager)(nil)
var _ MaintenanceService = (*maintenance.Coordinator)(nil)
var _ CheckpointOperations = (*checkpoint.Service)(nil)
