package application

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/httpapi"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/session"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/terminal"
)

type Application struct {
	config Config
	deps   Dependencies

	runtimeMu     sync.Mutex
	running       map[string]bool
	starting      map[string]chan struct{}
	mutationMu    sync.Mutex
	mutationLocks map[string]*mutationGate
	secretLocks   map[string]*mutationGate
	terminalLocks map[string]*mutationGate
	// terminalSetupLimit bounds work performed while terminal issuance holds a
	// device revocation gate. It is configurable only inside this package so
	// deterministic tests can exercise timeout and cancellation behavior.
	terminalSetupLimit time.Duration
}

type mutationGate struct {
	mu   sync.Mutex
	refs int
}

type utcClock struct{}

func (utcClock) Now() time.Time { return time.Now().UTC() }

var hostnamePattern = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$`)

func New(config Config, deps Dependencies) (*Application, error) {
	if deps.Health == nil || deps.Passkeys == nil || deps.Bootstrap == nil || deps.Sessions == nil ||
		deps.Repositories == nil || deps.Workspaces == nil || deps.WorkspaceStore == nil || deps.State == nil ||
		deps.SetupReviews == nil || deps.Coder == nil || deps.Terminals == nil {
		return nil, errors.New("application dependencies are required")
	}
	if config.GitHubConfigured && (deps.GitHub == nil || deps.Connections == nil) {
		return nil, errors.New("GitHub application and connection dependencies are required when configured")
	}
	if config.PreviewsConfigured && (deps.PreviewTokens == nil || deps.PreviewTunnels == nil) {
		return nil, errors.New("preview token and tunnel dependencies are required when previews are configured")
	}
	if config.APNSConfigured && deps.Notifications == nil {
		return nil, errors.New("activity notification dependency is required when APNs is configured")
	}
	if config.MaximumRunningWorkspaces < 1 || config.MaximumRunningWorkspaces > 1000 {
		return nil, errors.New("maximum running workspaces must be between 1 and 1000")
	}
	terminalURL, err := url.Parse(config.TerminalWebSocketURL)
	if err != nil || (terminalURL.Scheme != "ws" && terminalURL.Scheme != "wss") || terminalURL.Host == "" ||
		terminalURL.User != nil || terminalURL.RawQuery != "" || terminalURL.Fragment != "" {
		return nil, errors.New("terminal WebSocket URL must be an absolute ws or wss URL")
	}
	if config.PreviewsConfigured {
		config.PreviewDomain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(config.PreviewDomain), "."))
		if len(config.PreviewDomain) > 253 || !hostnamePattern.MatchString(config.PreviewDomain) {
			return nil, errors.New("preview domain must be a valid hostname")
		}
	}
	if config.APNSConfigured && (config.APNSTopic == "" || len(config.APNSTopic) > 255 || strings.ContainsAny(config.APNSTopic, "\x00\r\n")) {
		return nil, errors.New("APNs topic is required when APNs is configured")
	}
	if config.PreviewAccessTTL == 0 {
		config.PreviewAccessTTL = 5 * time.Minute
	}
	if config.PreviewAccessTTL < time.Second || config.PreviewAccessTTL > 10*time.Minute {
		return nil, errors.New("preview access TTL must be between one second and ten minutes")
	}
	if config.DefaultDeviceName == "" {
		config.DefaultDeviceName = "iPhone"
	}
	if len(config.DefaultDeviceName) > 120 || strings.ContainsAny(config.DefaultDeviceName, "\x00\r\n") {
		return nil, errors.New("default passkey device name is invalid")
	}
	if config.FileSearchLimit == 0 {
		config.FileSearchLimit = 200
	}
	if config.FileSearchLimit < 1 || config.FileSearchLimit > 500 {
		return nil, errors.New("file search limit must be between 1 and 500")
	}
	if config.InitialTerminalSize.Rows == 0 || config.InitialTerminalSize.Columns == 0 {
		config.InitialTerminalSize = terminal.Size{Rows: 24, Columns: 80}
	}
	if deps.Clock == nil {
		deps.Clock = utcClock{}
	}
	if deps.Random == nil {
		deps.Random = rand.Reader
	}
	return &Application{
		config:             config,
		deps:               deps,
		running:            make(map[string]bool),
		starting:           make(map[string]chan struct{}),
		mutationLocks:      make(map[string]*mutationGate),
		secretLocks:        make(map[string]*mutationGate),
		terminalLocks:      make(map[string]*mutationGate),
		terminalSetupLimit: defaultTerminalRuntimeSetupTimeout,
	}, nil
}

// acquireTerminalAdmission serializes every device-bound ephemeral authority
// (terminal tickets, preview grants, and APNs registration) with session/device
// revocation for exactly one owner/device pair. Callers revalidate durable
// session state while the gate is held, so a request authenticated before
// revocation cannot mint or reactivate authority after the revocation sweep.
// Entries disappear after the final holder/waiter releases.
func (a *Application) acquireTerminalAdmission(ownerID, deviceID string) func() {
	key := fmt.Sprintf("%d:%s:%s", len(ownerID), ownerID, deviceID)
	return a.acquireIndexedMutation(&a.terminalLocks, key)
}

// acquireWorkspaceMutation serializes authority and filesystem mutations for
// one workspace without retaining attacker-chosen identifiers forever.
func (a *Application) acquireWorkspaceMutation(workspaceID string) func() {
	return a.acquireIndexedMutation(&a.mutationLocks, workspaceID)
}

// acquireSecretMutation serializes one owner's secret rotation/grant graph.
// Length-prefixing avoids aliases between hostile owner and secret IDs.
func (a *Application) acquireSecretMutation(ownerID, secretID string) func() {
	key := fmt.Sprintf("%d:%s:%s", len(ownerID), ownerID, secretID)
	return a.acquireIndexedMutation(&a.secretLocks, key)
}

// acquireIndexedMutation reference-counts holders and waiters. The entry is
// removed only after the final critical section exits, while mutationMu keeps
// a new acquirer from racing between index removal and gate unlock.
func (a *Application) acquireIndexedMutation(index *map[string]*mutationGate, key string) func() {
	a.mutationMu.Lock()
	if *index == nil {
		*index = make(map[string]*mutationGate)
	}
	gate := (*index)[key]
	if gate == nil {
		gate = &mutationGate{}
		(*index)[key] = gate
	}
	gate.refs++
	a.mutationMu.Unlock()

	gate.mu.Lock()
	return func() {
		a.mutationMu.Lock()
		gate.refs--
		if gate.refs == 0 && (*index)[key] == gate {
			delete(*index, key)
		}
		gate.mu.Unlock()
		a.mutationMu.Unlock()
	}
}

func (a *Application) Health(ctx context.Context) error {
	return a.deps.Health.Ping(ctx)
}

func (a *Application) newID(prefix string) (string, error) {
	buffer := make([]byte, 16)
	if _, err := io.ReadFull(a.deps.Random, buffer); err != nil {
		return "", fmt.Errorf("generate %s identity: %w", prefix, err)
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(buffer), nil
}

func (a *Application) audit(principal httpapi.Principal, workspaceID, action, result, targetType, targetID string, details map[string]any) {
	switch result {
	case "success", "denied", "failed", "cancelled":
	default:
		// The durable schema intentionally has a closed result vocabulary. Fail
		// safe here so a future call-site typo cannot silently discard a
		// security-relevant audit event at the persistence boundary.
		normalized := make(map[string]any, len(details)+1)
		for key, value := range details {
			normalized[key] = value
		}
		normalized["audit_result_normalized"] = true
		details = normalized
		result = "failed"
	}
	data := json.RawMessage(`{}`)
	if len(details) != 0 {
		if encoded, err := json.Marshal(details); err == nil {
			data = encoded
		}
	}
	// Auditing is intentionally best-effort after the authoritative mutation.
	// Retrying an already successful create, commit, or approval solely because
	// the audit sink is unavailable would duplicate or corrupt user state.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = a.deps.State.Audit(ctx, principal.OwnerID, principal.DeviceID, workspaceID, action, result, targetType, targetID, data, a.deps.Clock.Now())
}

func invalid(cause error) error {
	if cause == nil {
		cause = errors.New("invalid input")
	}
	return fmt.Errorf("%w: %v", core.ErrInvalid, cause)
}

func unauthorized(cause error) error {
	if cause == nil {
		cause = errors.New("authentication failed")
	}
	return fmt.Errorf("%w: %v", core.ErrUnauthorized, cause)
}

func external(cause error) error {
	if cause == nil {
		cause = errors.New("provider failed")
	}
	if errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) ||
		errors.Is(cause, core.ErrNotFound) || errors.Is(cause, core.ErrConflict) || errors.Is(cause, core.ErrInvalid) ||
		errors.Is(cause, core.ErrForbidden) || errors.Is(cause, core.ErrPrecondition) || errors.Is(cause, core.ErrCapacity) ||
		errors.Is(cause, core.ErrOwnerActionNeeded) || errors.Is(cause, core.ErrExternal) {
		return cause
	}
	return fmt.Errorf("%w: %v", core.ErrExternal, cause)
}

type Authenticator struct {
	sessions SessionAuthenticator
}

func NewAuthenticator(sessions SessionAuthenticator) (*Authenticator, error) {
	if sessions == nil {
		return nil, errors.New("session authenticator is required")
	}
	return &Authenticator{sessions: sessions}, nil
}

func (a *Authenticator) Authenticate(ctx context.Context, token string) (httpapi.Principal, error) {
	principal, err := a.sessions.Authenticate(ctx, token)
	if err != nil {
		return httpapi.Principal{}, unauthorized(err)
	}
	if principal.OwnerID == "" || principal.DeviceID == "" || principal.FamilyID == "" {
		return httpapi.Principal{}, unauthorized(errors.New("incomplete session principal"))
	}
	return httpapi.Principal{OwnerID: principal.OwnerID, DeviceID: principal.DeviceID, FamilyID: principal.FamilyID}, nil
}

var _ httpapi.Application = (*Application)(nil)
var _ httpapi.Authenticator = (*Authenticator)(nil)
var _ SessionAuthenticator = (*session.Manager)(nil)
