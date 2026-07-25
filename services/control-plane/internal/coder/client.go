package coder

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/workspace"
)

const (
	maxResponseBytes        = 8 << 20
	maximumRememberedQuotas = 4096
	workspacePollInterval   = 250 * time.Millisecond
	workspaceStartTimeout   = 5 * time.Minute
	workspaceStopTimeout    = 5 * time.Minute
	workspaceDeleteTimeout  = 5 * time.Minute
	workspaceHelperTimeout  = 5 * time.Minute
	helperProcessWaitDelay  = 5 * time.Second
	helperRemoteDrainMargin = 5 * time.Second
)

const defaultWorkspaceHelperPath = "/opt/codex-mobile-helper/codex-mobile-workspace-helper"
const trustedHelperWorkingDirectory = "/"

const maximumWorkspaceMemoryMiB = 18 * 1024

type Config struct {
	URL                 string
	Token               string
	OrganizationID      string
	OwnerID             string
	TemplateID          string
	CLIPath             string
	WorkspaceHelperPath string
	HTTPClient          *http.Client
}

type Client struct {
	base                *url.URL
	token               string
	organizationID      string
	ownerID             string
	templateID          string
	cliPath             string
	workspaceHelperPath string
	http                *http.Client
	commandContext      func(context.Context, string, ...string) *exec.Cmd
	startTimeout        time.Duration
	stopTimeout         time.Duration
	helperTimeout       time.Duration
	mu                  sync.Mutex
	quotas              map[string]core.Quota
}

type parameter struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type workspaceResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	LatestBuild struct {
		ID         string `json:"id"`
		Status     string `json:"status"`
		Transition string `json:"transition"`
		Resources  []struct {
			Agents []struct {
				ID        string `json:"id"`
				Name      string `json:"name"`
				Status    string `json:"status"`
				Directory string `json:"directory"`
			} `json:"agents"`
		} `json:"resources"`
	} `json:"latest_build"`
}

type workspaceBuildResponse struct {
	ID         string `json:"id"`
	Status     string `json:"status"`
	Transition string `json:"transition"`
}

type apiStatusError struct {
	status  int
	message string
}

func (e *apiStatusError) Error() string {
	return fmt.Sprintf("Coder API status %d: %s", e.status, e.message)
}

func hasAPIStatus(err error, status int) bool {
	var apiError *apiStatusError
	return errors.As(err, &apiError) && apiError.status == status
}

type Port struct {
	Network     string `json:"network"`
	Port        int    `json:"port"`
	ProcessName string `json:"process_name"`
}

func New(cfg Config) (*Client, error) {
	base, err := url.Parse(cfg.URL)
	if err != nil || base.Scheme == "" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("Coder URL must be an absolute URL without credentials, query, or fragment")
	}
	if cfg.Token == "" || cfg.OrganizationID == "" || cfg.OwnerID == "" || cfg.TemplateID == "" {
		return nil, errors.New("Coder token, organization, owner, and template IDs are required")
	}
	for _, value := range []string{cfg.OrganizationID, cfg.OwnerID, cfg.TemplateID} {
		if !safeIdentifier.MatchString(value) {
			return nil, errors.New("invalid Coder identifier")
		}
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.CLIPath == "" {
		cfg.CLIPath = "coder"
	}
	if cfg.WorkspaceHelperPath == "" {
		cfg.WorkspaceHelperPath = defaultWorkspaceHelperPath
	}
	if strings.ContainsAny(cfg.CLIPath, "\x00\r\n") || strings.ContainsAny(cfg.WorkspaceHelperPath, "\x00\r\n") || !strings.HasPrefix(cfg.WorkspaceHelperPath, "/") {
		return nil, errors.New("invalid Coder CLI or workspace helper path")
	}
	base.Path = strings.TrimRight(base.Path, "/")
	return &Client{
		base: base, token: cfg.Token, organizationID: cfg.OrganizationID, ownerID: cfg.OwnerID, templateID: cfg.TemplateID,
		cliPath: cfg.CLIPath, workspaceHelperPath: cfg.WorkspaceHelperPath,
		http: cfg.HTTPClient, commandContext: exec.CommandContext,
		startTimeout: workspaceStartTimeout, stopTimeout: workspaceStopTimeout, helperTimeout: workspaceHelperTimeout,
		quotas: make(map[string]core.Quota),
	}, nil
}

// RunHelper executes the single audited helper inside a running Coder
// workspace. The remote command is fixed; callers can supply only the
// helper's bounded JSON protocol on stdin. The Coder credential is placed in
// the trusted local child process environment and is never forwarded to the
// workspace or included in command arguments.
func (c *Client) RunHelper(ctx context.Context, workspaceID string, request []byte) ([]byte, error) {
	if ctx == nil || !uuidPattern.MatchString(workspaceID) || len(request) == 0 || len(request) > maxResponseBytes {
		return nil, fmt.Errorf("%w: invalid workspace helper request", core.ErrInvalid)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	helperTimeout := c.helperTimeout
	if helperTimeout <= 0 {
		helperTimeout = workspaceHelperTimeout
	}
	helperContext, cancel := context.WithTimeout(ctx, helperTimeout)
	defer cancel()
	deadline, ok := helperContext.Deadline()
	if !ok {
		return nil, errors.New("Coder workspace helper deadline is unavailable")
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return nil, context.DeadlineExceeded
	}
	margin := helperRemoteDrainMargin
	if maximum := remaining / 4; margin > maximum {
		margin = maximum
	}
	remoteDeadline := deadline.Add(-margin)
	preparedRequest, err := helperRequestWithDeadline(request, remoteDeadline)
	if err != nil {
		return nil, err
	}
	defer clear(preparedRequest)
	commandContext := c.commandContext
	if commandContext == nil {
		commandContext = exec.CommandContext
	}
	args := helperCommandArguments(workspaceID, c.workspaceHelperPath)
	cmd := commandContext(helperContext, c.cliPath, args...)
	// The service process may be started from a repository, release staging
	// directory, or another attacker-influenced current directory. The local
	// Coder CLI never needs it, so run from the fixed host root instead.
	cmd.Dir = trustedHelperWorkingDirectory
	cmd.Env = helperEnvironment(c.base.String(), c.token)
	cmd.Stdin = bytes.NewReader(preparedRequest)
	cmd.WaitDelay = helperProcessWaitDelay
	var stdout, stderr limitedBuffer
	stdout.limit = maxResponseBytes
	stderr.limit = 64 << 10
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		if contextErr := helperContext.Err(); contextErr != nil {
			return nil, newRemoteHelperAmbiguityError(fmt.Errorf("Coder workspace helper interrupted: %w", contextErr), remoteDeadline)
		}
		// Coder's diagnostic output is deliberately not reflected because it can
		// contain network or workspace metadata. The exit type is sufficient for
		// server-side logging without exposing credentials to API clients.
		if stdout.overflow || stderr.overflow {
			return nil, newRemoteHelperAmbiguityError(errors.New("Coder workspace helper output exceeded size limit"), remoteDeadline)
		}
		return nil, newRemoteHelperAmbiguityError(fmt.Errorf("Coder workspace helper failed: %w", err), remoteDeadline)
	}
	if stdout.overflow {
		return nil, errors.New("Coder workspace helper output exceeded size limit")
	}
	return append([]byte(nil), stdout.Bytes()...), nil
}

// RemoteHelperAmbiguityError reports the independently enforced deadline of a
// remote helper whose exit could not be observed after the local Coder SSH
// process failed. Installation-token coordination uses this deadline to keep
// durable authority outstanding until remote work is known to be bounded.
type RemoteHelperAmbiguityError struct {
	cause     error
	safeAfter time.Time
}

func newRemoteHelperAmbiguityError(cause error, safeAfter time.Time) error {
	return &RemoteHelperAmbiguityError{cause: cause, safeAfter: safeAfter.UTC()}
}

func (e *RemoteHelperAmbiguityError) Error() string {
	if e == nil || e.cause == nil {
		return "Coder workspace helper exit is ambiguous"
	}
	return e.cause.Error()
}

func (e *RemoteHelperAmbiguityError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func (e *RemoteHelperAmbiguityError) GitHubTokenUseSafeAfter() time.Time {
	if e == nil {
		return time.Time{}
	}
	return e.safeAfter
}

func helperRequestWithDeadline(request []byte, deadline time.Time) ([]byte, error) {
	if len(request) == 0 || deadline.IsZero() || !deadline.After(time.Now()) {
		return nil, fmt.Errorf("%w: invalid workspace helper deadline", core.ErrInvalid)
	}
	decoder := json.NewDecoder(bytes.NewReader(request))
	decoder.DisallowUnknownFields()
	var envelope map[string]json.RawMessage
	if err := decoder.Decode(&envelope); err != nil || envelope == nil {
		return nil, fmt.Errorf("%w: invalid workspace helper request", core.ErrInvalid)
	}
	defer func() {
		for name, value := range envelope {
			clear(value)
			delete(envelope, name)
		}
	}()
	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		clear(extra)
		return nil, fmt.Errorf("%w: invalid workspace helper request", core.ErrInvalid)
	}
	clear(extra)
	if _, exists := envelope["operation_deadline_unix_milli"]; exists {
		return nil, fmt.Errorf("%w: workspace helper deadline is control-plane-owned", core.ErrInvalid)
	}
	encodedDeadline, err := json.Marshal(deadline.UTC().UnixMilli())
	if err != nil {
		return nil, fmt.Errorf("%w: invalid workspace helper deadline", core.ErrInvalid)
	}
	envelope["operation_deadline_unix_milli"] = encodedDeadline
	prepared, err := json.Marshal(envelope)
	if err != nil || len(prepared) > maxResponseBytes {
		clear(prepared)
		return nil, fmt.Errorf("%w: invalid workspace helper request", core.ErrInvalid)
	}
	return prepared, nil
}

func helperCommandArguments(workspaceID, helperPath string) []string {
	return []string{"ssh", "--disable-autostart", "--wait", "yes", workspaceID, "--", helperPath}
}

func helperEnvironment(coderURL, token string) []string {
	// Preserve only the operating-system variables required to locate trust
	// stores and execute the CLI. In particular, no application secret is
	// inherited by the child process.
	allowed := map[string]bool{
		"HOME": true, "PATH": true, "Path": true, "SystemRoot": true, "WINDIR": true,
		"TMPDIR": true, "TMP": true, "TEMP": true, "SSL_CERT_FILE": true,
		"SSL_CERT_DIR": true,
	}
	env := make([]string, 0, len(allowed)+4)
	for _, entry := range os.Environ() {
		name, _, ok := strings.Cut(entry, "=")
		if ok && allowed[name] {
			env = append(env, entry)
		}
	}
	return append(env,
		"CODER_URL="+coderURL,
		"CODER_SESSION_TOKEN="+token,
		"CODER_NO_VERSION_WARNING=true",
		"CODER_NO_FEATURE_WARNING=true",
		"CODER_DISABLE_NETWORK_TELEMETRY=true",
		"CODER_DISABLE_DIRECT_CONNECTIONS=true",
	)
}

type limitedBuffer struct {
	bytes.Buffer
	limit    int
	overflow bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	remaining := b.limit - b.Len()
	if remaining <= 0 {
		b.overflow = true
		return len(p), nil
	}
	if len(p) > remaining {
		b.overflow = true
		_, _ = b.Buffer.Write(p[:remaining])
		return len(p), nil
	}
	return b.Buffer.Write(p)
}

func (c *Client) Provision(ctx context.Context, request workspace.ProvisionRequest) (string, error) {
	if request.WorkspaceID == "" || request.Repository.ID == "" || !validWorkspaceQuota(request.Quota) ||
		!request.SafetyMode.Valid() || !validDevcontainerDirectory(request.DevcontainerDir) {
		return "", fmt.Errorf("%w: invalid Coder provision request", core.ErrInvalid)
	}
	if existingID, err := c.LookupProvisioned(ctx, request.WorkspaceID); err == nil {
		return existingID, nil
	} else if !errors.Is(err, core.ErrNotFound) {
		return "", fmt.Errorf("look up Coder workspace before create: %w", err)
	}
	body := struct {
		Name                string      `json:"name"`
		TemplateID          string      `json:"template_id"`
		AutomaticUpdates    string      `json:"automatic_updates"`
		RichParameterValues []parameter `json:"rich_parameter_values"`
	}{
		Name: providerWorkspaceName(request.WorkspaceID), TemplateID: c.templateID,
		AutomaticUpdates: "never", RichParameterValues: provisionParameters(request),
	}
	var response workspaceResponse
	// The user route is the non-deprecated v2.34.6 endpoint. Organization ID is
	// retained in configuration for template/bootstrap administration only.
	path := "/api/v2/users/" + url.PathEscape(c.ownerID) + "/workspaces"
	if err := c.doJSON(ctx, http.MethodPost, path, body, &response); err != nil {
		// A transport failure or malformed success response is ambiguous: Coder
		// may have committed the create even though its response was lost. The
		// deterministic user/name lookup is authoritative and prevents a retry
		// from creating a second provider runtime.
		if recoveredID, recoveryErr := c.LookupProvisioned(ctx, request.WorkspaceID); recoveryErr == nil {
			return recoveredID, nil
		} else if !errors.Is(recoveryErr, core.ErrNotFound) {
			return "", fmt.Errorf("create Coder workspace: %w (post-create lookup: %v)", err, recoveryErr)
		}
		return "", fmt.Errorf("create Coder workspace: %w", err)
	}
	if !safeIdentifier.MatchString(response.ID) {
		if recoveredID, err := c.LookupProvisioned(ctx, request.WorkspaceID); err == nil {
			return recoveredID, nil
		}
		return "", errors.New("Coder returned an invalid workspace ID")
	}
	return response.ID, nil
}

// LookupProvisioned performs the official user/name lookup used to reconcile
// response loss. The provider name is a collision-resistant digest of the
// immutable logical workspace ID and therefore remains stable across process
// restarts and retries.
func (c *Client) LookupProvisioned(ctx context.Context, workspaceID string) (string, error) {
	if ctx == nil || workspaceID == "" || len(workspaceID) > 512 || strings.ContainsAny(workspaceID, "\x00\r\n") {
		return "", fmt.Errorf("%w: invalid logical workspace ID", core.ErrInvalid)
	}
	name := providerWorkspaceName(workspaceID)
	var response workspaceResponse
	path := "/api/v2/users/" + url.PathEscape(c.ownerID) + "/workspace/" + url.PathEscape(name)
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &response); err != nil {
		if hasAPIStatus(err, http.StatusNotFound) {
			return "", core.ErrNotFound
		}
		return "", err
	}
	if !safeIdentifier.MatchString(response.ID) {
		return "", errors.New("Coder returned an invalid workspace ID")
	}
	if response.Name != "" && response.Name != name {
		return "", errors.New("Coder returned a mismatched workspace name")
	}
	return response.ID, nil
}

func (c *Client) Health(ctx context.Context) error {
	if ctx == nil {
		return errors.New("Coder health context is required")
	}
	var response struct {
		ID string `json:"id"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/api/v2/users/me", nil, &response); err != nil {
		return fmt.Errorf("Coder health check: %w", err)
	}
	if response.ID == "" {
		return errors.New("Coder health check returned no user identity")
	}
	return nil
}

func (c *Client) Start(ctx context.Context, workspaceID string, request workspace.StartRequest) error {
	if !request.SafetyMode.Valid() || !validWorkspaceQuota(request.Quota) {
		return fmt.Errorf("%w: invalid Coder start request", core.ErrInvalid)
	}
	return c.startIdempotent(ctx, workspaceID, startParameters(request))
}

// StartWithSetup changes the persisted Coder rich parameters only after the
// control plane has populated the plain workspace and recorded a structured
// owner decision. Unsupported configurations explicitly remain in plain mode.
func (c *Client) StartWithSetup(ctx context.Context, providerID string, request workspace.SetupStartRequest) error {
	if !safeIdentifier.MatchString(providerID) || request.WorkspaceID == "" ||
		(request.ConfigDirectory != "." && request.ConfigDirectory != ".devcontainer") ||
		!request.SafetyMode.Valid() || !validWorkspaceQuota(request.Quota) {
		return fmt.Errorf("%w: invalid approved setup start", core.ErrInvalid)
	}
	return c.startIdempotent(ctx, providerID, setupParameters(request))
}

func (c *Client) startIdempotent(ctx context.Context, workspaceID string, parameters []parameter) error {
	if ctx == nil || !safeIdentifier.MatchString(workspaceID) {
		return fmt.Errorf("%w: invalid Coder workspace start", core.ErrInvalid)
	}
	startTimeout := c.startTimeout
	if startTimeout <= 0 {
		startTimeout = workspaceStartTimeout
	}
	startContext, cancel := context.WithTimeout(ctx, startTimeout)
	defer cancel()

	value, err := c.Workspace(startContext, workspaceID)
	if err != nil {
		return err
	}
	if activeStart(value) {
		_, err = c.waitForStartBuild(startContext, workspaceID, value.LatestBuild.ID)
		return err
	}
	previousBuildID := value.LatestBuild.ID
	build, err := c.startBuild(startContext, workspaceID, parameters)
	if err != nil {
		// Recover an accepted build whose response was lost. Retrying the POST
		// without this read can enqueue duplicate builds and apply setup twice.
		return c.recoverAcceptedStart(startContext, workspaceID, previousBuildID, err)
	}
	_, err = c.waitForStartBuild(startContext, workspaceID, build.ID)
	return err
}

func (c *Client) recoverAcceptedStart(ctx context.Context, workspaceID, previousBuildID string, requestErr error) error {
	recovered, recoveryErr := c.Workspace(ctx, workspaceID)
	if recoveryErr != nil {
		return errors.Join(requestErr, fmt.Errorf("recover ambiguous Coder start build: %w", recoveryErr))
	}
	if !activeStart(recovered) || recovered.LatestBuild.ID == previousBuildID {
		return requestErr
	}
	if _, waitErr := c.waitForStartBuild(ctx, workspaceID, recovered.LatestBuild.ID); waitErr != nil {
		return errors.Join(requestErr, waitErr)
	}
	return nil
}

// waitForStartBuild is the provider readiness barrier used by ordinary
// starts, approved setup starts, and quota rebalances. Coder's build POST is
// asynchronous; only the exact build reaching running proves that Terraform
// and the container cgroup changes are applied. A different latest build means
// an external mutation superseded our authority and therefore fails closed.
func (c *Client) waitForStartBuild(ctx context.Context, workspaceID, buildID string) (workspaceResponse, error) {
	if ctx == nil || !safeIdentifier.MatchString(workspaceID) || !uuidPattern.MatchString(buildID) {
		return workspaceResponse{}, errors.New("invalid Coder start build identity")
	}
	for {
		value, err := c.Workspace(ctx, workspaceID)
		if err != nil {
			return workspaceResponse{}, err
		}
		if value.LatestBuild.ID != buildID || value.LatestBuild.Transition != "start" {
			return workspaceResponse{}, errors.New("Coder start build was superseded before readiness")
		}
		switch value.LatestBuild.Status {
		case "running":
			return value, nil
		case "pending", "starting", "canceling":
			// Continue below. Canceling is not a successful terminal state and
			// must be observed through canceled/failed or the bounded deadline.
		case "failed", "canceled":
			return workspaceResponse{}, errors.New("Coder workspace start did not complete cleanly")
		default:
			return workspaceResponse{}, errors.New("Coder returned an invalid start build status")
		}
		timer := time.NewTimer(workspacePollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return workspaceResponse{}, ctx.Err()
		case <-timer.C:
		}
	}
}

func activeStart(value workspaceResponse) bool {
	if value.LatestBuild.Transition != "start" {
		return false
	}
	switch value.LatestBuild.Status {
	case "pending", "starting", "running":
		return true
	default:
		return false
	}
}

func (c *Client) Stop(ctx context.Context, workspaceID string) error {
	return c.build(ctx, workspaceID, "stop", nil)
}

// StopAndWait does not expose a suspension or setup-approval boundary until
// Coder confirms the build has stopped. A mere accepted stop request would
// allow an autonomy change or immediate approval to race a live container.
func (c *Client) StopAndWait(ctx context.Context, workspaceID string) error {
	if ctx == nil || !safeIdentifier.MatchString(workspaceID) {
		return fmt.Errorf("%w: invalid Coder workspace stop", core.ErrInvalid)
	}
	stopTimeout := c.stopTimeout
	if stopTimeout <= 0 {
		stopTimeout = workspaceStopTimeout
	}
	stopContext, cancel := context.WithTimeout(ctx, stopTimeout)
	defer cancel()

	value, err := c.Workspace(stopContext, workspaceID)
	if hasAPIStatus(err, http.StatusNotFound) {
		c.forgetQuota(workspaceID)
		return nil
	}
	if err != nil {
		return err
	}
	if value.LatestBuild.Transition == "stop" && value.LatestBuild.Status == "stopped" {
		return nil
	}
	// Retrying a durable suspending workspace must not enqueue a second stop
	// while the first is still running. Only a non-stop or terminally failed
	// build needs a fresh provider request.
	if value.LatestBuild.Transition != "stop" || value.LatestBuild.Status == "failed" || value.LatestBuild.Status == "canceled" {
		if err := c.Stop(stopContext, workspaceID); err != nil {
			return err
		}
	}
	for {
		value, err := c.Workspace(stopContext, workspaceID)
		if hasAPIStatus(err, http.StatusNotFound) {
			c.forgetQuota(workspaceID)
			return nil
		}
		if err != nil {
			return err
		}
		if value.LatestBuild.Transition == "stop" {
			switch value.LatestBuild.Status {
			case "stopped":
				return nil
			case "failed", "canceled":
				return errors.New("Coder plain workspace did not stop cleanly")
			}
		}
		timer := time.NewTimer(workspacePollInterval)
		select {
		case <-stopContext.Done():
			timer.Stop()
			return stopContext.Err()
		case <-timer.C:
		}
	}
}

func (c *Client) Delete(ctx context.Context, workspaceID string) error {
	if ctx == nil || !safeIdentifier.MatchString(workspaceID) {
		return fmt.Errorf("%w: invalid Coder workspace deletion", core.ErrInvalid)
	}
	deleteContext, cancel := context.WithTimeout(ctx, workspaceDeleteTimeout)
	defer cancel()

	value, err := c.Workspace(deleteContext, workspaceID)
	if hasAPIStatus(err, http.StatusNotFound) {
		c.forgetQuota(workspaceID)
		return nil
	}
	if err != nil {
		return err
	}
	if value.LatestBuild.Transition != "delete" || value.LatestBuild.Status == "failed" || value.LatestBuild.Status == "canceled" {
		if err := c.build(deleteContext, workspaceID, "delete", nil); err != nil {
			if hasAPIStatus(err, http.StatusNotFound) {
				c.forgetQuota(workspaceID)
				return nil
			}
			return err
		}
	}

	for {
		value, err = c.Workspace(deleteContext, workspaceID)
		if hasAPIStatus(err, http.StatusNotFound) {
			c.forgetQuota(workspaceID)
			return nil
		}
		if err != nil {
			return err
		}
		if value.LatestBuild.Transition == "delete" && (value.LatestBuild.Status == "failed" || value.LatestBuild.Status == "canceled") {
			return errors.New("Coder workspace deletion did not complete cleanly")
		}
		timer := time.NewTimer(workspacePollInterval)
		select {
		case <-deleteContext.Done():
			timer.Stop()
			return deleteContext.Err()
		case <-timer.C:
		}
	}
}

func (c *Client) forgetQuota(workspaceID string) {
	c.mu.Lock()
	delete(c.quotas, workspaceID)
	c.mu.Unlock()
}

func (c *Client) ApplyQuota(ctx context.Context, workspaceID string, quota core.Quota) error {
	if ctx == nil || !safeIdentifier.MatchString(workspaceID) || !validWorkspaceQuota(quota) {
		return fmt.Errorf("%w: quota is outside the safe bounds", core.ErrInvalid)
	}
	c.mu.Lock()
	current, ok := c.quotas[workspaceID]
	c.mu.Unlock()
	if ok && current.DiskGiB != quota.DiskGiB {
		return fmt.Errorf("%w: persistent disk quota is immutable", core.ErrInvalid)
	}
	if ok && current == quota {
		return nil
	}
	startTimeout := c.startTimeout
	if startTimeout <= 0 {
		startTimeout = workspaceStartTimeout
	}
	quotaContext, cancel := context.WithTimeout(ctx, startTimeout)
	defer cancel()

	before, err := c.Workspace(quotaContext, workspaceID)
	if err != nil {
		return err
	}
	// Do not enqueue a quota update on top of an in-progress start. Its exact
	// build must finish first; after a process restart we cannot assume that an
	// arbitrary pre-existing build contains the requested quota.
	if activeStart(before) {
		before, err = c.waitForStartBuild(quotaContext, workspaceID, before.LatestBuild.ID)
		if err != nil {
			return err
		}
	}
	// disk_gib is immutable after workspace creation so persistent volumes are
	// never resized or replaced. Only cgroup limits participate in rebalances.
	params := runtimeQuotaParameters(quota)
	build, err := c.startBuild(quotaContext, workspaceID, params)
	if err != nil {
		if recoveryErr := c.recoverAcceptedStart(quotaContext, workspaceID, before.LatestBuild.ID, err); recoveryErr != nil {
			return recoveryErr
		}
	} else if _, err := c.waitForStartBuild(quotaContext, workspaceID, build.ID); err != nil {
		return err
	}
	c.mu.Lock()
	c.rememberQuotaLocked(workspaceID, quota)
	c.mu.Unlock()
	return nil
}

// The quota cache is a defense-in-depth check for immutable disk parameters,
// not authoritative workspace state. Bound it so long-lived create/suspend
// churn cannot grow process memory forever.
func (c *Client) rememberQuotaLocked(workspaceID string, quota core.Quota) {
	if _, exists := c.quotas[workspaceID]; !exists && len(c.quotas) >= maximumRememberedQuotas {
		for existingID := range c.quotas {
			delete(c.quotas, existingID)
			break
		}
	}
	c.quotas[workspaceID] = quota
}

func validWorkspaceQuota(quota core.Quota) bool {
	return quota.CPUMilli >= 500 &&
		quota.MemoryMiB >= 1536 && quota.MemoryMiB <= maximumWorkspaceMemoryMiB &&
		quota.DiskGiB >= core.MinimumWorkspaceDiskGiB && quota.DiskGiB <= core.MaximumWorkspaceDiskGiB
}

func (c *Client) Workspace(ctx context.Context, workspaceID string) (workspaceResponse, error) {
	if !safeIdentifier.MatchString(workspaceID) {
		return workspaceResponse{}, errors.New("invalid Coder workspace ID")
	}
	var response workspaceResponse
	err := c.doJSON(ctx, http.MethodGet, "/api/v2/workspaces/"+url.PathEscape(workspaceID), nil, &response)
	return response, err
}

func (c *Client) AgentID(ctx context.Context, workspaceID string) (string, error) {
	ws, err := c.Workspace(ctx, workspaceID)
	if err != nil {
		return "", err
	}
	for _, resource := range ws.LatestBuild.Resources {
		for _, agent := range resource.Agents {
			if safeIdentifier.MatchString(agent.ID) && agent.Status != "disconnected" {
				return agent.ID, nil
			}
		}
	}
	return "", fmt.Errorf("%w: connected Coder agent", core.ErrNotFound)
}

func (c *Client) ListeningPorts(ctx context.Context, agentID string) ([]Port, error) {
	if !safeIdentifier.MatchString(agentID) {
		return nil, errors.New("invalid Coder agent ID")
	}
	var response struct {
		Ports []Port `json:"ports"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/api/v2/workspaceagents/"+url.PathEscape(agentID)+"/listening-ports", nil, &response); err != nil {
		return nil, err
	}
	ports := response.Ports[:0]
	for _, port := range response.Ports {
		if port.Port > 0 && port.Port <= 65535 && (port.Network == "tcp" || port.Network == "tcp4" || port.Network == "tcp6") && len(port.ProcessName) <= 500 {
			ports = append(ports, port)
		}
	}
	return ports, nil
}

func (c *Client) ptyEndpoint(agentID, reconnectID, command string, columns, rows uint16) (string, http.Header, error) {
	if !safeIdentifier.MatchString(agentID) || !uuidPattern.MatchString(reconnectID) || command == "" || len(command) > 2048 || columns == 0 || rows == 0 {
		return "", nil, errors.New("invalid Coder PTY request")
	}
	u := *c.base
	if u.Scheme == "https" {
		u.Scheme = "wss"
	} else {
		u.Scheme = "ws"
	}
	u.Path += "/api/v2/workspaceagents/" + url.PathEscape(agentID) + "/pty"
	query := u.Query()
	query.Set("reconnect", reconnectID)
	query.Set("width", strconv.FormatUint(uint64(columns), 10))
	query.Set("height", strconv.FormatUint(uint64(rows), 10))
	query.Set("command", command)
	query.Set("backend_type", "buffered")
	u.RawQuery = query.Encode()
	header := make(http.Header)
	header.Set("Coder-Session-Token", c.token)
	return u.String(), header, nil
}

func (c *Client) build(ctx context.Context, workspaceID, transition string, params []parameter) error {
	if !safeIdentifier.MatchString(workspaceID) || (transition != "start" && transition != "stop" && transition != "delete") {
		return errors.New("invalid Coder build request")
	}
	body := struct {
		Transition          string      `json:"transition"`
		Reason              string      `json:"reason"`
		RichParameterValues []parameter `json:"rich_parameter_values,omitempty"`
	}{Transition: transition, Reason: "dashboard", RichParameterValues: params}
	return c.doJSON(ctx, http.MethodPost, "/api/v2/workspaces/"+url.PathEscape(workspaceID)+"/builds", body, &struct{}{})
}

func (c *Client) startBuild(ctx context.Context, workspaceID string, params []parameter) (workspaceBuildResponse, error) {
	if ctx == nil || !safeIdentifier.MatchString(workspaceID) {
		return workspaceBuildResponse{}, errors.New("invalid Coder start build request")
	}
	body := struct {
		Transition          string      `json:"transition"`
		Reason              string      `json:"reason"`
		RichParameterValues []parameter `json:"rich_parameter_values,omitempty"`
	}{Transition: "start", Reason: "dashboard", RichParameterValues: params}
	var response workspaceBuildResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/v2/workspaces/"+url.PathEscape(workspaceID)+"/builds", body, &response); err != nil {
		return workspaceBuildResponse{}, err
	}
	if !uuidPattern.MatchString(response.ID) || response.Transition != "start" {
		return workspaceBuildResponse{}, errors.New("Coder returned an invalid start build identity")
	}
	return response, nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, body, output any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}
	u := *c.base
	u.Path += path
	req, err := http.NewRequestWithContext(ctx, method, u.String(), reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Coder-Session-Token", c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxResponseBytes {
		return errors.New("Coder response exceeded size limit")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var problem struct{ Message, Detail string }
		_ = json.Unmarshal(data, &problem)
		message := problem.Message
		if message == "" {
			message = problem.Detail
		}
		if len(message) > 1000 {
			message = message[:1000]
		}
		return &apiStatusError{status: resp.StatusCode, message: message}
	}
	if output != nil && len(data) > 0 {
		if err := json.Unmarshal(data, output); err != nil {
			return fmt.Errorf("decode Coder response: %w", err)
		}
	}
	return nil
}

func provisionParameters(request workspace.ProvisionRequest) []parameter {
	directory := request.DevcontainerDir
	if directory == "" {
		directory = ".devcontainer"
	}
	params := []parameter{
		{Name: "workspace_mode", Value: "plain"},
		{Name: "setup_approval_id", Value: ""},
		{Name: "devcontainer_dir", Value: directory},
		{Name: "allow_egress", Value: strconv.FormatBool(request.SafetyMode != core.SafetySafe)},
	}
	return append(params, quotaParameters(request.Quota)...)
}

func setupParameters(request workspace.SetupStartRequest) []parameter {
	mode, receipt := "plain", ""
	if request.UseEnvBuilder {
		mode, receipt = "approved-envbuilder", approvalReceipt(request.WorkspaceID)
	}
	params := []parameter{
		{Name: "workspace_mode", Value: mode},
		{Name: "setup_approval_id", Value: receipt},
		{Name: "devcontainer_dir", Value: request.ConfigDirectory},
		{Name: "allow_egress", Value: strconv.FormatBool(request.SafetyMode != core.SafetySafe)},
	}
	return append(params, runtimeQuotaParameters(request.Quota)...)
}

func startParameters(request workspace.StartRequest) []parameter {
	params := []parameter{{
		Name: "allow_egress", Value: strconv.FormatBool(request.SafetyMode != core.SafetySafe),
	}}
	return append(params, runtimeQuotaParameters(request.Quota)...)
}

func validDevcontainerDirectory(value string) bool {
	return value == "" || value == "." || value == ".devcontainer"
}

func quotaParameters(quota core.Quota) []parameter {
	return append(runtimeQuotaParameters(quota), parameter{
		Name: "disk_gib", Value: strconv.FormatInt(quota.DiskGiB, 10),
	})
}

func runtimeQuotaParameters(quota core.Quota) []parameter {
	return []parameter{
		{Name: "cpu_millis", Value: strconv.FormatInt(quota.CPUMilli, 10)},
		{Name: "memory_mb", Value: strconv.FormatInt(quota.MemoryMiB, 10)},
		{Name: "pids_limit", Value: "512"},
	}
}

func approvalReceipt(workspaceID string) string {
	digest := sha256.Sum256([]byte("codex-mobile:setup-approval:v1:" + workspaceID))
	return "approval_" + hex.EncodeToString(digest[:16])
}

func providerWorkspaceName(id string) string {
	digest := sha256.Sum256([]byte("codex-mobile:provider-workspace:v1:" + id))
	// Coder names are limited to 32 characters. 112 digest bits make the
	// deterministic namespace collision-resistant while retaining a short
	// product prefix for operator recognition.
	return "cm-" + hex.EncodeToString(digest[:14])
}

var safeIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

var _ workspace.Provider = (*Client)(nil)
