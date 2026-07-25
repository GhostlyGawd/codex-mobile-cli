package workspacehelper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/attachments"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/codex"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	workspacefiles "github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/files"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/githubapp"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/gitops"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
)

const (
	Version                  = 1
	DefaultRoot              = "/workspaces/repository"
	MaxRequestBytes          = 16 << 20
	maxRequestDeadlineFuture = 5 * time.Minute
)

type Operation string

const (
	OpFileTree   Operation = "file_tree"
	OpFileRead   Operation = "file_read"
	OpFileSave   Operation = "file_save"
	OpFileSearch Operation = "file_search"
	OpGitStatus  Operation = "git_status"
	OpGitDiff    Operation = "git_diff"
	OpGitStage   Operation = "git_stage"
	OpGitCommit  Operation = "git_commit"
	OpGitPull    Operation = "git_pull"
	OpGitPush    Operation = "git_push"
	OpGitClone   Operation = "git_clone"
	OpConfigure  Operation = "configure_workspace"
	// OpRuntimeSecretsSync replaces the tmpfs-backed grant set with the
	// control plane's authoritative values. It is deliberately separate from
	// general workspace configuration so grant changes never rewrite Codex or
	// user environment policy.
	OpRuntimeSecretsSync Operation = "runtime_secrets_sync"
	// OpCheckpointExport is a control-plane-only operation. It derives live Git
	// risk and, when work is dirty or unpushed, returns a bounded archive for
	// storage outside the workspace. Repository input is never used as a shell
	// command or archive destination.
	OpCheckpointExport Operation = "checkpoint_export"
	// OpCheckpointRestoreFile restores one explicitly selected file from a
	// checkpoint after the control plane has verified the archive.
	OpCheckpointRestoreFile Operation = "checkpoint_restore_file"
	// OpCheckpointRestoreWorkspace applies one validated checkpoint delta with
	// an on-workspace rollback journal.
	OpCheckpointRestoreWorkspace Operation = "checkpoint_restore_workspace"
	// OpGitDiscard restores explicitly selected tracked paths only after a
	// recovery checkpoint has been persisted by the control plane.
	OpGitDiscard Operation = "git_discard"
	// OpRuntimeActivityProbe is a fixed, read-only inspection of /proc. It
	// accepts no process name, command, port, or path from the caller.
	OpRuntimeActivityProbe Operation = "runtime_activity_probe"
	// OpAttachmentStage materializes a bounded, validated upload only on the
	// workspace's dedicated noexec tmpfs. The helper, not the client, chooses
	// every path component.
	OpAttachmentStage Operation = "attachment_stage"
	// OpAttachmentCleanup is invoked periodically by the control plane. Stage
	// also performs a sweep so a restarted janitor converges immediately.
	OpAttachmentCleanup Operation = "attachment_cleanup"
	// OpCodexThreadLookup reads only the trusted Codex session index for one
	// terminal tab. It never parses terminal output or returns conversation
	// content.
	OpCodexThreadLookup Operation = "codex_thread_lookup"
	// OpCodexAuthStatus validates the workspace's ChatGPT credential envelope
	// without returning account data or credential material.
	OpCodexAuthStatus Operation = "codex_auth_status"
	// OpCodexAuthRevoke stops app-owned Codex tmux sessions before removing both
	// tmpfs and encrypted-at-rest authentication material. Conversation session
	// history is deliberately preserved for reauthentication and resume.
	OpCodexAuthRevoke Operation = "codex_auth_revoke"
)

type Request struct {
	Version                    int                  `json:"version"`
	Operation                  Operation            `json:"operation"`
	Path                       string               `json:"path,omitempty"`
	Content                    string               `json:"content,omitempty"`
	ExpectedETag               string               `json:"expected_etag,omitempty"`
	Query                      string               `json:"query,omitempty"`
	Staged                     bool                 `json:"staged,omitempty"`
	CommitMessage              string               `json:"commit_message,omitempty"`
	AuthorName                 string               `json:"author_name,omitempty"`
	AuthorEmail                string               `json:"author_email,omitempty"`
	GitHubToken                string               `json:"github_token,omitempty"`
	Repository                 string               `json:"repository,omitempty"`
	BaseBranch                 string               `json:"base_branch,omitempty"`
	Branch                     string               `json:"branch,omitempty"`
	Environment                map[string]string    `json:"environment,omitempty"`
	GrantedSecrets             map[string][]byte    `json:"granted_secrets,omitempty"`
	SafetyMode                 string               `json:"safety_mode,omitempty"`
	Network                    bool                 `json:"network,omitempty"`
	EventMode                  string               `json:"event_mode,omitempty"`
	CodexAuthKey               []byte               `json:"codex_auth_key,omitempty"`
	CheckpointContentSHA256    string               `json:"checkpoint_content_sha256,omitempty"`
	CheckpointMode             uint32               `json:"checkpoint_mode,omitempty"`
	CheckpointWorkspaceID      string               `json:"checkpoint_workspace_id,omitempty"`
	CheckpointArchiveSHA256    string               `json:"checkpoint_archive_sha256,omitempty"`
	CheckpointID               string               `json:"checkpoint_id,omitempty"`
	CheckpointForce            bool                 `json:"checkpoint_force,omitempty"`
	CheckpointSeal             bool                 `json:"checkpoint_seal,omitempty"`
	Paths                      []string             `json:"paths,omitempty"`
	Confirmed                  bool                 `json:"confirmed,omitempty"`
	TerminalTabID              string               `json:"terminal_tab_id,omitempty"`
	CodexTerminalTabIDs        []string             `json:"codex_terminal_tab_ids,omitempty"`
	Attachments                []attachments.Upload `json:"attachments,omitempty"`
	OperationDeadlineUnixMilli int64                `json:"operation_deadline_unix_milli,omitempty"`
}

type FileDocument struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	ETag    string `json:"etag"`
	Size    int64  `json:"size"`
}

// GitPrecondition describes why a bounded native Git operation could not
// continue and directs the owner to the authoritative terminal for manual
// conflict resolution. Native pull is always fast-forward-only.
type GitPrecondition struct {
	Reason           string `json:"reason"`
	Ahead            int    `json:"ahead"`
	Behind           int    `json:"behind"`
	HasConflicts     bool   `json:"has_conflicts"`
	Dirty            bool   `json:"dirty"`
	TerminalFallback string `json:"terminal_fallback"`
}

type Response struct {
	Version         int                          `json:"version"`
	OK              bool                         `json:"ok"`
	ErrorCode       string                       `json:"error_code,omitempty"`
	Error           string                       `json:"error,omitempty"`
	Tree            []workspacefiles.Entry       `json:"tree,omitempty"`
	File            *FileDocument                `json:"file,omitempty"`
	Search          []workspacefiles.SearchMatch `json:"search,omitempty"`
	GitStatus       *gitops.Status               `json:"git_status,omitempty"`
	Diff            string                       `json:"diff,omitempty"`
	CommitSHA       string                       `json:"commit_sha,omitempty"`
	Checkpoint      *CheckpointExport            `json:"checkpoint,omitempty"`
	RuntimeActivity *RuntimeActivity             `json:"runtime_activity,omitempty"`
	CheckpointID    string                       `json:"checkpoint_id,omitempty"`
	GitPrecondition *GitPrecondition             `json:"git_precondition,omitempty"`
	CodexThreadID   string                       `json:"codex_thread_id,omitempty"`
	CodexAuthState  string                       `json:"codex_auth_state,omitempty"`
	Attachments     []attachments.Staged         `json:"attachments,omitempty"`
}

type Helper struct {
	root           string
	temporaryRoot  string
	attachmentRoot string
	killCodexTmux  func(context.Context, string) error
}

func New(root string) (*Helper, error) {
	if root == "" {
		root = DefaultRoot
	}
	temporaryRoot := os.TempDir()
	if filepath.Clean(root) == filepath.Clean(DefaultRoot) {
		if err := requireMemoryBackedTemporaryRoot(temporaryRoot); err != nil {
			return nil, err
		}
	}
	return newWithRoots(root, temporaryRoot, attachments.DefaultRoot)
}

func NewWithTemporaryRoot(root, temporaryRoot string) (*Helper, error) {
	return newWithRoots(root, temporaryRoot, filepath.Join(temporaryRoot, "codex-mobile-attachments"))
}

func newWithRoots(root, temporaryRoot, attachmentRoot string) (*Helper, error) {
	if root == "" {
		root = DefaultRoot
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if temporaryRoot == "" {
		return nil, errors.New("invalid helper temporary root")
	}
	temporaryRoot, err = filepath.Abs(temporaryRoot)
	if err != nil {
		return nil, errors.New("invalid helper temporary root")
	}
	attachmentRoot, err = filepath.Abs(attachmentRoot)
	if err != nil || !filepath.IsAbs(attachmentRoot) {
		return nil, errors.New("invalid attachment staging root")
	}
	return &Helper{
		root: abs, temporaryRoot: temporaryRoot, attachmentRoot: attachmentRoot,
		killCodexTmux: func(ctx context.Context, tabID string) error {
			return killCodexTmuxSession(ctx, temporaryRoot, tabID)
		},
	}, nil
}

func (h *Helper) Serve(ctx context.Context, input io.Reader, output io.Writer) error {
	decoder := json.NewDecoder(io.LimitReader(input, MaxRequestBytes+1))
	decoder.DisallowUnknownFields()
	var request Request
	defer scrubSensitiveRequest(&request)
	if err := decoder.Decode(&request); err != nil {
		return writeResponse(output, failure("invalid_request", "Invalid helper request."))
	}
	if err := ensureEOF(decoder); err != nil || request.Version != Version {
		return writeResponse(output, failure("invalid_request", "Invalid helper request."))
	}
	requestContext, cancel, err := workspaceHelperRequestContext(ctx, &request)
	if err != nil {
		return writeResponse(output, failure("invalid_request", "Invalid helper request."))
	}
	defer cancel()
	response := h.execute(requestContext, &request)
	return writeResponse(output, response)
}

func workspaceHelperRequestContext(parent context.Context, request *Request) (context.Context, context.CancelFunc, error) {
	if parent == nil || request == nil {
		return nil, nil, errors.New("invalid workspace helper deadline")
	}
	encoded := request.OperationDeadlineUnixMilli
	request.OperationDeadlineUnixMilli = 0
	requiresDeadline := request.GitHubToken != "" || request.Operation == OpGitClone || request.Operation == OpGitPull || request.Operation == OpGitPush
	if encoded == 0 {
		if requiresDeadline {
			return nil, nil, errors.New("GitHub workspace helper operations require a deadline")
		}
		return parent, func() {}, nil
	}
	now := time.Now()
	deadline := time.UnixMilli(encoded)
	if !deadline.After(now) || deadline.After(now.Add(maxRequestDeadlineFuture)) {
		return nil, nil, errors.New("workspace helper deadline is invalid")
	}
	bounded, cancel := context.WithDeadline(parent, deadline)
	return bounded, cancel, nil
}

func (h *Helper) execute(ctx context.Context, request *Request) Response {
	if request.Operation == OpGitClone {
		return h.clone(ctx, request)
	}
	if request.Operation == OpConfigure {
		return h.configure(request)
	}
	if request.Operation == OpRuntimeSecretsSync {
		return h.syncRuntimeSecrets(request)
	}
	if request.Operation == OpCheckpointExport {
		if request.CheckpointSeal {
			if err := h.sealCodexAuth(); err != nil {
				return failure("precondition", "Codex authentication state could not be checkpointed.")
			}
			if err := h.purgeRuntimeSecrets(); err != nil {
				return failure("precondition", "Granted runtime secrets could not be sealed.")
			}
		}
		return h.checkpointExport(ctx, request)
	}
	if request.Operation == OpCheckpointRestoreFile {
		return h.checkpointRestoreFile(request)
	}
	if request.Operation == OpCheckpointRestoreWorkspace {
		return h.checkpointRestoreWorkspace(ctx, request)
	}
	if request.Operation == OpRuntimeActivityProbe {
		return h.runtimeActivityProbe()
	}
	if request.Operation == OpAttachmentStage {
		return h.stageAttachments(ctx, request.Attachments)
	}
	if request.Operation == OpAttachmentCleanup {
		return h.cleanupAttachments(ctx)
	}
	if request.Operation == OpCodexThreadLookup {
		return h.codexThreadLookup(request)
	}
	if request.Operation == OpCodexAuthStatus {
		return h.codexAuthStatus(request)
	}
	if request.Operation == OpCodexAuthRevoke {
		return h.codexAuthRevoke(ctx, request)
	}
	filesService, err := workspacefiles.New(h.root)
	if err != nil {
		return fromError(err)
	}
	defer filesService.Close()
	switch request.Operation {
	case OpFileTree:
		value, err := filesService.Tree()
		if err != nil {
			return fromError(err)
		}
		return Response{Version: Version, OK: true, Tree: value}
	case OpFileRead:
		value, err := filesService.Read(request.Path)
		if err != nil {
			return fromError(err)
		}
		return Response{Version: Version, OK: true, File: &FileDocument{Path: value.Path, Content: string(value.Content), ETag: value.ETag, Size: value.Size}}
	case OpFileSave:
		value, err := filesService.Save(request.Path, []byte(request.Content), request.ExpectedETag)
		if err != nil {
			return fromError(err)
		}
		return Response{Version: Version, OK: true, File: &FileDocument{Path: value.Path, Content: string(value.Content), ETag: value.ETag, Size: value.Size}}
	case OpFileSearch:
		value, err := filesService.Search(ctx, request.Query, 500)
		if err != nil {
			return fromError(err)
		}
		return Response{Version: Version, OK: true, Search: value}
	case OpGitStatus, OpGitDiff, OpGitStage, OpGitCommit, OpGitPull, OpGitPush, OpGitDiscard:
		return h.git(ctx, request)
	default:
		return failure("invalid_operation", "Unsupported helper operation.")
	}
}

func (h *Helper) syncRuntimeSecrets(request *Request) Response {
	if !runtimeSecretsSyncRequestOnly(request) || validateRuntimeSecrets(request.GrantedSecrets) != nil {
		return failure("invalid", "The runtime secret grant set was invalid.")
	}
	if err := writeRuntimeSecrets(h.temporaryRoot, request.GrantedSecrets); err != nil {
		return failure("precondition", "Granted runtime secrets could not be synchronized.")
	}
	return Response{Version: Version, OK: true}
}

// runtimeSecretsSyncRequestOnly keeps this privileged mutation narrower than
// the shared helper request envelope. Future request fields must be considered
// here before they can be accepted alongside plaintext grant material.
func runtimeSecretsSyncRequestOnly(request *Request) bool {
	return request.Path == "" && request.Content == "" && request.ExpectedETag == "" && request.Query == "" &&
		!request.Staged && request.CommitMessage == "" && request.AuthorName == "" && request.AuthorEmail == "" &&
		request.GitHubToken == "" && request.Repository == "" && request.BaseBranch == "" && request.Branch == "" &&
		len(request.Environment) == 0 && request.SafetyMode == "" && !request.Network && request.EventMode == "" &&
		len(request.CodexAuthKey) == 0 && request.CheckpointContentSHA256 == "" && request.CheckpointMode == 0 &&
		request.CheckpointWorkspaceID == "" && request.CheckpointArchiveSHA256 == "" && request.CheckpointID == "" &&
		!request.CheckpointForce && !request.CheckpointSeal && len(request.Paths) == 0 && !request.Confirmed && request.TerminalTabID == "" &&
		len(request.CodexTerminalTabIDs) == 0 &&
		len(request.Attachments) == 0
}

func (h *Helper) configure(request *Request) Response {
	mode := core.SafetyMode(request.SafetyMode)
	if !mode.Valid() || len(request.CodexAuthKey) != CodexAuthKeyBytes || len(request.Environment) > 100 || validateRuntimeSecrets(request.GrantedSecrets) != nil || (request.EventMode != "" && request.EventMode != "app-server") {
		return failure("invalid", "The workspace configuration was invalid.")
	}
	total := 0
	for name, value := range request.Environment {
		if !validEnvironmentName(name) || reservedEnvironmentName(name) || len(value) > 8192 || strings.ContainsRune(value, '\x00') {
			return failure("invalid", "The workspace configuration was invalid.")
		}
		total += len(name) + len(value)
	}
	if total > 256*1024 {
		return failure("invalid", "The workspace configuration was invalid.")
	}
	if err := h.purgeRuntimeSecrets(); err != nil {
		return failure("precondition", "Previous granted runtime secrets could not be removed.")
	}
	if err := h.configureCodexAuth(request.CodexAuthKey); err != nil {
		return failure("precondition", "Codex authentication state could not be configured.")
	}
	runtimeDir := filepath.Join(h.temporaryRoot, "codex-mobile-runtime")
	if err := ensurePrivateDirectory(runtimeDir); err != nil {
		return fromError(err)
	}
	encoded, err := json.Marshal(request.Environment)
	if err != nil {
		return fromError(err)
	}
	defer wipeBytes(encoded)
	if err := atomicPrivateFile(filepath.Join(runtimeDir, "environment.json"), encoded); err != nil {
		return fromError(err)
	}
	// Remove the plaintext location used by early development builds. A
	// regular legacy file is wiped before unlink; unexpected file types fail
	// closed instead of following a hostile symlink.
	legacyEnvironment := filepath.Join(filepath.Dir(h.root), ".codex-mobile", "environment.json")
	if err := secureRemove(legacyEnvironment); err != nil && !errors.Is(err, os.ErrNotExist) {
		return failure("precondition", "Legacy workspace runtime state could not be removed.")
	}
	configPath := filepath.Join(filepath.Dir(h.root), ".codex-home", "config.toml")
	if err := codex.WriteConfig(configPath, codex.RuntimeConfig{
		SafetyMode: mode, Network: request.Network, WritableRoot: h.root,
		EventMode: request.EventMode,
	}); err != nil {
		return fromError(err)
	}
	if err := writeRuntimeSecrets(h.temporaryRoot, request.GrantedSecrets); err != nil {
		return failure("precondition", "Granted runtime secrets could not be configured.")
	}
	return Response{Version: Version, OK: true}
}

func atomicPrivateFile(target string, content []byte) error {
	return writePrivateFilePlatform(target, content)
}

func validEnvironmentName(value string) bool {
	return environmentNamePattern.MatchString(value)
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

func (h *Helper) clone(ctx context.Context, request *Request) Response {
	if !repositoryPattern.MatchString(request.Repository) || !validGitRef(request.BaseBranch) ||
		!validGitRef(request.Branch) || request.GitHubToken == "" || len(request.GitHubToken) > 1024 {
		return failure("invalid", "The repository bootstrap request was invalid.")
	}
	entries, err := os.ReadDir(h.root)
	if err != nil {
		return fromError(err)
	}
	if len(entries) != 0 {
		if branch, branchErr := inProcessCurrentBranch(h.root); branchErr == nil && branch == request.Branch {
			request.GitHubToken = ""
			return Response{Version: Version, OK: true}
		}
		return failure("precondition", "The workspace checkout is already initialized.")
	}
	repositoryURL := "https://github.com/" + request.Repository + ".git"
	if err := gitops.ConfigureTrustedHTTPSForURL(repositoryURL); err != nil {
		return fromError(err)
	}
	broker := githubapp.TokenBroker{Token: request.GitHubToken}
	request.GitHubToken = ""
	credential, cleanup, err := broker.Credential(ctx)
	if err != nil {
		return fromError(err)
	}
	auth := &githttp.BasicAuth{Username: "x-access-token", Password: string(credential)}
	clear(credential)
	repository, err := git.PlainCloneContext(ctx, h.root, false, &git.CloneOptions{
		URL: repositoryURL, Auth: auth, ReferenceName: plumbing.NewBranchReferenceName(request.BaseBranch),
		SingleBranch: true, Tags: git.NoTags,
	})
	auth.Password = ""
	cleanup()
	if err != nil {
		return failure("external", "Authenticated repository clone failed.")
	}
	// The app owns a unique branch per isolated workspace. The base branch is
	// never modified directly.
	worktree, err := repository.Worktree()
	if err != nil {
		return fromError(err)
	}
	if err := worktree.Checkout(&git.CheckoutOptions{Branch: plumbing.NewBranchReferenceName(request.Branch), Create: true}); err != nil {
		_ = os.RemoveAll(filepath.Join(h.root, ".git"))
		return fromError(err)
	}
	return Response{Version: Version, OK: true}
}

func inProcessCurrentBranch(root string) (string, error) {
	repository, err := git.PlainOpenWithOptions(root, &git.PlainOpenOptions{DetectDotGit: false})
	if err != nil {
		return "", err
	}
	head, err := repository.Head()
	if err != nil || !head.Name().IsBranch() || len(head.Name().Short()) > 1024 {
		return "", errors.New("workspace branch is unavailable")
	}
	return head.Name().Short(), nil
}

func validGitRef(value string) bool {
	return value != "" && len(value) <= 255 && !strings.HasPrefix(value, "-") &&
		!strings.Contains(value, "..") && !strings.ContainsAny(value, " ~^:?*[\\\r\n\t") &&
		!strings.HasSuffix(value, ".") && !strings.HasSuffix(value, "/") && !strings.Contains(value, "//")
}

var repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$`)
var environmentNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

func (h *Helper) git(ctx context.Context, request *Request) Response {
	var checkpoint gitops.Checkpoint
	if request.Operation == OpGitDiscard {
		if !request.Confirmed || !safeHelperCheckpointID.MatchString(request.CheckpointID) {
			return failure("precondition", "A verified recovery checkpoint and explicit confirmation are required before discard.")
		}
		checkpoint = suppliedCheckpoint{id: request.CheckpointID}
	}
	var scanner gitops.SecretScanner
	var runtimeScanner *gitops.ValueSecretScanner
	needsScanner := request.Operation == OpGitCommit || request.Operation == OpGitPull || request.Operation == OpGitPush || (request.Operation == OpGitStage && request.Staged)
	if needsScanner {
		var scannerErr error
		runtimeScanner, scannerErr = h.runtimeSecretScanner(request.GrantedSecrets)
		if scannerErr != nil {
			return failure("precondition", "Granted runtime secret scanning is unavailable.")
		}
		defer runtimeScanner.Close()
		scanner = runtimeScanner
	}
	var expectedRepository []string
	if request.Operation == OpGitPull || request.Operation == OpGitPush {
		if !repositoryPattern.MatchString(request.Repository) {
			return failure("precondition", "The trusted GitHub repository is unavailable.")
		}
		expectedRepository = append(expectedRepository, request.Repository)
	}
	service, err := gitops.New(h.root, checkpoint, scanner, expectedRepository...)
	if err != nil {
		return fromError(err)
	}
	status := func() Response {
		value, statusErr := service.Status(ctx)
		if statusErr != nil {
			return fromError(statusErr)
		}
		return Response{Version: Version, OK: true, GitStatus: &value}
	}
	switch request.Operation {
	case OpGitStatus:
		return status()
	case OpGitDiff:
		value, err := service.Diff(ctx, request.Staged, request.Path)
		if err != nil {
			return fromError(err)
		}
		return Response{Version: Version, OK: true, Diff: string(value)}
	case OpGitStage:
		if request.Staged {
			err = service.Stage(ctx, []string{request.Path})
		} else {
			err = service.Unstage(ctx, []string{request.Path})
		}
		if err != nil {
			return fromError(err)
		}
		return status()
	case OpGitCommit:
		sha, err := service.CommitAs(ctx, request.CommitMessage, request.AuthorName, request.AuthorEmail)
		if err != nil {
			return fromError(err)
		}
		response := status()
		response.CommitSHA = sha
		return response
	case OpGitDiscard:
		checkpointID, discardErr := service.DiscardTracked(ctx, request.Paths, request.Confirmed)
		if discardErr != nil {
			response := fromError(discardErr)
			response.CheckpointID = checkpointID
			return response
		}
		response := status()
		response.CheckpointID = checkpointID
		return response
	case OpGitPull, OpGitPush:
		if request.GitHubToken == "" || len(request.GitHubToken) > 1024 {
			return failure("unauthorized", "GitHub authorization is unavailable.")
		}
		broker := githubapp.TokenBroker{Token: request.GitHubToken}
		request.GitHubToken = ""
		if request.Operation == OpGitPull {
			err = service.Pull(ctx, broker)
		} else {
			err = service.Push(ctx, broker)
		}
		if err != nil {
			response := fromError(err)
			if request.Operation == OpGitPull {
				if current, statusErr := service.Status(ctx); statusErr == nil {
					hasConflicts := false
					for _, change := range current.Changes {
						hasConflicts = hasConflicts || change.Conflict
					}
					isGitPrecondition := errors.Is(err, core.ErrPrecondition) || errors.Is(err, core.ErrConflict) || hasConflicts || (current.Ahead > 0 && current.Behind > 0)
					if !isGitPrecondition {
						return response
					}
					reason := "fast-forward-unavailable"
					if hasConflicts {
						reason = "conflicts-present"
					} else if current.Dirty {
						reason = "dirty-worktree"
					}
					response.ErrorCode = "precondition"
					response.Error = "Native pull could not fast-forward. Resolve the repository in the terminal; native pull never rebases."
					response.GitStatus = &current
					response.GitPrecondition = &GitPrecondition{
						Reason: reason, Ahead: current.Ahead, Behind: current.Behind,
						HasConflicts: hasConflicts, Dirty: current.Dirty,
						TerminalFallback: "Open the workspace terminal, run git status, and resolve or merge manually before retrying pull.",
					}
				}
			}
			return response
		}
		return status()
	default:
		return failure("invalid_operation", "Unsupported Git operation.")
	}
}

type suppliedCheckpoint struct{ id string }

func (checkpoint suppliedCheckpoint) Create(_ context.Context, reason string) (string, error) {
	if reason != "before-git-discard" || !safeHelperCheckpointID.MatchString(checkpoint.id) {
		return "", errors.New("verified recovery checkpoint is unavailable")
	}
	return checkpoint.id, nil
}

var safeHelperCheckpointID = regexp.MustCompile(`^cp_[0-9]{8}T[0-9]{6}\.[0-9]{9}Z_[0-9a-f]{24}$`)

func fromError(err error) Response {
	code, message := "internal", "Workspace operation failed."
	switch {
	case errors.Is(err, core.ErrInvalid):
		code, message = "invalid", "The workspace request was invalid."
	case errors.Is(err, core.ErrForbidden):
		code, message = "forbidden", "The workspace path is not available."
	case errors.Is(err, core.ErrNotFound), errors.Is(err, os.ErrNotExist):
		code, message = "not_found", "The workspace item was not found."
	case errors.Is(err, core.ErrConflict):
		code, message = "conflict", "The workspace item conflicts with current state."
	case errors.Is(err, core.ErrPrecondition):
		code, message = "precondition", "The workspace item changed; reload before saving."
	}
	return failure(code, message)
}

func failure(code, message string) Response {
	return Response{Version: Version, ErrorCode: code, Error: message}
}

func writeResponse(output io.Writer, response Response) error {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(true)
	return encoder.Encode(response)
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}

func DecodeResponse(data []byte) (Response, error) {
	var response Response
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil || response.Version != Version {
		return Response{}, errors.New("invalid workspace helper response")
	}
	if !response.OK {
		return response, fmt.Errorf("workspace helper %s: %s", response.ErrorCode, response.Error)
	}
	return response, nil
}
