package application

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	workspacefiles "github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/files"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/githubapp"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/gitops"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/httpapi"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/workspacehelper"
)

func (a *Application) GetFileTree(ctx context.Context, principal httpapi.Principal, workspaceID string) ([]httpapi.FileEntry, error) {
	value, err := a.helperWorkspace(ctx, principal.OwnerID, workspaceID)
	if err != nil {
		return nil, err
	}
	response, err := a.runHelper(ctx, value, workspacehelper.Request{Version: workspacehelper.Version, Operation: workspacehelper.OpFileTree})
	if err != nil {
		return nil, err
	}
	if err := a.touchWorkspace(ctx, value); err != nil {
		return nil, err
	}
	return fileTree(response.Tree), nil
}

func (a *Application) SearchFiles(ctx context.Context, principal httpapi.Principal, workspaceID, query string) ([]httpapi.FileSearchResult, error) {
	value, err := a.helperWorkspace(ctx, principal.OwnerID, workspaceID)
	if err != nil {
		return nil, err
	}
	if err := a.touchWorkspace(ctx, value); err != nil {
		return nil, err
	}
	response, err := a.runHelper(ctx, value, workspacehelper.Request{Version: workspacehelper.Version, Operation: workspacehelper.OpFileSearch, Query: query})
	if err != nil {
		return nil, err
	}
	result := make([]httpapi.FileSearchResult, 0, min(len(response.Search), a.config.FileSearchLimit))
	for _, match := range response.Search {
		if len(result) >= a.config.FileSearchLimit {
			break
		}
		if workspacefiles.Sensitive(match.Path) {
			continue
		}
		result = append(result, httpapi.FileSearchResult{Path: match.Path, Line: match.Line, Column: match.Column, Preview: truncateText(match.Text, 4096)})
	}
	return result, nil
}

func (a *Application) GetFile(ctx context.Context, principal httpapi.Principal, workspaceID, filePath string) (httpapi.FileDocument, error) {
	value, err := a.helperWorkspace(ctx, principal.OwnerID, workspaceID)
	if err != nil {
		return httpapi.FileDocument{}, err
	}
	response, err := a.runHelper(ctx, value, workspacehelper.Request{Version: workspacehelper.Version, Operation: workspacehelper.OpFileRead, Path: filePath})
	if err != nil {
		return httpapi.FileDocument{}, err
	}
	if response.File == nil {
		return httpapi.FileDocument{}, external(errors.New("workspace helper omitted file document"))
	}
	if err := a.touchWorkspace(ctx, value); err != nil {
		return httpapi.FileDocument{}, err
	}
	return fileDocument(*response.File), nil
}

func (a *Application) SaveFile(ctx context.Context, principal httpapi.Principal, workspaceID, filePath string, request httpapi.SaveFileRequest) (httpapi.FileDocument, error) {
	value, err := a.helperWorkspace(ctx, principal.OwnerID, workspaceID)
	if err != nil {
		return httpapi.FileDocument{}, err
	}
	releaseMutation := a.acquireWorkspaceMutation(workspaceID)
	defer releaseMutation()
	response, err := a.runHelper(ctx, value, workspacehelper.Request{
		Version:      workspacehelper.Version,
		Operation:    workspacehelper.OpFileSave,
		Path:         filePath,
		Content:      request.Content,
		ExpectedETag: request.ExpectedETag,
	})
	if err != nil {
		a.audit(principal, workspaceID, "file.save", "failed", "workspace_file", "", nil)
		return httpapi.FileDocument{}, err
	}
	if response.File == nil {
		return httpapi.FileDocument{}, external(errors.New("workspace helper omitted saved file document"))
	}
	if statusResponse, statusErr := a.runHelper(ctx, value, workspacehelper.Request{Version: workspacehelper.Version, Operation: workspacehelper.OpGitStatus}); statusErr == nil && statusResponse.GitStatus != nil {
		if err := a.syncGitState(ctx, value, *statusResponse.GitStatus); err != nil {
			return httpapi.FileDocument{}, err
		}
	} else {
		// A successful save is conservatively considered dirty if the status
		// refresh is unavailable. This preserves checkpoint and auto-delete
		// safety even during a transient helper failure.
		if err := a.deps.WorkspaceStore.UpdateGitRisk(ctx, value.OwnerID, value.ID, true, value.Unpushed, a.deps.Clock.Now()); err != nil {
			return httpapi.FileDocument{}, err
		}
	}
	if err := a.touchWorkspace(ctx, value); err != nil {
		return httpapi.FileDocument{}, err
	}
	a.audit(principal, workspaceID, "file.save", "success", "workspace_file", "", nil)
	return fileDocument(*response.File), nil
}

func (a *Application) GetGitStatus(ctx context.Context, principal httpapi.Principal, workspaceID string) (httpapi.GitStatusDetail, error) {
	value, err := a.helperWorkspace(ctx, principal.OwnerID, workspaceID)
	if err != nil {
		return httpapi.GitStatusDetail{}, err
	}
	return a.gitOperation(ctx, value, workspacehelper.Request{Version: workspacehelper.Version, Operation: workspacehelper.OpGitStatus})
}

func (a *Application) GetGitDiff(ctx context.Context, principal httpapi.Principal, workspaceID, filePath string) (httpapi.DiffDocument, error) {
	if workspacefiles.Sensitive(filePath) {
		return httpapi.DiffDocument{}, fmt.Errorf("%w: sensitive paths are unavailable", core.ErrForbidden)
	}
	value, err := a.helperWorkspace(ctx, principal.OwnerID, workspaceID)
	if err != nil {
		return httpapi.DiffDocument{}, err
	}
	if err := a.touchWorkspace(ctx, value); err != nil {
		return httpapi.DiffDocument{}, err
	}
	response, err := a.runHelper(ctx, value, workspacehelper.Request{Version: workspacehelper.Version, Operation: workspacehelper.OpGitDiff, Path: filePath})
	if err != nil {
		return httpapi.DiffDocument{}, err
	}
	diff := response.Diff
	return httpapi.DiffDocument{Path: filePath, UnifiedDiff: &diff, CacheDirective: httpapi.CacheOrdinary}, nil
}

func (a *Application) SetGitStaged(ctx context.Context, principal httpapi.Principal, workspaceID string, request httpapi.StageRequest) (httpapi.GitStatusDetail, error) {
	value, err := a.helperWorkspace(ctx, principal.OwnerID, workspaceID)
	if err != nil {
		return httpapi.GitStatusDetail{}, err
	}
	releaseMutation := a.acquireWorkspaceMutation(workspaceID)
	defer releaseMutation()
	result, err := a.gitOperation(ctx, value, workspacehelper.Request{Version: workspacehelper.Version, Operation: workspacehelper.OpGitStage, Path: request.Path, Staged: request.Staged})
	if err != nil {
		a.audit(principal, workspaceID, "git.stage", "failed", "workspace", workspaceID, nil)
		return httpapi.GitStatusDetail{}, err
	}
	a.audit(principal, workspaceID, "git.stage", "success", "workspace", workspaceID, map[string]any{"staged": request.Staged})
	return result, nil
}

func (a *Application) CreateCommit(ctx context.Context, principal httpapi.Principal, workspaceID string, request httpapi.CommitRequest) (httpapi.GitStatusDetail, error) {
	value, err := a.helperWorkspace(ctx, principal.OwnerID, workspaceID)
	if err != nil {
		return httpapi.GitStatusDetail{}, err
	}
	releaseMutation := a.acquireWorkspaceMutation(workspaceID)
	defer releaseMutation()
	response, err := a.runHelper(ctx, value, workspacehelper.Request{
		Version:       workspacehelper.Version,
		Operation:     workspacehelper.OpGitCommit,
		CommitMessage: request.Message,
		AuthorName:    request.AuthorName,
		AuthorEmail:   request.AuthorEmail,
	})
	if err != nil {
		a.audit(principal, workspaceID, "git.commit", "failed", "workspace", workspaceID, nil)
		return httpapi.GitStatusDetail{}, err
	}
	if response.GitStatus == nil || response.CommitSHA == "" {
		return httpapi.GitStatusDetail{}, external(errors.New("workspace helper omitted commit result"))
	}
	if err := a.syncGitState(ctx, value, *response.GitStatus); err != nil {
		return httpapi.GitStatusDetail{}, err
	}
	if err := a.touchWorkspace(ctx, value); err != nil {
		return httpapi.GitStatusDetail{}, err
	}
	a.audit(principal, workspaceID, "git.commit", "success", "commit", response.CommitSHA, nil)
	return gitStatusDetail(*response.GitStatus), nil
}

func (a *Application) PullWorkspace(ctx context.Context, principal httpapi.Principal, workspaceID string) (httpapi.GitStatusDetail, error) {
	return a.authenticatedGitOperation(ctx, principal, workspaceID, workspacehelper.OpGitPull, "git.pull", map[string]string{"contents": "read"})
}

func (a *Application) PushWorkspace(ctx context.Context, principal httpapi.Principal, workspaceID string) (httpapi.GitStatusDetail, error) {
	return a.authenticatedGitOperation(ctx, principal, workspaceID, workspacehelper.OpGitPush, "git.push", map[string]string{"contents": "write"})
}

func (a *Application) CreatePullRequest(ctx context.Context, principal httpapi.Principal, workspaceID string, request httpapi.PullRequestRequest) (httpapi.PullRequestResult, error) {
	if !a.config.GitHubConfigured || a.deps.GitHub == nil {
		return httpapi.PullRequestResult{}, fmt.Errorf("%w: GitHub App is not configured", core.ErrPrecondition)
	}
	value, err := a.helperWorkspace(ctx, principal.OwnerID, workspaceID)
	if err != nil {
		return httpapi.PullRequestResult{}, err
	}
	if err := a.touchWorkspace(ctx, value); err != nil {
		return httpapi.PullRequestResult{}, err
	}
	var result httpapi.PullRequestResult
	err = a.withInstallationToken(ctx, principal.OwnerID, value.Repository, map[string]string{"contents": "write", "pull_requests": "write"}, func(leaseCtx context.Context, token string) error {
		pullRequest, createErr := a.deps.GitHub.CreatePullRequest(leaseCtx, token, value.Repository.FullName, request.Title, request.Body, value.Branch, request.BaseBranch, false)
		if createErr != nil {
			return external(createErr)
		}
		result = httpapi.PullRequestResult{Number: pullRequest.Number, URL: pullRequest.URL, State: pullRequest.State}
		return nil
	})
	if err != nil {
		a.audit(principal, workspaceID, "github.pull_request.create", "failed", "workspace", workspaceID, nil)
		return httpapi.PullRequestResult{}, err
	}
	a.audit(principal, workspaceID, "github.pull_request.create", "success", "pull_request", strconv.Itoa(result.Number), nil)
	return result, nil
}

func (a *Application) authenticatedGitOperation(ctx context.Context, principal httpapi.Principal, workspaceID string, operation workspacehelper.Operation, auditAction string, permissions map[string]string) (httpapi.GitStatusDetail, error) {
	if !a.config.GitHubConfigured || a.deps.GitHub == nil {
		return httpapi.GitStatusDetail{}, fmt.Errorf("%w: GitHub App is not configured", core.ErrPrecondition)
	}
	value, err := a.helperWorkspace(ctx, principal.OwnerID, workspaceID)
	if err != nil {
		return httpapi.GitStatusDetail{}, err
	}
	releaseMutation := a.acquireWorkspaceMutation(workspaceID)
	defer releaseMutation()
	var result httpapi.GitStatusDetail
	err = a.withInstallationToken(ctx, principal.OwnerID, value.Repository, permissions, func(leaseCtx context.Context, token string) error {
		var operationErr error
		result, operationErr = a.gitOperation(leaseCtx, value, workspacehelper.Request{Version: workspacehelper.Version, Operation: operation, GitHubToken: token, Repository: value.Repository.FullName})
		return operationErr
	})
	if err != nil {
		a.audit(principal, workspaceID, auditAction, "failed", "workspace", workspaceID, nil)
		return httpapi.GitStatusDetail{}, err
	}
	a.audit(principal, workspaceID, auditAction, "success", "workspace", workspaceID, nil)
	return result, nil
}

func (a *Application) withInstallationToken(ctx context.Context, ownerID string, repository core.Repository, permissions map[string]string, operation func(context.Context, string) error) error {
	repositoryID, err := strconv.ParseInt(repository.ID, 10, 64)
	if err != nil || repositoryID <= 0 || operation == nil {
		return external(errors.New("repository has an invalid GitHub identity"))
	}
	if a.deps.Connections == nil {
		return fmt.Errorf("%w: GitHub connection persistence is unavailable", core.ErrPrecondition)
	}
	return a.deps.Connections.WithGitHubInstallationLease(ctx, ownerID, repository.InstallationID, func(leaseCtx context.Context) error {
		err := githubapp.UseInstallationToken(
			leaseCtx, a.deps.GitHub, a.deps.Connections, ownerID, repository.InstallationID,
			[]int64{repositoryID}, permissions, operation,
		)
		if err != nil {
			return external(err)
		}
		return nil
	})
}

func (a *Application) helperWorkspace(ctx context.Context, ownerID, workspaceID string) (core.Workspace, error) {
	value, err := a.deps.WorkspaceStore.Get(ctx, ownerID, workspaceID)
	if err != nil {
		return core.Workspace{}, err
	}
	if value.ProviderResourceID == "" {
		return core.Workspace{}, fmt.Errorf("%w: workspace runtime is not available", core.ErrPrecondition)
	}
	if value.State != core.WorkspaceRunning && value.State != core.WorkspaceReady && value.State != core.WorkspaceIdle && value.State != core.WorkspaceNeedsAttention {
		return core.Workspace{}, fmt.Errorf("%w: workspace is not running", core.ErrConflict)
	}
	return value, nil
}

func (a *Application) runHelper(ctx context.Context, value core.Workspace, request workspacehelper.Request) (workspacehelper.Response, error) {
	request.Version = workspacehelper.Version
	if helperOperationNeedsGrantedSecrets(request) {
		granted, err := a.deps.State.LoadGrantedWorkspaceSecrets(ctx, value.OwnerID, value.ID)
		if err != nil {
			return workspacehelper.Response{}, external(errors.New("active workspace secret grants are unavailable"))
		}
		request.GrantedSecrets = granted
	}
	encoded, err := json.Marshal(request)
	request.Content = ""
	request.GitHubToken = ""
	request.CommitMessage = ""
	request.AuthorName = ""
	request.AuthorEmail = ""
	for name, value := range request.GrantedSecrets {
		zero(value)
		delete(request.GrantedSecrets, name)
	}
	request.GrantedSecrets = nil
	for index := range request.Attachments {
		zero(request.Attachments[index].Content)
		request.Attachments[index].Content = nil
	}
	request.Attachments = nil
	if err != nil {
		return workspacehelper.Response{}, err
	}
	defer zero(encoded)
	data, err := a.deps.Coder.RunHelper(ctx, value.ProviderResourceID, encoded)
	if err != nil {
		return workspacehelper.Response{}, external(err)
	}
	defer zero(data)
	response, err := decodeHelperResponse(data)
	if err != nil {
		return response, err
	}
	return response, nil
}

func helperOperationNeedsGrantedSecrets(request workspacehelper.Request) bool {
	return request.Operation == workspacehelper.OpRuntimeSecretsSync || request.Operation == workspacehelper.OpGitCommit || request.Operation == workspacehelper.OpGitPull || request.Operation == workspacehelper.OpGitPush ||
		(request.Operation == workspacehelper.OpGitStage && request.Staged)
}

func (a *Application) syncWorkspaceRuntimeSecrets(ctx context.Context, value core.Workspace) error {
	if value.ProviderResourceID == "" {
		return external(errors.New("workspace runtime secret synchronization is unavailable"))
	}
	_, err := a.runHelper(ctx, value, workspacehelper.Request{
		Version: workspacehelper.Version, Operation: workspacehelper.OpRuntimeSecretsSync,
	})
	return err
}

func decodeHelperResponse(data []byte) (workspacehelper.Response, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var response workspacehelper.Response
	if err := decoder.Decode(&response); err != nil || response.Version != workspacehelper.Version {
		return workspacehelper.Response{}, external(errors.New("invalid workspace helper response"))
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return workspacehelper.Response{}, external(errors.New("invalid workspace helper response"))
	}
	if response.OK {
		return response, nil
	}
	var marker error
	switch response.ErrorCode {
	case "invalid", "invalid_request":
		marker = core.ErrInvalid
	case "forbidden":
		marker = core.ErrForbidden
	case "not_found":
		marker = core.ErrNotFound
	case "conflict":
		marker = core.ErrConflict
	case "precondition":
		marker = core.ErrPrecondition
	case "unauthorized":
		marker = core.ErrExternal
	default:
		marker = core.ErrExternal
	}
	return response, fmt.Errorf("%w: workspace helper rejected the operation", marker)
}

func (a *Application) gitOperation(ctx context.Context, value core.Workspace, request workspacehelper.Request) (httpapi.GitStatusDetail, error) {
	response, err := a.runHelper(ctx, value, request)
	if err != nil {
		if response.GitPrecondition != nil {
			precondition := response.GitPrecondition
			return httpapi.GitStatusDetail{}, &httpapi.ProblemError{
				Status: 412, Code: "git_precondition", Title: "Git precondition failed",
				Detail: "Native pull could not fast-forward. Resolve the repository in the terminal; native pull never rebases.", Err: err,
				GitPrecondition: &httpapi.GitOperationPrecondition{
					Reason: precondition.Reason, Ahead: precondition.Ahead, Behind: precondition.Behind,
					HasConflicts: precondition.HasConflicts, Dirty: precondition.Dirty,
					TerminalFallback: precondition.TerminalFallback,
				},
			}
		}
		return httpapi.GitStatusDetail{}, err
	}
	if response.GitStatus == nil {
		return httpapi.GitStatusDetail{}, external(errors.New("workspace helper omitted Git status"))
	}
	if err := a.syncGitState(ctx, value, *response.GitStatus); err != nil {
		return httpapi.GitStatusDetail{}, err
	}
	if err := a.touchWorkspace(ctx, value); err != nil {
		return httpapi.GitStatusDetail{}, err
	}
	return gitStatusDetail(*response.GitStatus), nil
}

func (a *Application) syncGitState(ctx context.Context, value core.Workspace, status gitops.Status) error {
	if value.Dirty == status.Dirty && value.Unpushed == status.Unpushed {
		return nil
	}
	return a.deps.WorkspaceStore.UpdateGitRisk(ctx, value.OwnerID, value.ID, status.Dirty, status.Unpushed, a.deps.Clock.Now())
}

func (a *Application) touchWorkspace(ctx context.Context, value core.Workspace) error {
	return a.deps.WorkspaceStore.TouchActivity(ctx, value.OwnerID, value.ID, a.deps.Clock.Now())
}

func gitStatusDetail(status gitops.Status) httpapi.GitStatusDetail {
	changes := make([]httpapi.GitFileChange, 0, len(status.Changes))
	for _, change := range status.Changes {
		if workspacefiles.Sensitive(change.Path) {
			continue
		}
		code := strings.TrimSpace(string([]byte{change.Index, change.Worktree}))
		if code == "" {
			code = "modified"
		}
		if change.Conflict {
			changes = append(changes, httpapi.GitFileChange{Path: change.Path, Status: code, Group: httpapi.GitConflicted})
			continue
		}
		if change.Untracked {
			changes = append(changes, httpapi.GitFileChange{Path: change.Path, Status: code, Group: httpapi.GitUntracked})
			continue
		}
		if change.Staged {
			changes = append(changes, httpapi.GitFileChange{Path: change.Path, Status: code, Group: httpapi.GitStaged})
		}
		if change.Unstaged {
			changes = append(changes, httpapi.GitFileChange{Path: change.Path, Status: code, Group: httpapi.GitUnstaged})
		}
	}
	return httpapi.GitStatusDetail{Branch: status.Branch, Ahead: status.Ahead, Behind: status.Behind, Changes: changes}
}

type treeNode struct {
	entry    workspacefiles.Entry
	children []*treeNode
}

func fileTree(entries []workspacefiles.Entry) []httpapi.FileEntry {
	nodes := make(map[string]*treeNode, len(entries))
	for _, entry := range entries {
		nodes[entry.Path] = &treeNode{entry: entry}
	}
	roots := make([]*treeNode, 0)
	for _, node := range nodes {
		parentPath := path.Dir(node.entry.Path)
		if parentPath != "." {
			if parent := nodes[parentPath]; parent != nil && parent.entry.Directory {
				parent.children = append(parent.children, node)
				continue
			}
		}
		roots = append(roots, node)
	}
	sortTreeNodes(roots)
	result := make([]httpapi.FileEntry, 0, len(roots))
	for _, root := range roots {
		result = append(result, fileTreeEntry(root))
	}
	return result
}

func sortTreeNodes(nodes []*treeNode) {
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].entry.Directory != nodes[j].entry.Directory {
			return nodes[i].entry.Directory
		}
		return nodes[i].entry.Path < nodes[j].entry.Path
	})
	for _, node := range nodes {
		sortTreeNodes(node.children)
	}
}

func fileTreeEntry(node *treeNode) httpapi.FileEntry {
	kind := httpapi.FileText
	if node.entry.Directory {
		kind = httpapi.FileDirectory
	} else if node.entry.Sensitive {
		kind = httpapi.FileSensitive
	} else if node.entry.Binary {
		kind = httpapi.FileBinary
	} else if node.entry.Size > workspacefiles.DefaultMaxFileBytes {
		kind = httpapi.FileTooLarge
	}
	result := httpapi.FileEntry{Path: node.entry.Path, Name: fileName(node.entry.Path), Kind: kind}
	if node.entry.Directory {
		children := make([]httpapi.FileEntry, 0, len(node.children))
		for _, child := range node.children {
			children = append(children, fileTreeEntry(child))
		}
		result.Children = &children
	} else {
		size := node.entry.Size
		result.SizeBytes = &size
	}
	return result
}

func fileDocument(value workspacehelper.FileDocument) httpapi.FileDocument {
	return httpapi.FileDocument{
		Path:           value.Path,
		Content:        value.Content,
		ETag:           value.ETag,
		LanguageHint:   languageHint(value.Path),
		Kind:           httpapi.FileText,
		CacheDirective: httpapi.CacheOrdinary,
	}
}

func languageHint(filePath string) *string {
	extension := strings.ToLower(path.Ext(filePath))
	value := ""
	switch extension {
	case ".go":
		value = "go"
	case ".swift":
		value = "swift"
	case ".js", ".mjs", ".cjs":
		value = "javascript"
	case ".ts", ".tsx":
		value = "typescript"
	case ".jsx":
		value = "javascriptreact"
	case ".py":
		value = "python"
	case ".rb":
		value = "ruby"
	case ".rs":
		value = "rust"
	case ".json":
		value = "json"
	case ".yaml", ".yml":
		value = "yaml"
	case ".md":
		value = "markdown"
	case ".sh", ".bash":
		value = "shell"
	case ".css":
		value = "css"
	case ".html", ".htm":
		value = "html"
	}
	if value == "" {
		return nil
	}
	return &value
}
