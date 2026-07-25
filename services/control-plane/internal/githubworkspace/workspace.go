package githubworkspace

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/githubapp"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/workspace"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/workspacehelper"
)

type GitHubClient interface {
	InstallationToken(context.Context, int64, []int64, map[string]string) (githubapp.InstallationToken, error)
	RevokeInstallationToken(context.Context, string) error
	RepositoryContent(context.Context, string, string, string, string) ([]byte, bool, error)
}

type HelperRunner interface {
	RunHelper(context.Context, string, []byte) ([]byte, error)
}

type EnvironmentStore interface {
	SaveWorkspaceEnvironment(context.Context, core.Workspace) error
	LoadWorkspaceEnvironment(context.Context, core.Workspace) (map[string]string, error)
	LoadOrCreateWorkspaceCodexAuthKey(context.Context, core.Workspace) ([]byte, error)
	LoadGrantedWorkspaceSecrets(context.Context, string, string) (map[string][]byte, error)
}

type InitialPromptStore interface {
	SaveWorkspaceInitialPrompt(context.Context, core.Workspace) error
}

type InstallationAuthorizer interface {
	githubapp.TokenUseStore
	WithGitHubInstallationLease(context.Context, string, int64, func(context.Context) error) error
}

type Detector struct {
	github     GitHubClient
	authorizer InstallationAuthorizer
}

func NewDetector(github GitHubClient, authorizer InstallationAuthorizer) (*Detector, error) {
	if github == nil || authorizer == nil {
		return nil, errors.New("GitHub client and installation authorizer are required for environment detection")
	}
	return &Detector{github: github, authorizer: authorizer}, nil
}

func (d *Detector) Detect(ctx context.Context, ownerID string, repository core.Repository, branch string) (workspace.Environment, error) {
	var result workspace.Environment
	err := d.authorizer.WithGitHubInstallationLease(ctx, ownerID, repository.InstallationID, func(leaseCtx context.Context) error {
		repositoryID, identityErr := repositoryIdentity(repository)
		if identityErr != nil {
			return identityErr
		}
		return githubapp.UseInstallationToken(
			leaseCtx, d.github, d.authorizer, ownerID, repository.InstallationID,
			[]int64{repositoryID}, map[string]string{"contents": "read"},
			func(tokenCtx context.Context, token string) error {
				var detectErr error
				result, detectErr = d.detect(tokenCtx, repository, branch, token)
				return detectErr
			},
		)
	})
	return result, err
}

func (d *Detector) detect(ctx context.Context, repository core.Repository, branch, token string) (workspace.Environment, error) {
	for _, candidate := range []struct {
		path      string
		directory string
	}{
		{path: ".devcontainer/devcontainer.json", directory: ".devcontainer"},
		{path: ".devcontainer.json", directory: "."},
	} {
		content, exists, err := d.github.RepositoryContent(ctx, token, repository.FullName, candidate.path, branch)
		if err != nil {
			return workspace.Environment{}, err
		}
		if !exists {
			continue
		}
		var document map[string]any
		if err := json.Unmarshal(content, &document); err != nil || document == nil {
			return workspace.Environment{
				HasDevcontainer: true, Supported: false, RequiresTrust: true,
				ConfigDirectory: candidate.directory,
				Reason:          "Dev Container configuration is invalid; safe plain-image fallback is available.",
			}, nil
		}
		if unsupportedDevcontainer(document) {
			return workspace.Environment{
				HasDevcontainer: true, Supported: false, RequiresTrust: true,
				ConfigDirectory: candidate.directory,
				Reason:          "Dev Container configuration requests unsupported isolation features; safe plain-image fallback is available.",
			}, nil
		}
		return workspace.Environment{
			HasDevcontainer: true, Supported: true, RequiresTrust: true,
			ConfigDirectory: candidate.directory,
			Reason:          "Repository Dev Container configuration executes repository-controlled setup and requires owner approval.",
		}, nil
	}
	return workspace.Environment{Supported: true}, nil
}

// unsupportedDevcontainer rejects repository-controlled capabilities that the
// approved EnvBuilder template cannot safely honor. The list is intentionally
// conservative: the owner can still continue with the explicit plain-image
// fallback without weakening the workspace boundary.
func unsupportedDevcontainer(document map[string]any) bool {
	if _, exists := document["dockerComposeFile"]; exists {
		return true
	}
	if value, ok := document["privileged"].(bool); ok && value {
		return true
	}
	for _, key := range []string{"capAdd", "mounts", "runArgs", "workspaceMount", "initializeCommand"} {
		if nonemptyJSONValue(document[key]) {
			return true
		}
	}
	for _, key := range []string{"containerUser", "remoteUser"} {
		if value, ok := document[key].(string); ok && strings.EqualFold(strings.TrimSpace(value), "root") {
			return true
		}
	}
	if features, ok := document["features"].(map[string]any); ok {
		for feature := range features {
			feature = strings.ToLower(feature)
			if strings.Contains(feature, "docker-in-docker") || strings.Contains(feature, "docker-outside-of-docker") {
				return true
			}
		}
	}
	return false
}

func nonemptyJSONValue(value any) bool {
	switch value := value.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(value) != ""
	case []any:
		return len(value) != 0
	case map[string]any:
		return len(value) != 0
	case bool:
		return value
	default:
		return true
	}
}

type Initializer struct {
	github       GitHubClient
	runner       HelperRunner
	environments EnvironmentStore
	authorizer   InstallationAuthorizer
}

func NewInitializer(github GitHubClient, runner HelperRunner, environments EnvironmentStore, authorizer InstallationAuthorizer) (*Initializer, error) {
	if github == nil || runner == nil || environments == nil || authorizer == nil {
		return nil, errors.New("GitHub client, Coder helper runner, environment store, and installation authorizer are required")
	}
	return &Initializer{github: github, runner: runner, environments: environments, authorizer: authorizer}, nil
}

func (i *Initializer) Initialize(ctx context.Context, value core.Workspace) error {
	if value.ProviderResourceID == "" {
		return fmt.Errorf("workspace initialization: %w", core.ErrPrecondition)
	}
	err := i.authorizer.WithGitHubInstallationLease(ctx, value.OwnerID, value.Repository.InstallationID, func(leaseCtx context.Context) error {
		return i.cloneRepository(leaseCtx, value)
	})
	if err != nil {
		return fmt.Errorf("workspace initialization GitHub access: %w", err)
	}
	if err := i.PrepareEnvironment(ctx, value); err != nil {
		return err
	}
	environment := value.EnvironmentVariables
	var authKey []byte
	var grantedSecrets map[string][]byte
	if i.environments != nil {
		environment, err = i.environments.LoadWorkspaceEnvironment(ctx, value)
		if err != nil {
			return err
		}
		authKey, err = i.environments.LoadOrCreateWorkspaceCodexAuthKey(ctx, value)
		if err != nil {
			return err
		}
		if len(authKey) != workspacehelper.CodexAuthKeyBytes {
			for index := range authKey {
				authKey[index] = 0
			}
			return errors.New("workspace Codex authentication key is invalid")
		}
		defer func() {
			for index := range authKey {
				authKey[index] = 0
			}
		}()
		grantedSecrets, err = i.environments.LoadGrantedWorkspaceSecrets(ctx, value.OwnerID, value.ID)
		if err != nil {
			return errors.New("load granted workspace secrets")
		}
		defer wipeGrantedSecrets(grantedSecrets)
	} else {
		return errors.New("workspace Codex authentication persistence is not configured")
	}
	configuration, err := json.Marshal(workspacehelper.Request{
		Version: workspacehelper.Version, Operation: workspacehelper.OpConfigure,
		Environment: environment, SafetyMode: string(value.SafetyMode),
		Network:        value.SafetyMode != core.SafetySafe,
		CodexAuthKey:   authKey,
		GrantedSecrets: grantedSecrets,
	})
	if err != nil {
		return err
	}
	configured, err := i.runner.RunHelper(ctx, value.ProviderResourceID, configuration)
	for index := range configuration {
		configuration[index] = 0
	}
	if err != nil {
		return fmt.Errorf("run workspace configuration: %w", err)
	}
	if _, err := workspacehelper.DecodeResponse(configured); err != nil {
		return fmt.Errorf("configure workspace runtime: %w", err)
	}
	return nil
}

func (i *Initializer) cloneRepository(ctx context.Context, value core.Workspace) error {
	repositoryID, err := repositoryIdentity(value.Repository)
	if err != nil {
		return err
	}
	return githubapp.UseInstallationToken(
		ctx, i.github, i.authorizer, value.OwnerID, value.Repository.InstallationID,
		[]int64{repositoryID}, map[string]string{"contents": "write"},
		func(tokenCtx context.Context, token string) error {
			request, marshalErr := json.Marshal(workspacehelper.Request{
				Version: workspacehelper.Version, Operation: workspacehelper.OpGitClone,
				Repository: value.Repository.FullName, BaseBranch: value.BaseBranch,
				Branch: value.Branch, GitHubToken: token,
			})
			if marshalErr != nil {
				return marshalErr
			}
			response, runErr := i.runner.RunHelper(tokenCtx, value.ProviderResourceID, request)
			for index := range request {
				request[index] = 0
			}
			if runErr != nil {
				return fmt.Errorf("run repository initializer: %w", runErr)
			}
			if _, decodeErr := workspacehelper.DecodeResponse(response); decodeErr != nil {
				return fmt.Errorf("initialize repository checkout: %w", decodeErr)
			}
			return nil
		},
	)
}

func wipeGrantedSecrets(values map[string][]byte) {
	for name, value := range values {
		for index := range value {
			value[index] = 0
		}
		delete(values, name)
	}
}

func (i *Initializer) PrepareEnvironment(ctx context.Context, value core.Workspace) error {
	if (len(value.EnvironmentVariables) != 0 || value.InitialPrompt != "") && i.environments == nil {
		return errors.New("workspace environment persistence is not configured")
	}
	if len(value.EnvironmentVariables) != 0 {
		if err := i.environments.SaveWorkspaceEnvironment(ctx, value); err != nil {
			return err
		}
	}
	if value.InitialPrompt != "" {
		prompts, ok := i.environments.(InitialPromptStore)
		if !ok {
			return errors.New("workspace initial prompt persistence is not configured")
		}
		if err := prompts.SaveWorkspaceInitialPrompt(ctx, value); err != nil {
			return err
		}
	}
	return nil
}

func repositoryIdentity(repository core.Repository) (int64, error) {
	repositoryID, err := strconv.ParseInt(repository.ID, 10, 64)
	if err != nil || repositoryID <= 0 {
		return 0, fmt.Errorf("GitHub repository identity: %w", core.ErrInvalid)
	}
	return repositoryID, nil
}

var _ workspace.EnvironmentDetector = (*Detector)(nil)
var _ workspace.Initializer = (*Initializer)(nil)
var _ workspace.EnvironmentPreparer = (*Initializer)(nil)
