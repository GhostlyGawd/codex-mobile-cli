package githubworkspace

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/githubapp"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/workspacehelper"
)

type noopTokenUseStore struct{}

func (noopTokenUseStore) BeginGitHubInstallationTokenUse(context.Context, githubapp.TokenUseMetadata) error {
	return nil
}
func (noopTokenUseStore) SetGitHubInstallationTokenUseExpiry(context.Context, string, int64, string, time.Time) error {
	return nil
}
func (noopTokenUseStore) RevokeGitHubInstallationTokenUse(context.Context, string, int64, string, time.Time) error {
	return nil
}

type deniedInstallationAuthorizer struct{ noopTokenUseStore }

func (deniedInstallationAuthorizer) WithGitHubInstallationLease(context.Context, string, int64, func(context.Context) error) error {
	return fmt.Errorf("GitHub installation is disconnected: %w", core.ErrPrecondition)
}

type allowInstallationAuthorizer struct{ noopTokenUseStore }

func (allowInstallationAuthorizer) WithGitHubInstallationLease(ctx context.Context, _ string, _ int64, operation func(context.Context) error) error {
	return operation(ctx)
}

type initializerGitHub struct {
	tokenCalls   int
	revokeCalls  int
	revokedToken string
}

func (g *initializerGitHub) InstallationToken(context.Context, int64, []int64, map[string]string) (githubapp.InstallationToken, error) {
	g.tokenCalls++
	return githubapp.InstallationToken{Token: "github-sensitive-token", ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func (g *initializerGitHub) RevokeInstallationToken(_ context.Context, token string) error {
	g.revokeCalls++
	g.revokedToken = token
	return nil
}

func (*initializerGitHub) RepositoryContent(context.Context, string, string, string, string) ([]byte, bool, error) {
	return nil, false, nil
}

type detectorGitHub struct {
	contents   map[string][]byte
	paths      []string
	tokenCalls int
	revokes    int
}

func (d *detectorGitHub) InstallationToken(context.Context, int64, []int64, map[string]string) (githubapp.InstallationToken, error) {
	d.tokenCalls++
	return githubapp.InstallationToken{Token: "short-lived-read-token", ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func (d *detectorGitHub) RevokeInstallationToken(context.Context, string) error {
	d.revokes++
	return nil
}

func TestDetectorRejectsDisconnectedInstallationBeforeMinting(t *testing.T) {
	github := &detectorGitHub{}
	detector, err := NewDetector(github, deniedInstallationAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = detector.Detect(context.Background(), "owner-id", core.Repository{
		ID: "123", InstallationID: 42, FullName: "owner/repository",
	}, "main")
	if !errors.Is(err, core.ErrPrecondition) {
		t.Fatalf("disconnected detection = %v", err)
	}
	if github.tokenCalls != 0 || len(github.paths) != 0 {
		t.Fatalf("disconnected detection reached GitHub: tokens=%d paths=%v", github.tokenCalls, github.paths)
	}
}

func (d *detectorGitHub) RepositoryContent(_ context.Context, token, repository, path, branch string) ([]byte, bool, error) {
	if token != "short-lived-read-token" || repository != "owner/repository" || branch != "main" {
		return nil, false, core.ErrUnauthorized
	}
	d.paths = append(d.paths, path)
	content, ok := d.contents[path]
	return append([]byte(nil), content...), ok, nil
}

func TestDetectorPreservesExactStandardDevcontainerDirectory(t *testing.T) {
	for _, test := range []struct {
		name      string
		contents  map[string][]byte
		wantDir   string
		supported bool
	}{
		{
			name: "root dotfile", contents: map[string][]byte{".devcontainer.json": []byte(`{"image":"ubuntu:24.04"}`)},
			wantDir: ".", supported: true,
		},
		{
			name: "standard directory", contents: map[string][]byte{".devcontainer/devcontainer.json": []byte(`{"build":{"dockerfile":"Dockerfile"}}`)},
			wantDir: ".devcontainer", supported: true,
		},
		{
			name: "unsupported isolation request", contents: map[string][]byte{".devcontainer/devcontainer.json": []byte(`{"privileged":true}`)},
			wantDir: ".devcontainer", supported: false,
		},
		{
			name: "invalid document", contents: map[string][]byte{".devcontainer.json": []byte(`{"image":`)},
			wantDir: ".", supported: false,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			github := &detectorGitHub{contents: test.contents}
			detector, err := NewDetector(github, allowInstallationAuthorizer{})
			if err != nil {
				t.Fatal(err)
			}
			environment, err := detector.Detect(context.Background(), "owner-id", core.Repository{
				ID: "123", InstallationID: 42, FullName: "owner/repository",
			}, "main")
			if err != nil {
				t.Fatal(err)
			}
			if !environment.HasDevcontainer || !environment.RequiresTrust ||
				environment.Supported != test.supported || environment.ConfigDirectory != test.wantDir {
				t.Fatalf("detected environment = %#v", environment)
			}
			if github.tokenCalls != 1 || github.revokes != 1 {
				t.Fatalf("detector token lifecycle: minted=%d revoked=%d", github.tokenCalls, github.revokes)
			}
		})
	}
}

type initializerStore struct {
	noopTokenUseStore
	key          []byte
	grantedAlias []byte
}

func (s *initializerStore) WithGitHubInstallationLease(ctx context.Context, _ string, _ int64, operation func(context.Context) error) error {
	return operation(ctx)
}

func (s *initializerStore) SaveWorkspaceEnvironment(context.Context, core.Workspace) error {
	return nil
}
func (s *initializerStore) SaveWorkspaceInitialPrompt(context.Context, core.Workspace) error {
	return nil
}
func (s *initializerStore) LoadWorkspaceEnvironment(context.Context, core.Workspace) (map[string]string, error) {
	return map[string]string{"PRIVATE_TOKEN": "environment-sensitive-value"}, nil
}
func (s *initializerStore) LoadOrCreateWorkspaceCodexAuthKey(context.Context, core.Workspace) ([]byte, error) {
	return append([]byte(nil), s.key...), nil
}
func (s *initializerStore) LoadGrantedWorkspaceSecrets(context.Context, string, string) (map[string][]byte, error) {
	s.grantedAlias = []byte("granted-sensitive-value")
	return map[string][]byte{"GRANTED_TOKEN": s.grantedAlias}, nil
}

type initializerRunner struct {
	requests [][]byte
	decoded  []workspacehelper.Request
}

func (r *initializerRunner) RunHelper(_ context.Context, _ string, request []byte) ([]byte, error) {
	r.requests = append(r.requests, request)
	var decoded workspacehelper.Request
	if err := json.Unmarshal(request, &decoded); err != nil {
		return nil, err
	}
	r.decoded = append(r.decoded, decoded)
	return json.Marshal(workspacehelper.Response{Version: workspacehelper.Version, OK: true})
}

func TestInitializerTransfersAndScrubsWorkspaceAuthKey(t *testing.T) {
	key := bytes.Repeat([]byte{0x37}, workspacehelper.CodexAuthKeyBytes)
	runner := &initializerRunner{}
	store := &initializerStore{key: key}
	github := &initializerGitHub{}
	initializer, err := NewInitializer(github, runner, store, store)
	if err != nil {
		t.Fatal(err)
	}
	value := core.Workspace{
		ID: "workspace-1", OwnerID: "owner-1", ProviderResourceID: "provider-1",
		Repository: core.Repository{ID: "123", InstallationID: 42, FullName: "owner/repository"},
		BaseBranch: "main", Branch: "codex-mobile/task-1", SafetyMode: core.SafetyBalanced,
	}
	if err := initializer.Initialize(context.Background(), value); err != nil {
		t.Fatal(err)
	}
	if len(runner.decoded) != 2 || runner.decoded[1].Operation != workspacehelper.OpConfigure ||
		!bytes.Equal(runner.decoded[1].CodexAuthKey, key) ||
		runner.decoded[1].Environment["PRIVATE_TOKEN"] != "environment-sensitive-value" ||
		!bytes.Equal(runner.decoded[1].GrantedSecrets["GRANTED_TOKEN"], []byte("granted-sensitive-value")) {
		t.Fatal("trusted configure request did not carry the expected private state")
	}
	for _, request := range runner.requests {
		if !bytes.Equal(request, make([]byte, len(request))) {
			t.Fatal("serialized helper request retained GitHub, environment, or Codex key material")
		}
	}
	if !bytes.Equal(store.grantedAlias, make([]byte, len(store.grantedAlias))) {
		t.Fatal("plaintext grant buffer returned by the store was not zeroed")
	}
	if github.tokenCalls != 1 || github.revokeCalls != 1 || github.revokedToken != "github-sensitive-token" {
		t.Fatalf("initializer token lifecycle: minted=%d revoked=%d token=%q", github.tokenCalls, github.revokeCalls, github.revokedToken)
	}
}

func TestInitializerRejectsDisconnectedInstallationBeforeMintingOrRunning(t *testing.T) {
	runner := &initializerRunner{}
	store := &initializerStore{key: bytes.Repeat([]byte{0x37}, workspacehelper.CodexAuthKeyBytes)}
	github := &initializerGitHub{}
	initializer, err := NewInitializer(github, runner, store, deniedInstallationAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	value := core.Workspace{
		ID: "workspace-1", OwnerID: "owner-1", ProviderResourceID: "provider-1",
		Repository: core.Repository{ID: "123", InstallationID: 42, FullName: "owner/repository"},
		BaseBranch: "main", Branch: "codex-mobile/task-1", SafetyMode: core.SafetyBalanced,
	}
	if err := initializer.Initialize(context.Background(), value); !errors.Is(err, core.ErrPrecondition) {
		t.Fatalf("disconnected initialization = %v", err)
	}
	if len(runner.requests) != 0 {
		t.Fatal("disconnected installation reached the workspace helper")
	}
	if github.tokenCalls != 0 {
		t.Fatalf("disconnected initialization minted %d installation tokens", github.tokenCalls)
	}
}
