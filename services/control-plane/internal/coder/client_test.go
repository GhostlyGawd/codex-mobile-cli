package coder

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/workspace"
)

func TestHelperCommandIsFixedAndKeepsTokenOutOfArguments(t *testing.T) {
	t.Parallel()
	workspaceID := "123e4567-e89b-12d3-a456-426614174000"
	args := helperCommandArguments(workspaceID, defaultWorkspaceHelperPath)
	want := []string{"ssh", "--disable-autostart", "--wait", "yes", workspaceID, "--", defaultWorkspaceHelperPath}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("helper args = %#v, want %#v", args, want)
	}
	for _, arg := range args {
		if strings.Contains(arg, "super-secret") {
			t.Fatal("Coder token appeared in arguments")
		}
	}
	env := helperEnvironment("https://coder.example.test", "super-secret")
	if !slices.Contains(env, "CODER_SESSION_TOKEN=super-secret") || !slices.Contains(env, "CODER_DISABLE_DIRECT_CONNECTIONS=true") {
		t.Fatalf("helper environment missing required fixed settings: %#v", env)
	}
}

func TestRunHelperUsesFixedWorkingDirectoryAndBoundedLifetime(t *testing.T) {
	workspaceID := "123e4567-e89b-12d3-a456-426614174000"
	newClient := func(t *testing.T, token string) *Client {
		t.Helper()
		client, err := New(Config{
			URL: "https://coder.example.test", Token: token,
			OrganizationID: "org", OwnerID: "me", TemplateID: "template",
		})
		if err != nil {
			t.Fatal(err)
		}
		return client
	}

	t.Run("fixed working directory", func(t *testing.T) {
		client := newClient(t, "working-directory-child-token")
		var command *exec.Cmd
		client.commandContext = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
			command = exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRunHelperNoopChild$")
			return command
		}
		if _, err := client.RunHelper(context.Background(), workspaceID, []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
		if command == nil {
			t.Fatal("helper command was not created")
		}
		if command.Dir != trustedHelperWorkingDirectory {
			t.Fatalf("helper working directory = %q, want %q", command.Dir, trustedHelperWorkingDirectory)
		}
	})

	t.Run("internal deadline stops hung child", func(t *testing.T) {
		client := newClient(t, "blocking-child-token")
		client.helperTimeout = 40 * time.Millisecond
		client.commandContext = blockingHelperCommand
		started := time.Now()
		if _, err := client.RunHelper(context.Background(), workspaceID, []byte(`{}`)); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("hung helper deadline = %v", err)
		}
		if elapsed := time.Since(started); elapsed > 2*time.Second {
			t.Fatalf("hung helper exceeded bounded cancellation time: %s", elapsed)
		}
	})

	t.Run("caller cancellation stops hung child", func(t *testing.T) {
		client := newClient(t, "blocking-child-token")
		client.helperTimeout = 2 * time.Second
		client.commandContext = blockingHelperCommand
		ctx, cancel := context.WithCancel(context.Background())
		timer := time.AfterFunc(40*time.Millisecond, cancel)
		defer timer.Stop()
		_, err := client.RunHelper(ctx, workspaceID, []byte(`{}`))
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled helper = %v", err)
		}
		var ambiguous *RemoteHelperAmbiguityError
		if !errors.As(err, &ambiguous) || !ambiguous.GitHubTokenUseSafeAfter().After(time.Now()) || ambiguous.GitHubTokenUseSafeAfter().After(time.Now().Add(2*time.Second)) {
			t.Fatalf("canceled helper ambiguity = %#v", ambiguous)
		}
	})
}

func TestHelperRequestDeadlineIsControlPlaneOwned(t *testing.T) {
	deadline := time.Now().Add(time.Minute).UTC()
	prepared, err := helperRequestWithDeadline([]byte(`{"version":1,"operation":"git_push"}`), deadline)
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(prepared, &envelope); err != nil {
		t.Fatal(err)
	}
	var encoded int64
	if err := json.Unmarshal(envelope["operation_deadline_unix_milli"], &encoded); err != nil || encoded != deadline.UnixMilli() {
		t.Fatalf("prepared helper deadline = %d, %v", encoded, err)
	}
	if _, err := helperRequestWithDeadline([]byte(`{"operation_deadline_unix_milli":1}`), deadline); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("caller-owned helper deadline = %v", err)
	}
}

func TestRunHelperNoopChild(t *testing.T) {}

func TestRunHelperBlockingChild(t *testing.T) {
	if os.Getenv("CODER_SESSION_TOKEN") != "blocking-child-token" {
		return
	}
	time.Sleep(10 * time.Minute)
}

func blockingHelperCommand(ctx context.Context, _ string, _ ...string) *exec.Cmd {
	return exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRunHelperBlockingChild$")
}

func TestProvisionAndLifecycle(t *testing.T) {
	var mu sync.Mutex
	requests := make([]map[string]any, 0)
	deleteRequested := false
	created := false
	latestBuildID := "00000000-0000-4000-8000-000000000001"
	latestTransition := "stop"
	latestStatus := "stopped"
	buildCounter := 1
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Coder-Session-Token") != "secret-token" {
			t.Fatalf("missing Coder auth header")
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			mu.Lock()
			deleted := deleteRequested
			exists := created
			buildID, transition, status := latestBuildID, latestTransition, latestStatus
			mu.Unlock()
			if strings.Contains(r.URL.Path, "/users/") && !exists {
				http.Error(w, `{"message":"workspace not found"}`, http.StatusNotFound)
				return
			}
			if deleted {
				http.Error(w, `{"message":"workspace not found"}`, http.StatusNotFound)
				return
			}
			_, _ = fmt.Fprintf(w, `{"id":"coder-ws-1","latest_build":{"id":%q,"status":%q,"transition":%q,"resources":[]}}`, buildID, status, transition)
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		requests = append(requests, body)
		if strings.Contains(r.URL.Path, "/users/") {
			created = true
		}
		transition, _ := body["transition"].(string)
		if transition == "delete" {
			deleteRequested = true
		} else if transition == "stop" {
			buildCounter++
			latestBuildID = fmt.Sprintf("00000000-0000-4000-8000-%012d", buildCounter)
			latestTransition, latestStatus = "stop", "stopped"
		} else if transition == "start" {
			buildCounter++
			latestBuildID = fmt.Sprintf("00000000-0000-4000-8000-%012d", buildCounter)
			latestTransition, latestStatus = "start", "running"
		}
		buildID, buildTransition, buildStatus := latestBuildID, latestTransition, latestStatus
		mu.Unlock()
		if strings.Contains(r.URL.Path, "/users/") {
			_, _ = fmt.Fprintf(w, `{"id":"coder-ws-1","name":"ws-1","latest_build":{"id":%q,"status":"pending","transition":"start"}}`, buildID)
			return
		}
		if buildTransition == "start" {
			_, _ = fmt.Fprintf(w, `{"id":%q,"status":%q,"transition":"start"}`, buildID, buildStatus)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	client, err := New(Config{URL: server.URL, Token: "secret-token", OrganizationID: "org-id", OwnerID: "me", TemplateID: "template-id"})
	if err != nil {
		t.Fatal(err)
	}
	request := workspace.ProvisionRequest{
		WorkspaceID: "ws_TEST_123", Repository: core.Repository{ID: "repo-1"}, Quota: core.Quota{CPUMilli: 1000, MemoryMiB: 2048, DiskGiB: 8}, SafetyMode: core.SafetyBalanced, DevcontainerDir: ".",
	}
	id, err := client.Provision(context.Background(), request)
	if err != nil || id != "coder-ws-1" {
		t.Fatalf("provision: %q %v", id, err)
	}
	if err := client.Start(context.Background(), id, workspace.StartRequest{SafetyMode: core.SafetySafe, Quota: request.Quota}); err != nil {
		t.Fatal(err)
	}
	if err := client.Stop(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if err := client.ApplyQuota(context.Background(), id, request.Quota); err != nil {
		t.Fatal(err)
	}
	if err := client.ApplyQuota(context.Background(), id, core.Quota{CPUMilli: 500, MemoryMiB: 1536, DiskGiB: 8}); err != nil {
		t.Fatal(err)
	}
	if err := client.Delete(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 6 {
		t.Fatalf("expected create,start,stop,confirmed-quota,rebalance-quota,delete; got %d: %#v", len(requests), requests)
	}
	encoded, _ := json.Marshal(requests[0])
	for _, want := range []string{`"automatic_updates":"never"`, `"workspace_mode"`, `"plain"`, `"setup_approval_id"`, `"devcontainer_dir"`, `"."`, `"allow_egress"`, `"disk_gib"`, `"8"`} {
		if !strings.Contains(string(encoded), want) {
			t.Fatalf("create request missing %s: %s", want, encoded)
		}
	}
	if strings.Contains(string(encoded), "secret-token") {
		t.Fatal("Coder token leaked into request body")
	}
	startBuild, _ := json.Marshal(requests[1])
	if !strings.Contains(string(startBuild), `"allow_egress","value":"false"`) || strings.Contains(string(startBuild), "disk_gib") {
		t.Fatalf("resume start did not apply safe egress with immutable disk omitted: %s", startBuild)
	}
	for _, index := range []int{3, 4} {
		quotaBuild, _ := json.Marshal(requests[index])
		if strings.Contains(string(quotaBuild), "disk_gib") {
			t.Fatalf("immutable disk parameter was resent during rebalance: %s", quotaBuild)
		}
	}
}

func TestProvisionRecoversAmbiguousCreateWithoutDuplicateProvider(t *testing.T) {
	var mu sync.Mutex
	created := false
	postCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			mu.Lock()
			exists := created
			mu.Unlock()
			if !exists {
				http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
				return
			}
			_, _ = fmt.Fprintf(w, `{"id":"provider-recovered","name":%q}`, providerWorkspaceName("logical-workspace"))
			return
		}
		mu.Lock()
		postCalls++
		created = true
		mu.Unlock()
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("test server cannot simulate response loss")
		}
		connection, _, err := hijacker.Hijack()
		if err != nil {
			t.Fatal(err)
		}
		_ = connection.Close()
	}))
	defer server.Close()
	client, err := New(Config{URL: server.URL, Token: "token", OrganizationID: "org", OwnerID: "me", TemplateID: "template"})
	if err != nil {
		t.Fatal(err)
	}
	request := workspace.ProvisionRequest{
		WorkspaceID: "logical-workspace", Repository: core.Repository{ID: "repo"},
		Quota: core.Quota{CPUMilli: 1000, MemoryMiB: 2048, DiskGiB: 8}, SafetyMode: core.SafetyBalanced,
	}
	for attempt := 0; attempt < 2; attempt++ {
		id, provisionErr := client.Provision(context.Background(), request)
		if provisionErr != nil || id != "provider-recovered" {
			t.Fatalf("attempt %d recovered %q, %v", attempt, id, provisionErr)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if postCalls != 1 {
		t.Fatalf("ambiguous create issued %d provider creations, want 1", postCalls)
	}
}

func TestProviderWorkspaceNameIsStableBoundedAndCollisionResistant(t *testing.T) {
	t.Parallel()
	first := providerWorkspaceName(strings.Repeat("same-prefix", 20) + "-one")
	second := providerWorkspaceName(strings.Repeat("same-prefix", 20) + "-two")
	if first != providerWorkspaceName(strings.Repeat("same-prefix", 20)+"-one") || first == second {
		t.Fatalf("provider names are not stable and distinct: %q %q", first, second)
	}
	if len(first) > 32 || !regexp.MustCompile(`^[a-z0-9-]+$`).MatchString(first) {
		t.Fatalf("provider name is outside Coder bounds: %q", first)
	}
}

func TestStartResponseLossIsRecoveredWithoutDuplicateBuild(t *testing.T) {
	const previousBuildID = "10000000-0000-4000-8000-000000000001"
	const acceptedBuildID = "10000000-0000-4000-8000-000000000002"
	started := false
	postCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			status, transition, buildID := "stopped", "stop", previousBuildID
			if started {
				status, transition, buildID = "running", "start", acceptedBuildID
			}
			_, _ = fmt.Fprintf(w, `{"id":"provider-id","latest_build":{"id":%q,"transition":%q,"status":%q}}`, buildID, transition, status)
			return
		}
		postCalls++
		started = true
		hijacker := w.(http.Hijacker)
		connection, _, err := hijacker.Hijack()
		if err != nil {
			t.Fatal(err)
		}
		_ = connection.Close()
	}))
	defer server.Close()
	client, err := New(Config{URL: server.URL, Token: "token", OrganizationID: "org", OwnerID: "me", TemplateID: "template"})
	if err != nil {
		t.Fatal(err)
	}
	request := workspace.SetupStartRequest{
		WorkspaceID: "logical", ConfigDirectory: ".devcontainer", UseEnvBuilder: true,
		SafetyMode: core.SafetyBalanced, Quota: core.Quota{CPUMilli: 1000, MemoryMiB: 2048, DiskGiB: 8},
	}
	if err := client.StartWithSetup(context.Background(), "provider-id", request); err != nil {
		t.Fatal(err)
	}
	if err := client.StartWithSetup(context.Background(), "provider-id", request); err != nil {
		t.Fatal(err)
	}
	if postCalls != 1 {
		t.Fatalf("ambiguous setup start issued %d builds, want 1", postCalls)
	}
}

func TestApprovedSetupBuildUsesExactDirectoryOrPlainFallback(t *testing.T) {
	for _, test := range []struct {
		name          string
		directory     string
		useEnvBuilder bool
		wantMode      string
	}{
		{name: "root file", directory: ".", useEnvBuilder: true, wantMode: "approved-envbuilder"},
		{name: "directory file", directory: ".devcontainer", useEnvBuilder: true, wantMode: "approved-envbuilder"},
		{name: "unsupported fallback", directory: ".devcontainer", useEnvBuilder: false, wantMode: "plain"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var body map[string]any
			started := false
			const previousBuildID = "20000000-0000-4000-8000-000000000001"
			const acceptedBuildID = "20000000-0000-4000-8000-000000000002"
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Coder-Session-Token") != "secret-token" {
					t.Fatal("missing Coder authentication")
				}
				if r.Method == http.MethodGet {
					if started {
						_, _ = fmt.Fprintf(w, `{"id":"provider-id","latest_build":{"id":%q,"transition":"start","status":"running"}}`, acceptedBuildID)
					} else {
						_, _ = fmt.Fprintf(w, `{"id":"provider-id","latest_build":{"id":%q,"transition":"stop","status":"stopped"}}`, previousBuildID)
					}
					return
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				started = true
				_, _ = fmt.Fprintf(w, `{"id":%q,"transition":"start","status":"pending"}`, acceptedBuildID)
			}))
			defer server.Close()
			client, err := New(Config{URL: server.URL, Token: "secret-token", OrganizationID: "org", OwnerID: "me", TemplateID: "template"})
			if err != nil {
				t.Fatal(err)
			}
			err = client.StartWithSetup(context.Background(), "provider-id", workspace.SetupStartRequest{
				WorkspaceID: "ws_logical", ConfigDirectory: test.directory, UseEnvBuilder: test.useEnvBuilder,
				SafetyMode: core.SafetyBalanced, Quota: core.Quota{CPUMilli: 1000, MemoryMiB: 2048, DiskGiB: 8},
			})
			if err != nil {
				t.Fatal(err)
			}
			encoded, _ := json.Marshal(body)
			text := string(encoded)
			for _, want := range []string{`"transition":"start"`, `"workspace_mode"`, `"` + test.wantMode + `"`, `"devcontainer_dir"`, `"` + test.directory + `"`} {
				if !strings.Contains(text, want) {
					t.Fatalf("approved setup request missing %s: %s", want, text)
				}
			}
			if test.useEnvBuilder && !strings.Contains(text, `"value":"approval_`) {
				t.Fatalf("EnvBuilder request omitted approval receipt: %s", text)
			}
			if !test.useEnvBuilder && strings.Contains(text, `"value":"approval_`) {
				t.Fatalf("plain fallback received an approval receipt: %s", text)
			}
			if strings.Contains(text, "secret-token") {
				t.Fatal("Coder token leaked into approved setup parameters")
			}
		})
	}
}

func TestStopAndWaitRequiresConfirmedProviderStop(t *testing.T) {
	getCalls, postCalls := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			postCalls++
			_, _ = w.Write([]byte(`{}`))
			return
		}
		getCalls++
		status := "stopping"
		if getCalls > 1 {
			status = "stopped"
		}
		_, _ = fmt.Fprintf(w, `{"id":"provider-id","latest_build":{"transition":"stop","status":%q}}`, status)
	}))
	defer server.Close()
	client, err := New(Config{URL: server.URL, Token: "token", OrganizationID: "org", OwnerID: "me", TemplateID: "template"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.StopAndWait(ctx, "provider-id"); err != nil {
		t.Fatal(err)
	}
	if getCalls != 2 {
		t.Fatalf("confirmed stop polls = %d, want 2", getCalls)
	}
	if postCalls != 0 {
		t.Fatalf("in-progress stop was duplicated %d times", postCalls)
	}
}

func TestStopAndWaitTreatsConfirmedStopAsIdempotentSuccess(t *testing.T) {
	getCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			t.Fatal("confirmed stop issued a duplicate provider build")
		}
		getCalls++
		_, _ = w.Write([]byte(`{"id":"provider-id","latest_build":{"transition":"stop","status":"stopped"}}`))
	}))
	defer server.Close()
	client, err := New(Config{URL: server.URL, Token: "token", OrganizationID: "org", OwnerID: "me", TemplateID: "template"})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.StopAndWait(context.Background(), "provider-id"); err != nil {
		t.Fatal(err)
	}
	if getCalls != 1 {
		t.Fatalf("confirmed stop reads = %d, want 1", getCalls)
	}
}

func TestStopAndWaitInternalDeadlineRetainsIdempotentRetry(t *testing.T) {
	stopped := false
	postCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			postCalls++
			_, _ = w.Write([]byte(`{}`))
			return
		}
		status := "pending"
		if stopped {
			status = "stopped"
		}
		_, _ = fmt.Fprintf(w, `{"id":"provider-id","latest_build":{"transition":"stop","status":%q}}`, status)
	}))
	defer server.Close()
	client, err := New(Config{URL: server.URL, Token: "token", OrganizationID: "org", OwnerID: "me", TemplateID: "template"})
	if err != nil {
		t.Fatal(err)
	}
	client.stopTimeout = 40 * time.Millisecond
	if err := client.StopAndWait(context.Background(), "provider-id"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("pending stop deadline = %v", err)
	}
	stopped = true
	if err := client.StopAndWait(context.Background(), "provider-id"); err != nil {
		t.Fatalf("retry confirmed stop: %v", err)
	}
	if postCalls != 0 {
		t.Fatalf("pending/confirmed stop retry issued %d duplicate builds", postCalls)
	}
}

func TestDeleteWaitsForConfirmedAbsence(t *testing.T) {
	getCalls, postCalls := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			postCalls++
			_, _ = w.Write([]byte(`{}`))
			return
		}
		getCalls++
		if getCalls >= 3 {
			http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
			return
		}
		transition, status := "start", "running"
		if getCalls == 2 {
			transition, status = "delete", "running"
		}
		_, _ = fmt.Fprintf(w, `{"id":"provider-id","latest_build":{"transition":%q,"status":%q}}`, transition, status)
	}))
	defer server.Close()
	client, err := New(Config{URL: server.URL, Token: "token", OrganizationID: "org", OwnerID: "me", TemplateID: "template"})
	if err != nil {
		t.Fatal(err)
	}
	client.quotas["provider-id"] = core.Quota{DiskGiB: 8}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.Delete(ctx, "provider-id"); err != nil {
		t.Fatal(err)
	}
	if getCalls != 3 || postCalls != 1 {
		t.Fatalf("confirmed delete calls: gets=%d posts=%d", getCalls, postCalls)
	}
	if _, retained := client.quotas["provider-id"]; retained {
		t.Fatal("confirmed deletion retained quota state")
	}
}

func TestDeleteIsIdempotentWhenCoderWorkspaceIsAlreadyAbsent(t *testing.T) {
	postCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			postCalls++
		}
		http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
	}))
	defer server.Close()
	client, err := New(Config{URL: server.URL, Token: "token", OrganizationID: "org", OwnerID: "me", TemplateID: "template"})
	if err != nil {
		t.Fatal(err)
	}
	client.quotas["provider-id"] = core.Quota{DiskGiB: 8}
	if err := client.Delete(context.Background(), "provider-id"); err != nil {
		t.Fatal(err)
	}
	if postCalls != 0 {
		t.Fatalf("already-absent deletion issued %d builds", postCalls)
	}
	if _, retained := client.quotas["provider-id"]; retained {
		t.Fatal("already-absent deletion retained quota state")
	}
}

func TestDeleteFailureAndTimeoutRetainRetryState(t *testing.T) {
	t.Run("terminal build failure", func(t *testing.T) {
		getCalls := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			getCalls++
			status := "running"
			if getCalls > 1 {
				status = "failed"
			}
			_, _ = fmt.Fprintf(w, `{"id":"provider-id","latest_build":{"transition":"delete","status":%q}}`, status)
		}))
		defer server.Close()
		client, err := New(Config{URL: server.URL, Token: "token", OrganizationID: "org", OwnerID: "me", TemplateID: "template"})
		if err != nil {
			t.Fatal(err)
		}
		client.quotas["provider-id"] = core.Quota{DiskGiB: 8}
		if err := client.Delete(context.Background(), "provider-id"); err == nil {
			t.Fatal("failed delete build was accepted as final")
		}
		if _, retained := client.quotas["provider-id"]; !retained {
			t.Fatal("failed deletion discarded retry quota state")
		}
	})

	t.Run("context timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"id":"provider-id","latest_build":{"transition":"delete","status":"running"}}`))
		}))
		defer server.Close()
		client, err := New(Config{URL: server.URL, Token: "token", OrganizationID: "org", OwnerID: "me", TemplateID: "template"})
		if err != nil {
			t.Fatal(err)
		}
		client.quotas["provider-id"] = core.Quota{DiskGiB: 8}
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
		defer cancel()
		if err := client.Delete(ctx, "provider-id"); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("delete timeout = %v", err)
		}
		if _, retained := client.quotas["provider-id"]; !retained {
			t.Fatal("timed-out deletion discarded retry quota state")
		}
	})
}

func TestDeleteRetryReissuesFailedTerminalBuild(t *testing.T) {
	postCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			postCalls++
			_, _ = w.Write([]byte(`{}`))
			return
		}
		if postCalls != 0 {
			http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"id":"provider-id","latest_build":{"transition":"delete","status":"failed"}}`))
	}))
	defer server.Close()
	client, err := New(Config{URL: server.URL, Token: "token", OrganizationID: "org", OwnerID: "me", TemplateID: "template"})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Delete(context.Background(), "provider-id"); err != nil {
		t.Fatal(err)
	}
	if postCalls != 1 {
		t.Fatalf("failed delete retry builds = %d, want 1", postCalls)
	}
}

func TestApprovedSetupRejectsUntrustedDirectoryBeforeCoderRequest(t *testing.T) {
	client, err := New(Config{URL: "https://coder.example.test", Token: "token", OrganizationID: "org", OwnerID: "me", TemplateID: "template"})
	if err != nil {
		t.Fatal(err)
	}
	err = client.StartWithSetup(context.Background(), "provider-id", workspace.SetupStartRequest{
		WorkspaceID: "ws_logical", ConfigDirectory: "../outside", UseEnvBuilder: true,
		SafetyMode: core.SafetyBalanced, Quota: core.Quota{CPUMilli: 1000, MemoryMiB: 2048, DiskGiB: 8},
	})
	if !strings.Contains(fmt.Sprint(err), "invalid approved setup start") {
		t.Fatalf("unsafe setup directory error = %v", err)
	}
}

func TestProvisionParametersDisableEgressForSafeMode(t *testing.T) {
	parameters := provisionParameters(workspace.ProvisionRequest{
		WorkspaceID: "ws_safe", SafetyMode: core.SafetySafe,
		Quota: core.Quota{CPUMilli: 500, MemoryMiB: 1536, DiskGiB: 8},
	})
	values := make(map[string]string, len(parameters))
	for _, parameter := range parameters {
		values[parameter.Name] = parameter.Value
	}
	if values["allow_egress"] != "false" {
		t.Fatalf("safe-mode egress = %q, want false", values["allow_egress"])
	}
	if values["workspace_mode"] != "plain" {
		t.Fatalf("safe-mode workspace mode = %q, want plain", values["workspace_mode"])
	}
	if values["disk_gib"] != "8" {
		t.Fatalf("disk quota parameter = %q, want 8", values["disk_gib"])
	}
}

func TestApplyQuotaRejectsDiskOutsidePersistentVolumeBounds(t *testing.T) {
	t.Parallel()
	client, err := New(Config{URL: "https://coder.example.test", Token: "token", OrganizationID: "org", OwnerID: "me", TemplateID: "template"})
	if err != nil {
		t.Fatal(err)
	}
	for _, disk := range []int64{core.MinimumWorkspaceDiskGiB - 1, core.MaximumWorkspaceDiskGiB + 1} {
		err := client.ApplyQuota(context.Background(), "workspace-id", core.Quota{CPUMilli: 500, MemoryMiB: 1536, DiskGiB: disk})
		if !strings.Contains(fmt.Sprint(err), "outside the safe bounds") {
			t.Fatalf("disk %d error = %v", disk, err)
		}
	}
	client.quotas["workspace-id"] = core.Quota{CPUMilli: 500, MemoryMiB: 1536, DiskGiB: 8}
	err = client.ApplyQuota(context.Background(), "workspace-id", core.Quota{CPUMilli: 500, MemoryMiB: 1536, DiskGiB: 12})
	if !strings.Contains(fmt.Sprint(err), "persistent disk quota is immutable") {
		t.Fatalf("in-range disk resize error = %v", err)
	}
}

func TestQuotaCacheRemainsBoundedAcrossWorkspaceChurn(t *testing.T) {
	client := &Client{quotas: make(map[string]core.Quota)}
	quota := core.Quota{CPUMilli: 500, MemoryMiB: 1536, DiskGiB: 8}
	client.mu.Lock()
	for index := 0; index < maximumRememberedQuotas+100; index++ {
		client.rememberQuotaLocked(fmt.Sprintf("workspace-%d", index), quota)
	}
	retained := len(client.quotas)
	_, newestRetained := client.quotas[fmt.Sprintf("workspace-%d", maximumRememberedQuotas+99)]
	client.mu.Unlock()
	if retained != maximumRememberedQuotas || !newestRetained {
		t.Fatalf("quota cache size=%d newest=%t", retained, newestRetained)
	}
}

func TestCoderQuotaBoundsIncludeSingleWorkspaceMemoryShare(t *testing.T) {
	t.Parallel()
	maximum := core.Quota{
		CPUMilli: 6000, MemoryMiB: maximumWorkspaceMemoryMiB,
		DiskGiB: core.MaximumWorkspaceDiskGiB,
	}
	if !validWorkspaceQuota(maximum) {
		t.Fatalf("reference one-workspace quota rejected: %#v", maximum)
	}
	maximum.MemoryMiB++
	if validWorkspaceQuota(maximum) {
		t.Fatalf("quota above Coder template memory maximum accepted: %#v", maximum)
	}
}

func TestAgentPortsAndPTYEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/listening-ports") {
			_, _ = w.Write([]byte(`{"ports":[{"network":"tcp","port":3000,"process_name":"next"},{"network":"udp","port":53,"process_name":"dns"},{"network":"tcp","port":70000,"process_name":"bad"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":"workspace-id","latest_build":{"resources":[{"agents":[{"id":"agent-id","status":"connected"}]}]}}`))
	}))
	defer server.Close()
	client, _ := New(Config{URL: server.URL, Token: "token", OrganizationID: "org", OwnerID: "me", TemplateID: "template"})
	agentID, err := client.AgentID(context.Background(), "workspace-id")
	if err != nil || agentID != "agent-id" {
		t.Fatalf("agent: %q %v", agentID, err)
	}
	ports, err := client.ListeningPorts(context.Background(), agentID)
	if err != nil || len(ports) != 1 || ports[0].Port != 3000 {
		t.Fatalf("ports: %#v %v", ports, err)
	}
	endpoint, header, err := client.ptyEndpoint(agentID, "52e782d5-6e80-4944-a42f-a21201900c74", "tmux new-session -A -s cm-test", 80, 24)
	if err != nil || !strings.HasPrefix(endpoint, "ws://") || header.Get("Coder-Session-Token") != "token" || strings.Contains(endpoint, "token") {
		t.Fatalf("PTY endpoint leaked or malformed: %q %#v %v", endpoint, header, err)
	}
	if !strings.Contains(endpoint, "reconnect=52e782d5-6e80-4944-a42f-a21201900c74") || !strings.Contains(endpoint, "width=80") || !strings.Contains(endpoint, "backend_type=buffered") {
		t.Fatalf("PTY endpoint missing v2.34.6 query contract: %q", endpoint)
	}
}
