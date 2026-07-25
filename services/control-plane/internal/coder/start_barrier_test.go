package coder

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/workspace"
)

const (
	barrierOldBuildID = "30000000-0000-4000-8000-000000000001"
	barrierNewBuildID = "30000000-0000-4000-8000-000000000002"
)

func newBarrierClient(t *testing.T, handler http.Handler) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := New(Config{URL: server.URL, Token: "token", OrganizationID: "org", OwnerID: "me", TemplateID: "template"})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func writeBarrierWorkspace(t *testing.T, w http.ResponseWriter, buildID, transition, status string) {
	t.Helper()
	_, _ = fmt.Fprintf(w, `{"id":"provider-id","latest_build":{"id":%q,"transition":%q,"status":%q}}`, buildID, transition, status)
}

func TestStartWaitsForExactBuildToReachRunning(t *testing.T) {
	var posted atomic.Bool
	var polls atomic.Int32
	client := newBarrierClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posted.Store(true)
			_, _ = fmt.Fprintf(w, `{"id":%q,"transition":"start","status":"pending"}`, barrierNewBuildID)
			return
		}
		if !posted.Load() {
			writeBarrierWorkspace(t, w, barrierOldBuildID, "stop", "stopped")
			return
		}
		status := "pending"
		switch polls.Add(1) {
		case 1:
			status = "pending"
		case 2:
			status = "starting"
		default:
			status = "running"
		}
		writeBarrierWorkspace(t, w, barrierNewBuildID, "start", status)
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := client.Start(ctx, "provider-id", workspace.StartRequest{
		SafetyMode: core.SafetyBalanced,
		Quota:      core.Quota{CPUMilli: 1000, MemoryMiB: 2048, DiskGiB: 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := polls.Load(); got != 3 {
		t.Fatalf("start readiness polls = %d, want 3", got)
	}
}

func TestStartRejectsFailedCanceledAndSupersededBuilds(t *testing.T) {
	for _, test := range []struct {
		name, buildID, transition, status string
	}{
		{name: "failed", buildID: barrierNewBuildID, transition: "start", status: "failed"},
		{name: "canceled", buildID: barrierNewBuildID, transition: "start", status: "canceled"},
		{name: "superseded", buildID: barrierOldBuildID, transition: "start", status: "running"},
	} {
		t.Run(test.name, func(t *testing.T) {
			posted := false
			client := newBarrierClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					posted = true
					_, _ = fmt.Fprintf(w, `{"id":%q,"transition":"start","status":"pending"}`, barrierNewBuildID)
					return
				}
				if !posted {
					writeBarrierWorkspace(t, w, barrierOldBuildID, "stop", "stopped")
					return
				}
				writeBarrierWorkspace(t, w, test.buildID, test.transition, test.status)
			}))
			err := client.Start(context.Background(), "provider-id", workspace.StartRequest{
				SafetyMode: core.SafetyBalanced,
				Quota:      core.Quota{CPUMilli: 1000, MemoryMiB: 2048, DiskGiB: 8},
			})
			if err == nil {
				t.Fatal("unsafe start build was accepted")
			}
		})
	}
}

func TestStartReadinessHasAnInternalDeadline(t *testing.T) {
	posted := false
	client := newBarrierClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posted = true
			_, _ = fmt.Fprintf(w, `{"id":%q,"transition":"start","status":"pending"}`, barrierNewBuildID)
			return
		}
		if !posted {
			writeBarrierWorkspace(t, w, barrierOldBuildID, "stop", "stopped")
			return
		}
		writeBarrierWorkspace(t, w, barrierNewBuildID, "start", "pending")
	}))
	client.startTimeout = 40 * time.Millisecond
	err := client.Start(context.Background(), "provider-id", workspace.StartRequest{
		SafetyMode: core.SafetyBalanced,
		Quota:      core.Quota{CPUMilli: 1000, MemoryMiB: 2048, DiskGiB: 8},
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("pending start deadline = %v", err)
	}
}

func TestApplyQuotaDoesNotReturnOrCacheBeforeBuildIsRunning(t *testing.T) {
	oldQuota := core.Quota{CPUMilli: 1000, MemoryMiB: 2048, DiskGiB: 8}
	target := core.Quota{CPUMilli: 500, MemoryMiB: 1536, DiskGiB: 8}
	posted := make(chan struct{})
	var running atomic.Bool
	var didPost atomic.Bool
	client := newBarrierClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			didPost.Store(true)
			close(posted)
			_, _ = fmt.Fprintf(w, `{"id":%q,"transition":"start","status":"pending"}`, barrierNewBuildID)
			return
		}
		if !didPost.Load() {
			writeBarrierWorkspace(t, w, barrierOldBuildID, "start", "running")
			return
		}
		status := "pending"
		if running.Load() {
			status = "running"
		}
		writeBarrierWorkspace(t, w, barrierNewBuildID, "start", status)
	}))
	client.quotas["provider-id"] = oldQuota
	done := make(chan error, 1)
	go func() { done <- client.ApplyQuota(context.Background(), "provider-id", target) }()
	select {
	case <-posted:
	case <-time.After(time.Second):
		t.Fatal("quota build was not submitted")
	}
	select {
	case err := <-done:
		t.Fatalf("quota returned before provider readiness: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	client.mu.Lock()
	remembered := client.quotas["provider-id"]
	client.mu.Unlock()
	if remembered != oldQuota {
		t.Fatalf("unconfirmed quota was cached: %#v", remembered)
	}
	running.Store(true)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("confirmed quota build did not return")
	}
	client.mu.Lock()
	remembered = client.quotas["provider-id"]
	client.mu.Unlock()
	if remembered != target {
		t.Fatalf("confirmed quota was not cached: %#v", remembered)
	}
}

func TestApplyQuotaFailureAndTimeoutRetainPreviousQuota(t *testing.T) {
	oldQuota := core.Quota{CPUMilli: 1000, MemoryMiB: 2048, DiskGiB: 8}
	target := core.Quota{CPUMilli: 500, MemoryMiB: 1536, DiskGiB: 8}
	for _, test := range []struct {
		name, status string
		timeout      time.Duration
	}{
		{name: "failed", status: "failed"},
		{name: "canceled", status: "canceled"},
		{name: "timeout", status: "pending", timeout: 40 * time.Millisecond},
	} {
		t.Run(test.name, func(t *testing.T) {
			posted := false
			client := newBarrierClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					posted = true
					_, _ = fmt.Fprintf(w, `{"id":%q,"transition":"start","status":"pending"}`, barrierNewBuildID)
					return
				}
				if !posted {
					writeBarrierWorkspace(t, w, barrierOldBuildID, "start", "running")
					return
				}
				writeBarrierWorkspace(t, w, barrierNewBuildID, "start", test.status)
			}))
			client.quotas["provider-id"] = oldQuota
			if test.timeout != 0 {
				client.startTimeout = test.timeout
			}
			if err := client.ApplyQuota(context.Background(), "provider-id", target); err == nil {
				t.Fatal("unconfirmed quota build was accepted")
			}
			client.mu.Lock()
			remembered := client.quotas["provider-id"]
			client.mu.Unlock()
			if remembered != oldQuota {
				t.Fatalf("unconfirmed quota replaced cache: %#v", remembered)
			}
		})
	}
}

func TestApplyQuotaRecoversAcceptedResponseLossWithoutDuplicateBuild(t *testing.T) {
	oldQuota := core.Quota{CPUMilli: 1000, MemoryMiB: 2048, DiskGiB: 8}
	target := core.Quota{CPUMilli: 500, MemoryMiB: 1536, DiskGiB: 8}
	started := false
	postCalls := 0
	client := newBarrierClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if started {
				writeBarrierWorkspace(t, w, barrierNewBuildID, "start", "running")
			} else {
				writeBarrierWorkspace(t, w, barrierOldBuildID, "start", "running")
			}
			return
		}
		postCalls++
		started = true
		connection, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Fatal(err)
		}
		_ = connection.Close()
	}))
	client.quotas["provider-id"] = oldQuota
	if err := client.ApplyQuota(context.Background(), "provider-id", target); err != nil {
		t.Fatal(err)
	}
	if err := client.ApplyQuota(context.Background(), "provider-id", target); err != nil {
		t.Fatal(err)
	}
	if postCalls != 1 {
		t.Fatalf("ambiguous quota build issued %d requests", postCalls)
	}
}

func TestProvisionLookupRecoveryDoesNotSeedUnconfirmedQuotaCache(t *testing.T) {
	target := core.Quota{CPUMilli: 1000, MemoryMiB: 2048, DiskGiB: 8}
	var applied atomic.Bool
	var postCalls atomic.Int32
	client := newBarrierClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			postCalls.Add(1)
			applied.Store(true)
			_, _ = fmt.Fprintf(w, `{"id":%q,"transition":"start","status":"pending"}`, barrierNewBuildID)
			return
		}
		buildID := barrierOldBuildID
		if applied.Load() {
			buildID = barrierNewBuildID
		}
		if len(r.URL.Path) >= len("/api/v2/users/") && r.URL.Path[:len("/api/v2/users/")] == "/api/v2/users/" {
			_, _ = fmt.Fprintf(w, `{"id":"provider-id","name":%q,"latest_build":{"id":%q,"transition":"start","status":"running"}}`, providerWorkspaceName("logical-workspace"), buildID)
			return
		}
		writeBarrierWorkspace(t, w, buildID, "start", "running")
	}))
	request := workspace.ProvisionRequest{
		WorkspaceID: "logical-workspace", Repository: core.Repository{ID: "repo"},
		Quota: target, SafetyMode: core.SafetyBalanced,
	}
	id, err := client.Provision(context.Background(), request)
	if err != nil || id != "provider-id" {
		t.Fatalf("lookup recovery = %q, %v", id, err)
	}
	if err := client.ApplyQuota(context.Background(), id, target); err != nil {
		t.Fatal(err)
	}
	if got := postCalls.Load(); got != 1 {
		t.Fatalf("lookup recovery emitted %d exact quota builds, want 1", got)
	}
}
