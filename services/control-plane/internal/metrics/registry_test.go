package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRegistryRendersBoundedMetadataOnlyMetrics(t *testing.T) {
	t.Parallel()
	registry := New()
	registry.RecordHTTP("listWorkspaces", http.StatusOK, 15*time.Millisecond)
	registry.RecordHTTP("listWorkspaces", http.StatusInternalServerError, 5*time.Millisecond)
	registry.RecordHTTP("workspace_id=secret\nforged_metric", http.StatusOK, time.Millisecond)
	registry.RecordCheckpoint(true)
	registry.RecordNotification(false)
	registry.SetWorkspaceCounts(3, 2)

	text := registry.Render()
	for _, expected := range []string{
		`operation="listWorkspaces",status_class="2xx"} 1`,
		`operation="listWorkspaces",status_class="5xx"} 1`,
		`operation="unknown",status_class="2xx"} 1`,
		"codex_mobile_checkpoint_success_total 1",
		"codex_mobile_notification_failure_total 1",
		"codex_mobile_running_workspaces 3",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("missing %q in metrics:\n%s", expected, text)
		}
	}
	if strings.Contains(text, "workspace_id=secret") || strings.Contains(text, "forged_metric") {
		t.Fatalf("unbounded label data reached metrics: %s", text)
	}
}

func TestMetricsHandlerIsGETOnlyAndNoStore(t *testing.T) {
	t.Parallel()
	registry := New()
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	response := httptest.NewRecorder()
	registry.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected metrics response: %d %#v", response.Code, response.Header())
	}

	request = httptest.NewRequest(http.MethodPost, "/metrics", nil)
	response = httptest.NewRecorder()
	registry.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("POST status = %d", response.Code)
	}
}
