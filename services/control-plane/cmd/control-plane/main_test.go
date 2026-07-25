package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWebsocketURLUsesPublicOriginAndFixedPath(t *testing.T) {
	t.Parallel()
	got, err := websocketURL("https://api.codex.example")
	if err != nil {
		t.Fatal(err)
	}
	if got != "wss://api.codex.example/v1/terminal" {
		t.Fatalf("websocket URL = %q", got)
	}
	if _, err := websocketURL("ftp://api.codex.example"); err == nil {
		t.Fatal("accepted a non-HTTP public origin")
	}
}

func TestHostRouterSeparatesAPIWebhookAndPreviewOrigins(t *testing.T) {
	t.Parallel()
	called := ""
	record := func(name string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			called = name
			w.WriteHeader(http.StatusNoContent)
		})
	}
	router := hostRouter{
		apiHost: "api.codex.example", previewDomain: "preview.codex.example", production: true,
		api: record("api"), preview: record("preview"), webhook: record("webhook"),
	}

	request := httptest.NewRequest(http.MethodGet, "https://api.codex.example/v1/workspaces", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if called != "api" || response.Code != http.StatusNoContent {
		t.Fatalf("API route dispatched to %q with status %d", called, response.Code)
	}

	called = ""
	request = httptest.NewRequest(http.MethodPost, "https://api.codex.example/v1/github/webhook", nil)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if called != "webhook" {
		t.Fatalf("webhook dispatched to %q", called)
	}

	called = ""
	request = httptest.NewRequest(http.MethodGet, "https://route-1.preview.codex.example/", nil)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if called != "preview" {
		t.Fatalf("preview dispatched to %q", called)
	}

	called = ""
	request = httptest.NewRequest(http.MethodGet, "https://attacker.example/healthz", nil)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if called != "" || response.Code != http.StatusNotFound {
		t.Fatalf("unknown production host reached %q with status %d", called, response.Code)
	}
}

func TestSafeErrorBoundsAndRemovesControls(t *testing.T) {
	t.Parallel()
	value := safeError(testError(strings.Repeat("x", 700) + "\r\nsecret"))
	if len(value) != 500 || strings.ContainsAny(value, "\r\n") {
		t.Fatalf("unsafe error output length=%d value=%q", len(value), value)
	}
}

type testError string

func (e testError) Error() string { return string(e) }
