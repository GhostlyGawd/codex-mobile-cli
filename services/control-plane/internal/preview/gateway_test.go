package preview

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

type testTunnel struct{ target *url.URL }

func (t testTunnel) Target(context.Context, string, uint16) (*url.URL, error) { return t.target, nil }

func TestGatewayExchangesFragmentTokenAndStripsCredentials(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Fatal("gateway credential reached preview upstream")
		}
		_, _ = io.WriteString(w, "upstream")
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	tokens, _ := NewTokenManager([]byte(strings.Repeat("p", 32)))
	route := Route{ID: "preview_abc", OwnerID: "owner", WorkspaceID: "workspace", Port: 3000, Host: "123e4567-e89b-12d3-a456-426614174000"}
	token, _, err := tokens.Issue(route, "device", 0)
	if err == nil {
		t.Fatal("zero preview TTL accepted")
	}
	token, _, err = tokens.Issue(route, "device", 10*60*1e9)
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := NewGateway("preview.example.test", tokens, func(context.Context, string) (Route, error) {
		return route, nil
	}, testTunnel{target})
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "https://preview_abc.preview.example.test/", nil)
	request.Host = "preview_abc.preview.example.test"
	gateway.ServeHTTP(bootstrap, request)
	if bootstrap.Code != http.StatusOK || !strings.Contains(bootstrap.Body.String(), "location.hash") {
		t.Fatalf("bootstrap = %d: %s", bootstrap.Code, bootstrap.Body.String())
	}
	session := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "https://preview_abc.preview.example.test"+SessionPath, strings.NewReader(`{"token":"`+token+`"}`))
	request.Host = "preview_abc.preview.example.test"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://preview_abc.preview.example.test")
	gateway.ServeHTTP(session, request)
	if session.Code != http.StatusNoContent || len(session.Result().Cookies()) != 1 {
		t.Fatalf("session = %d: %s", session.Code, session.Body.String())
	}
	for name, mutate := range map[string]func(*http.Request){
		"cross-origin": func(request *http.Request) {
			request.Header.Set("Origin", "https://attacker.preview.example.test")
		},
		"same-site-fetch": func(request *http.Request) {
			request.Header.Set("Sec-Fetch-Site", "same-site")
		},
		"cross-origin-websocket": func(request *http.Request) {
			request.Header.Set("Origin", "https://attacker.preview.example.test")
			request.Header.Set("Upgrade", "websocket")
		},
	} {
		t.Run(name, func(t *testing.T) {
			blocked := httptest.NewRecorder()
			blockedRequest := httptest.NewRequest(http.MethodGet, "https://preview_abc.preview.example.test/private", nil)
			blockedRequest.Host = "preview_abc.preview.example.test"
			blockedRequest.AddCookie(session.Result().Cookies()[0])
			mutate(blockedRequest)
			gateway.ServeHTTP(blocked, blockedRequest)
			if blocked.Code != http.StatusForbidden {
				t.Fatalf("cross-origin authenticated preview = %d: %s", blocked.Code, blocked.Body.String())
			}
		})
	}
	proxied := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "https://preview_abc.preview.example.test/path", nil)
	request.Host = "preview_abc.preview.example.test"
	request.Header.Set("Authorization", "Bearer must-not-forward")
	request.AddCookie(session.Result().Cookies()[0])
	gateway.ServeHTTP(proxied, request)
	if proxied.Code != http.StatusOK || proxied.Body.String() != "upstream" {
		t.Fatalf("proxied = %d: %s", proxied.Code, proxied.Body.String())
	}
}

func TestGatewayRequiresExactOriginForSessionExchange(t *testing.T) {
	tokens, _ := NewTokenManager([]byte(strings.Repeat("p", 32)))
	route := Route{ID: "preview_abc", OwnerID: "owner", WorkspaceID: "workspace", Port: 3000, Host: "workspace"}
	token, _, err := tokens.Issue(route, "device", 10*60*1e9)
	if err != nil {
		t.Fatal(err)
	}
	target, _ := url.Parse("http://127.0.0.1:3000")
	gateway, err := NewGateway("preview.example.test", tokens, func(context.Context, string) (Route, error) {
		return route, nil
	}, testTunnel{target})
	if err != nil {
		t.Fatal(err)
	}
	for _, origin := range []string{"", "https://attacker.preview.example.test"} {
		request := httptest.NewRequest(http.MethodPost, "https://preview_abc.preview.example.test"+SessionPath, strings.NewReader(`{"token":"`+token+`"}`))
		request.Host = "preview_abc.preview.example.test"
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", origin)
		response := httptest.NewRecorder()
		gateway.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Fatalf("session origin %q returned %d", origin, response.Code)
		}
	}
}

func TestGatewayMapsActiveAuthorizationCapacityToServiceUnavailable(t *testing.T) {
	tokens, _ := NewTokenManager([]byte(strings.Repeat("p", 32)))
	tokens.maxActive = 1
	tokens.maxOwnerActive = 1
	tokens.maxRouteActive = 1
	route := Route{ID: "preview_capacity", OwnerID: "owner", WorkspaceID: "workspace", Port: 3000, Host: "workspace"}
	token, _, err := tokens.Issue(route, "device", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, release, err := tokens.Authorize(context.Background(), token, route.ID, route.OwnerID, route.WorkspaceID, route.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	target, _ := url.Parse("http://127.0.0.1:3000")
	gateway, err := NewGateway("preview.example.test", tokens, func(context.Context, string) (Route, error) {
		return route, nil
	}, testTunnel{target})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://preview_capacity.preview.example.test/", nil)
	request.Host = "preview_capacity.preview.example.test"
	request.AddCookie(&http.Cookie{Name: CookieName, Value: token})
	response := httptest.NewRecorder()
	gateway.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("preview capacity status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
}

func TestGatewayRevocationTerminatesActiveStream(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
		close(canceled)
	}))
	defer upstream.Close()
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := NewTokenManager([]byte(strings.Repeat("p", 32)))
	if err != nil {
		t.Fatal(err)
	}
	route := Route{ID: "preview_stream", OwnerID: "owner", WorkspaceID: "workspace", Port: 3000, Host: "workspace"}
	token, _, err := tokens.Issue(route, "device", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := NewGateway("preview.example.test", tokens, func(context.Context, string) (Route, error) {
		return route, nil
	}, testTunnel{target})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gateway)
	defer server.Close()

	request, err := http.NewRequest(http.MethodGet, server.URL+"/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = route.ID + ".preview.example.test"
	request.AddCookie(&http.Cookie{Name: CookieName, Value: token})
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("preview stream did not reach upstream")
	}
	if count := tokens.RevokeRoute(route.ID); count != 1 {
		t.Fatalf("revoked %d grants", count)
	}
	select {
	case <-canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream stream remained active after route revocation")
	}
}

func TestGatewayRevocationTerminatesActiveWebSocket(t *testing.T) {
	started := make(chan struct{})
	disconnected := make(chan struct{})
	upstreamErrors := make(chan error, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		socket, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			upstreamErrors <- err
			return
		}
		defer socket.CloseNow()
		close(started)
		_, _, _ = socket.Read(context.Background())
		close(disconnected)
	}))
	defer upstream.Close()
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := NewTokenManager([]byte(strings.Repeat("p", 32)))
	if err != nil {
		t.Fatal(err)
	}
	route := Route{ID: "preview_socket", OwnerID: "owner", WorkspaceID: "workspace", Port: 3000, Host: "workspace"}
	token, _, err := tokens.Issue(route, "device", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := NewGateway("preview.example.test", tokens, func(context.Context, string) (Route, error) {
		return route, nil
	}, testTunnel{target})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gateway)
	defer server.Close()

	dialer := &net.Dialer{}
	transport := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, server.Listener.Addr().String())
	}}
	defer transport.CloseIdleConnections()
	host := route.ID + ".preview.example.test"
	socket, _, err := websocket.Dial(context.Background(), "ws://"+host+"/socket", &websocket.DialOptions{
		HTTPClient: &http.Client{Transport: transport},
		HTTPHeader: http.Header{
			"Cookie": {CookieName + "=" + token},
			"Origin": {"https://" + host},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.CloseNow()
	select {
	case <-started:
	case err := <-upstreamErrors:
		t.Fatalf("accept upstream WebSocket: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("preview WebSocket did not reach upstream")
	}
	if count := tokens.RevokeRoute(route.ID); count != 1 {
		t.Fatalf("revoked %d grants", count)
	}
	select {
	case <-disconnected:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream WebSocket remained active after route revocation")
	}
	readContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, _, err := socket.Read(readContext); err == nil {
		t.Fatal("client WebSocket remained active after route revocation")
	}
}
