package preview

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
)

const (
	SessionPath = "/__codex_mobile/session"
	CookieName  = "__Host-codex_mobile_preview"
)

type RouteResolver func(context.Context, string) (Route, error)

type Tunnel interface {
	Target(context.Context, string, uint16) (*url.URL, error)
}

type Gateway struct {
	domain  string
	tokens  *TokenManager
	resolve RouteResolver
	tunnel  Tunnel
}

func NewGateway(domain string, tokens *TokenManager, resolve RouteResolver, tunnel Tunnel) (*Gateway, error) {
	domain = strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))
	if domain == "" || strings.ContainsAny(domain, "/:\\\r\n\x00") || tokens == nil || resolve == nil || tunnel == nil {
		return nil, errors.New("preview domain, tokens, resolver, and tunnel are required")
	}
	return &Gateway{domain: domain, tokens: tokens, resolve: resolve, tunnel: tunnel}, nil
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	routeID, ok := g.routeID(r.Host)
	if !ok {
		http.NotFound(w, r)
		return
	}
	route, err := g.resolve(r.Context(), routeID)
	if err != nil || route.ID != routeID || route.RevokedAt != nil {
		http.NotFound(w, r)
		return
	}
	if r.URL.Path == SessionPath {
		g.establishSession(w, r, route)
		return
	}
	cookie, err := r.Cookie(CookieName)
	if err != nil {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			g.bootstrap(w, r)
			return
		}
		http.Error(w, "preview authorization required", http.StatusUnauthorized)
		return
	}
	authorizedContext, release, err := g.tokens.Authorize(
		r.Context(), cookie.Value, route.ID, route.OwnerID, route.WorkspaceID, route.Port,
	)
	if err != nil {
		if errors.Is(err, core.ErrCapacity) {
			http.Error(w, "preview capacity is temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			g.bootstrap(w, r)
			return
		}
		http.Error(w, "preview authorization required", http.StatusUnauthorized)
		return
	}
	defer release()
	r = r.WithContext(authorizedContext)
	if !samePreviewOrigin(r, isWebSocketRequest(r) || !safePreviewMethod(r.Method)) {
		http.Error(w, "preview origin rejected", http.StatusForbidden)
		return
	}
	if route.Host == "" {
		http.Error(w, "preview provider is unavailable", http.StatusBadGateway)
		return
	}
	target, err := g.tunnel.Target(r.Context(), route.Host, route.Port)
	if err != nil {
		http.Error(w, "preview is temporarily unavailable", http.StatusBadGateway)
		return
	}
	g.proxy(target).ServeHTTP(w, r)
}

func (g *Gateway) routeID(rawHost string) (string, bool) {
	host := strings.ToLower(rawHost)
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	}
	suffix := "." + g.domain
	if !strings.HasSuffix(host, suffix) {
		return "", false
	}
	id := strings.TrimSuffix(host, suffix)
	return id, previewIDPattern.MatchString(id)
}

func (g *Gateway) establishSession(w http.ResponseWriter, r *http.Request, route Route) {
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "invalid preview session request", http.StatusBadRequest)
		return
	}
	if !samePreviewOrigin(r, true) {
		http.Error(w, "preview origin rejected", http.StatusForbidden)
		return
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512))
	decoder.DisallowUnknownFields()
	var input struct {
		Token string `json:"token"`
	}
	if err := decoder.Decode(&input); err != nil || input.Token == "" {
		http.Error(w, "invalid preview session request", http.StatusBadRequest)
		return
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		http.Error(w, "invalid preview session request", http.StatusBadRequest)
		return
	}
	if err := g.tokens.Validate(input.Token, route.ID, route.OwnerID, route.WorkspaceID, route.Port); err != nil {
		http.Error(w, "invalid preview authorization", http.StatusUnauthorized)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: input.Token, Path: "/", MaxAge: 600,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func samePreviewOrigin(r *http.Request, requireOrigin bool) bool {
	expected := "https://" + strings.ToLower(strings.TrimSpace(r.Host))
	origin := strings.TrimRight(strings.TrimSpace(r.Header.Get("Origin")), "/")
	if origin != "" {
		return origin == expected
	}
	if requireOrigin {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))) {
	case "", "none", "same-origin":
		return true
	default:
		return false
	}
}

func isWebSocketRequest(r *http.Request) bool {
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket")
}

func safePreviewMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

func (g *Gateway) bootstrap(w http.ResponseWriter, r *http.Request) {
	nonceBytes := make([]byte, 18)
	if _, err := rand.Read(nonceBytes); err != nil {
		http.Error(w, "preview bootstrap unavailable", http.StatusInternalServerError)
		return
	}
	nonce := base64.RawStdEncoding.EncodeToString(nonceBytes)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_, _ = fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><title>Opening preview</title><p>Opening private preview…</p><script nonce="%s">(async()=>{const t=location.hash.slice(1);if(!t){document.body.textContent='Preview link is missing authorization.';return}const d=location.pathname+location.search;history.replaceState(null,'',d);const r=await fetch('%s',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:t})});if(r.ok)location.replace(d);else document.body.textContent='Preview link expired. Return to Codex Mobile and open it again.'})()</script>`, nonce, SessionPath)
}

func (g *Gateway) proxy(target *url.URL) http.Handler {
	proxy := &httputil.ReverseProxy{
		Rewrite: func(request *httputil.ProxyRequest) {
			request.SetURL(target)
			request.Out.Host = target.Host
			for _, name := range []string{
				"Authorization", "Proxy-Authorization", "Cookie", "Coder-Session-Token",
				"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
				"X-Real-Ip", "X-Codex-Mobile-Preview",
			} {
				request.Out.Header.Del(name)
			}
		},
		ModifyResponse: func(response *http.Response) error {
			cookies := response.Header.Values("Set-Cookie")
			response.Header.Del("Set-Cookie")
			for _, cookie := range cookies {
				if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(cookie)), strings.ToLower(CookieName)+"=") {
					response.Header.Add("Set-Cookie", cookie)
				}
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "preview upstream unavailable", http.StatusBadGateway)
		},
	}
	return proxy
}

var previewIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
