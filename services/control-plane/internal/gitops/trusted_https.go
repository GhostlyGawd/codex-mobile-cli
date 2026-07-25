package gitops

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	gitclient "github.com/go-git/go-git/v5/plumbing/transport/client"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
)

const TrustedGitHubCABundlePath = "/opt/codex-mobile-helper/ca-certificates.crt"

var trustedHTTPSInstallation struct {
	sync.Once
	err error
}

// ConfigureTrustedHTTPSForURL installs the process-local HTTPS transport used
// by go-git. The workspace's proxy variables, trust store, Git config, and
// executable paths are attacker-controlled, so this transport connects
// directly and trusts only the root-owned read-only CA bundle mounted beside
// the workspace helper.
func ConfigureTrustedHTTPSForURL(remoteURL string) error {
	parsed, err := url.Parse(remoteURL)
	if err != nil {
		return errors.New("authenticated Git remote is invalid")
	}
	if parsed.Scheme != "https" {
		// File transports are used only by local unit tests. Production remotes
		// are constructed internally as exact GitHub HTTPS URLs.
		if parsed.Scheme == "" || parsed.Scheme == "file" {
			return nil
		}
		return errors.New("authenticated Git requires HTTPS")
	}
	if !strings.EqualFold(parsed.Hostname(), "github.com") || parsed.Port() != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("authenticated Git remote must be an exact GitHub HTTPS URL")
	}
	trustedHTTPSInstallation.Do(func() {
		trustedHTTPSInstallation.err = installTrustedHTTPS(TrustedGitHubCABundlePath)
	})
	return trustedHTTPSInstallation.err
}

func installTrustedHTTPS(caPath string) error {
	info, err := os.Lstat(caPath)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 4<<20 {
		return errors.New("trusted GitHub CA bundle is unavailable")
	}
	bundle, err := os.ReadFile(caPath)
	if err != nil {
		return errors.New("trusted GitHub CA bundle is unavailable")
	}
	defer clear(bundle)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(bundle) {
		return errors.New("trusted GitHub CA bundle is invalid")
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          8,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
		},
	}
	httpClient := &http.Client{
		Transport: transport,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 3 || request.URL.Scheme != "https" || !strings.EqualFold(request.URL.Hostname(), "github.com") || request.URL.Port() != "" {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	gitclient.InstallProtocol("https", githttp.NewClientWithOptions(httpClient, &githttp.ClientOptions{
		RedirectPolicy: githttp.FollowInitialRedirects,
	}))
	return nil
}
