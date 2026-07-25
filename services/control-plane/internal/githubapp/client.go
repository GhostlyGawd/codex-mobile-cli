package githubapp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
)

const (
	APIVersion = "2026-03-10"
	maxBody    = 4 * 1024 * 1024
)

type Client struct {
	appID      int64
	privateKey *rsa.PrivateKey
	baseURL    *url.URL
	http       *http.Client
	now        func() time.Time
}

type InstallationToken struct {
	Token       string
	ExpiresAt   time.Time
	Permissions map[string]string
}

type Installation struct {
	ID                  int64
	AccountID           int64
	AccountLogin        string
	AccountType         string
	RepositorySelection string
	Permissions         map[string]string
	CreatedAt           time.Time
	UpdatedAt           time.Time
	SuspendedAt         *time.Time
}

type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("GitHub API status %d: %s", e.Status, e.Message)
}

type PullRequest struct {
	Number int    `json:"number"`
	URL    string `json:"html_url"`
	State  string `json:"state"`
	Draft  bool   `json:"draft"`
}

func New(appID int64, privateKeyPEM []byte, httpClient *http.Client) (*Client, error) {
	if appID <= 0 {
		return nil, errors.New("GitHub App ID must be positive")
	}
	key, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return nil, err
	}
	base, _ := url.Parse("https://api.github.com/")
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 20 * time.Second}
	}
	return &Client{appID: appID, privateKey: key, baseURL: base, http: httpClient, now: func() time.Time { return time.Now().UTC() }}, nil
}

func (c *Client) AppJWT() (string, error) {
	now := c.now()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": strconv.FormatInt(c.appID, 10),
	})
	unsigned := encode(header) + "." + encode(claims)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, c.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign GitHub App JWT: %w", err)
	}
	return unsigned + "." + encode(signature), nil
}

func (c *Client) InstallationToken(ctx context.Context, installationID int64, repositoryIDs []int64, permissions map[string]string) (InstallationToken, error) {
	if installationID <= 0 || len(repositoryIDs) > 500 {
		return InstallationToken{}, errors.New("invalid GitHub installation token scope")
	}
	for name, level := range permissions {
		if name == "" || (level != "read" && level != "write") {
			return InstallationToken{}, errors.New("invalid GitHub App permission scope")
		}
	}
	body := struct {
		RepositoryIDs []int64           `json:"repository_ids,omitempty"`
		Permissions   map[string]string `json:"permissions,omitempty"`
	}{repositoryIDs, permissions}
	var response struct {
		Token       string            `json:"token"`
		ExpiresAt   time.Time         `json:"expires_at"`
		Permissions map[string]string `json:"permissions"`
	}
	if err := c.appRequest(ctx, http.MethodPost, fmt.Sprintf("app/installations/%d/access_tokens", installationID), body, &response); err != nil {
		return InstallationToken{}, err
	}
	if response.Token == "" || !response.ExpiresAt.After(c.now()) {
		return InstallationToken{}, errors.New("GitHub returned an invalid installation token")
	}
	return InstallationToken(response), nil
}

// RevokeInstallationToken invalidates exactly the installation access token
// used to authenticate the request. GitHub documents DELETE /installation/token
// as an immediate invalidation boundary. A 401 means the credential is already
// invalid and is therefore also a successful local revocation outcome.
func (c *Client) RevokeInstallationToken(ctx context.Context, token string) error {
	if token == "" || len(token) > 1024 || strings.ContainsAny(token, "\x00\r\n") {
		return errors.New("invalid GitHub installation token revocation")
	}
	err := c.tokenRequest(ctx, http.MethodDelete, "installation/token", token, nil, nil)
	var apiError *APIError
	if errors.As(err, &apiError) && apiError.Status == http.StatusUnauthorized {
		return nil
	}
	return err
}

func (c *Client) VerifyInstallationOwnership(ctx context.Context, userAccessToken string, installationID int64) error {
	if userAccessToken == "" || installationID <= 0 {
		return errors.New("user authorization and installation ID are required")
	}
	var response struct {
		ID          int64      `json:"id"`
		SuspendedAt *time.Time `json:"suspended_at"`
	}
	if err := c.tokenRequest(ctx, http.MethodGet, fmt.Sprintf("user/installations/%d", installationID), userAccessToken, nil, &response); err != nil {
		return err
	}
	if response.ID != installationID || response.SuspendedAt != nil {
		return errors.New("GitHub installation is unavailable or suspended")
	}
	return nil
}

func (c *Client) Installation(ctx context.Context, installationID int64) (Installation, error) {
	if installationID <= 0 {
		return Installation{}, errors.New("invalid GitHub installation ID")
	}
	var response struct {
		ID                  int64             `json:"id"`
		RepositorySelection string            `json:"repository_selection"`
		Permissions         map[string]string `json:"permissions"`
		CreatedAt           time.Time         `json:"created_at"`
		UpdatedAt           time.Time         `json:"updated_at"`
		SuspendedAt         *time.Time        `json:"suspended_at"`
		Account             struct {
			ID    int64  `json:"id"`
			Login string `json:"login"`
			Type  string `json:"type"`
		} `json:"account"`
	}
	if err := c.appRequest(ctx, http.MethodGet, fmt.Sprintf("app/installations/%d", installationID), nil, &response); err != nil {
		return Installation{}, err
	}
	if response.ID != installationID || response.Account.ID <= 0 || response.Account.Login == "" || response.SuspendedAt != nil {
		return Installation{}, errors.New("GitHub installation is unavailable or suspended")
	}
	return Installation{
		ID: response.ID, AccountID: response.Account.ID, AccountLogin: response.Account.Login,
		AccountType: response.Account.Type, RepositorySelection: response.RepositorySelection,
		Permissions: response.Permissions, CreatedAt: response.CreatedAt, UpdatedAt: response.UpdatedAt,
		SuspendedAt: response.SuspendedAt,
	}, nil
}

// RepositoryContent retrieves a bounded repository file without ever placing
// the installation token in a URL. A missing path is reported as exists=false.
func (c *Client) RepositoryContent(ctx context.Context, token, repository, path, ref string) ([]byte, bool, error) {
	if token == "" || !validRepository(repository) || !validContentPath(path) || ref == "" || len(ref) > 255 {
		return nil, false, errors.New("invalid GitHub repository content request")
	}
	escapedPath := strings.Join(mapPathSegments(path, url.PathEscape), "/")
	query := url.Values{"ref": []string{ref}}
	var response struct {
		Type     string `json:"type"`
		Encoding string `json:"encoding"`
		Content  string `json:"content"`
		Size     int64  `json:"size"`
	}
	err := c.tokenRequest(ctx, http.MethodGet, "repos/"+repository+"/contents/"+escapedPath+"?"+query.Encode(), token, nil, &response)
	var apiError *APIError
	if errors.As(err, &apiError) && apiError.Status == http.StatusNotFound {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if response.Type != "file" || response.Encoding != "base64" || response.Size < 0 || response.Size > 1<<20 {
		return nil, false, errors.New("GitHub repository content is not a supported file")
	}
	encoded := strings.ReplaceAll(response.Content, "\n", "")
	content, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || int64(len(content)) != response.Size {
		return nil, false, errors.New("GitHub repository content encoding is invalid")
	}
	return content, true, nil
}

func (c *Client) ListRepositories(ctx context.Context, token string, installationID int64) ([]core.Repository, error) {
	if token == "" || installationID <= 0 {
		return nil, errors.New("installation token and ID are required")
	}
	repositories := make([]core.Repository, 0)
	for page := 1; page <= 10; page++ {
		var response struct {
			Repositories []struct {
				ID            int64     `json:"id"`
				FullName      string    `json:"full_name"`
				DefaultBranch string    `json:"default_branch"`
				Private       bool      `json:"private"`
				UpdatedAt     time.Time `json:"updated_at"`
				Permissions   struct {
					Admin bool `json:"admin"`
					Push  bool `json:"push"`
					Pull  bool `json:"pull"`
				} `json:"permissions"`
				Owner struct {
					Type string `json:"type"`
				} `json:"owner"`
			} `json:"repositories"`
		}
		path := fmt.Sprintf("installation/repositories?per_page=100&page=%d", page)
		if err := c.tokenRequest(ctx, http.MethodGet, path, token, nil, &response); err != nil {
			return nil, err
		}
		for _, repo := range response.Repositories {
			permission := "read"
			if repo.Permissions.Admin {
				permission = "admin"
			} else if repo.Permissions.Push {
				permission = "write"
			}
			repositories = append(repositories, core.Repository{
				ID: strconv.FormatInt(repo.ID, 10), InstallationID: installationID,
				FullName: repo.FullName, DefaultBranch: repo.DefaultBranch, Private: repo.Private,
				Organization: repo.Owner.Type == "Organization", Permission: permission, UpdatedAt: repo.UpdatedAt,
			})
		}
		if len(response.Repositories) < 100 {
			break
		}
	}
	return repositories, nil
}

func (c *Client) CreatePullRequest(ctx context.Context, token, repository, title, body, head, base string, draft bool) (PullRequest, error) {
	if token == "" || !validRepository(repository) || strings.TrimSpace(title) == "" || head == "" || base == "" {
		return PullRequest{}, errors.New("invalid pull request input")
	}
	request := map[string]any{
		"title": title, "body": body, "head": head, "base": base,
		"draft": draft, "maintainer_can_modify": true,
	}
	var response PullRequest
	if err := c.tokenRequest(ctx, http.MethodPost, "repos/"+repository+"/pulls", token, request, &response); err != nil {
		return PullRequest{}, err
	}
	return response, nil
}

func (c *Client) appRequest(ctx context.Context, method, path string, input, output any) error {
	token, err := c.AppJWT()
	if err != nil {
		return err
	}
	return c.tokenRequest(ctx, method, path, token, input, output)
}

func (c *Client) tokenRequest(ctx context.Context, method, path, token string, input, output any) error {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	endpoint, err := c.baseURL.Parse(path)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", APIVersion)
	req.Header.Set("Authorization", "Bearer "+token)
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("GitHub request: %w", err)
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return err
	}
	if len(responseBody) > maxBody {
		return errors.New("GitHub response exceeds limit")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var problem struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(responseBody, &problem)
		return &APIError{Status: resp.StatusCode, Message: safeMessage(problem.Message)}
	}
	if output != nil && len(responseBody) > 0 {
		if err := json.Unmarshal(responseBody, output); err != nil {
			return fmt.Errorf("decode GitHub response: %w", err)
		}
	}
	return nil
}

func parsePrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("GitHub App private key is not PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("GitHub App private key is not PKCS#1 or PKCS#8 RSA")
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("GitHub App private key must be RSA")
	}
	return key, nil
}

func validRepository(value string) bool {
	parts := strings.Split(value, "/")
	return len(parts) == 2 && parts[0] != "" && parts[1] != "" && !strings.Contains(value, "..")
}

func validContentPath(value string) bool {
	if value == "" || len(value) > 1024 || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || strings.Contains(value, "\\") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." || strings.ContainsAny(segment, "\x00\r\n") {
			return false
		}
	}
	return true
}

func mapPathSegments(value string, fn func(string) string) []string {
	parts := strings.Split(value, "/")
	for i := range parts {
		parts[i] = fn(parts[i])
	}
	return parts
}

func encode(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }

func safeMessage(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 512 {
		value = value[:512]
	}
	return value
}
