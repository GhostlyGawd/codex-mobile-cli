package apns

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	SandboxURL    = "https://api.sandbox.push.apple.com"
	ProductionURL = "https://api.push.apple.com"
	maxResponse   = 64 << 10
)

var ErrUnregistered = errors.New("APNs device is unregistered")

type Environment string

const (
	Sandbox    Environment = "sandbox"
	Production Environment = "production"
)

type DeliveryError struct {
	Status     int
	Reason     string
	RetryAfter time.Duration
}

func (e *DeliveryError) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("APNs rejected notification: status=%d reason=%s retry_after=%s", e.Status, e.Reason, e.RetryAfter)
	}
	return fmt.Sprintf("APNs rejected notification: status=%d reason=%s", e.Status, e.Reason)
}

type Key struct {
	ID         string
	PrivateKey *ecdsa.PrivateKey
}

type Config struct {
	TeamID        string
	BundleID      string
	SandboxKey    Key
	ProductionKey Key
	SandboxURL    string
	ProductionURL string
	HTTPClient    *http.Client
	Now           func() time.Time
}

type Notification struct {
	Kind       string
	ActivityID string
	DeepLink   string
	Title      string
}

type Client struct {
	teamID, bundleID string
	sandboxKey       Key
	productionKey    Key
	sandboxURL       *url.URL
	productionURL    *url.URL
	http             *http.Client
	now              func() time.Time
	mu               sync.Mutex
	tokens           map[Environment]cachedToken
}

type cachedToken struct {
	value     string
	createdAt time.Time
}

func New(cfg Config) (*Client, error) {
	if cfg.TeamID == "" || cfg.BundleID == "" || cfg.ProductionKey.ID == "" || cfg.ProductionKey.PrivateKey == nil {
		return nil, errors.New("APNs team, bundle, and production signing key are required")
	}
	if cfg.SandboxURL == "" {
		cfg.SandboxURL = SandboxURL
	}
	if cfg.ProductionURL == "" {
		cfg.ProductionURL = ProductionURL
	}
	sandboxURL, err := parseBaseURL(cfg.SandboxURL)
	if err != nil {
		return nil, fmt.Errorf("sandbox URL: %w", err)
	}
	productionURL, err := parseBaseURL(cfg.ProductionURL)
	if err != nil {
		return nil, fmt.Errorf("production URL: %w", err)
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Client{
		teamID: cfg.TeamID, bundleID: cfg.BundleID,
		sandboxKey: cfg.SandboxKey, productionKey: cfg.ProductionKey,
		sandboxURL: sandboxURL, productionURL: productionURL,
		http: cfg.HTTPClient, now: cfg.Now, tokens: make(map[Environment]cachedToken),
	}, nil
}

func ParsePrivateKey(data []byte) (*ecdsa.PrivateKey, error) {
	block, rest := pem.Decode(data)
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("APNs key must be one PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse APNs PKCS#8 key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve.Params().Name != "P-256" {
		return nil, errors.New("APNs key must be an EC P-256 private key")
	}
	return key, nil
}

func (c *Client) Send(ctx context.Context, environment Environment, deviceToken string, notification Notification) error {
	if err := validateDeviceToken(deviceToken); err != nil {
		return err
	}
	if notification.ActivityID == "" || len(notification.ActivityID) > 128 || len(notification.DeepLink) > 1000 {
		return errors.New("notification activity ID is required and fields must be bounded")
	}
	key, base, err := c.destination(environment)
	if err != nil {
		return err
	}
	auth, err := c.providerToken(environment, key)
	if err != nil {
		return err
	}
	title := "Codex Mobile"
	if notification.Title != "" {
		title = notification.Title
	}
	body, err := json.Marshal(map[string]any{
		"aps": map[string]any{
			"alert": map[string]string{"title": title, "body": genericBody(notification.Kind)},
			"sound": "default", "thread-id": "codex-mobile-activity",
		},
		"activity_id": notification.ActivityID,
		"deep_link":   notification.DeepLink,
	})
	if err != nil {
		return err
	}
	endpoint := *base
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/3/device/" + strings.ToLower(deviceToken)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("authorization", "bearer "+auth)
	req.Header.Set("apns-topic", c.bundleID)
	req.Header.Set("apns-push-type", "alert")
	req.Header.Set("apns-priority", "10")
	req.Header.Set("content-type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("deliver APNs notification: %w", err)
	}
	defer resp.Body.Close()
	limited, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if readErr != nil {
		return fmt.Errorf("read APNs response: %w", readErr)
	}
	if len(limited) > maxResponse {
		return errors.New("APNs response exceeded size limit")
	}
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	var response struct {
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(limited, &response)
	if resp.StatusCode == http.StatusGone || response.Reason == "Unregistered" {
		return fmt.Errorf("%w: %s", ErrUnregistered, response.Reason)
	}
	return &DeliveryError{Status: resp.StatusCode, Reason: response.Reason, RetryAfter: parseRetryAfter(resp.Header.Get("retry-after"), c.now())}
}

func (c *Client) destination(environment Environment) (Key, *url.URL, error) {
	switch environment {
	case Production:
		return c.productionKey, c.productionURL, nil
	case Sandbox:
		if c.sandboxKey.ID == "" || c.sandboxKey.PrivateKey == nil {
			return Key{}, nil, errors.New("sandbox APNs key is not configured")
		}
		return c.sandboxKey, c.sandboxURL, nil
	default:
		return Key{}, nil, errors.New("invalid APNs environment")
	}
}

func (c *Client) providerToken(environment Environment, key Key) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if cached := c.tokens[environment]; cached.value != "" && now.Sub(cached.createdAt) < 50*time.Minute && now.Sub(cached.createdAt) >= 0 {
		return cached.value, nil
	}
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": key.ID})
	claims, _ := json.Marshal(map[string]any{"iss": c.teamID, "iat": now.Unix()})
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(unsigned))
	r, s, err := ecdsa.Sign(rand.Reader, key.PrivateKey, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign APNs provider token: %w", err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	token := unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
	c.tokens[environment] = cachedToken{value: token, createdAt: now}
	return token, nil
}

func parseBaseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("must be an absolute HTTP(S) URL without credentials, query, or fragment")
	}
	return u, nil
}

func validateDeviceToken(token string) error {
	if len(token) < 64 || len(token) > 200 || len(token)%2 != 0 {
		return errors.New("invalid APNs device token")
	}
	if _, err := hex.DecodeString(token); err != nil {
		return errors.New("invalid APNs device token")
	}
	return nil
}

func genericBody(kind string) string {
	switch kind {
	case "completion":
		return "A session completed."
	case "failure":
		return "A session failed."
	default:
		return "A session needs attention."
	}
}

func parseRetryAfter(value string, now time.Time) time.Duration {
	if seconds, err := strconv.Atoi(value); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	if at, err := http.ParseTime(value); err == nil && at.After(now) {
		return at.Sub(now)
	}
	return 0
}
