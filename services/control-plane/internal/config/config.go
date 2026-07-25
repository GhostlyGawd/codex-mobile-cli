package config

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Lookup func(string) (string, bool)
type ReadFile func(string) ([]byte, error)

type Config struct {
	Environment              string
	HTTPAddr                 string
	PublicOrigin             string
	PasskeyRPID              string
	PasskeyOrigins           []string
	DatabaseURL              string
	MasterKey                []byte
	SessionPepper            []byte
	CoderURL                 string
	CoderToken               string
	CoderOrganizationID      string
	CoderOwnerID             string
	CoderTemplateID          string
	CodexAppServerEvents     bool
	GitHubEnabled            bool
	GitHubAppID              int64
	GitHubClientID           string
	GitHubClientSecret       string
	GitHubPrivateKey         []byte
	GitHubWebhookSecret      string
	APNSEnabled              bool
	APNSTeamID               string
	APNSSandboxKeyID         string
	APNSProductionKeyID      string
	APNSSandboxPrivateKey    []byte
	APNSProductionPrivateKey []byte
	IOSBundleID              string
	BaseDomain               string
	APIHost                  string
	PreviewDomain            string
	WorkspaceDiskProbePath   string
	CheckpointRoot           string
	CheckpointInterval       time.Duration
	CheckpointRetention      time.Duration
	CheckpointMaxBytes       int64
	CheckpointMaxCount       int
	LifecycleScanInterval    time.Duration
	LifecycleWarningLead     time.Duration
	MetricsAddr              string
	MaintenanceEnabled       bool
	MaintenanceWeekday       time.Weekday
	MaintenanceHourUTC       int
	MaintenanceWarningLead   time.Duration
	MaintenanceUrgentLead    time.Duration
	MaintenanceScanInterval  time.Duration
	AccessTTL                time.Duration
	RefreshTTL               time.Duration
	BootstrapTTL             time.Duration
	MaxRunning               int
}

func Load() (Config, error) {
	return load(os.LookupEnv, os.ReadFile)
}

func load(lookup Lookup, readFile ReadFile) (Config, error) {
	env := value(lookup, "APP_ENV", "development")
	production := env == "production"
	if env != "development" && !production {
		return Config{}, fmt.Errorf("APP_ENV must be development or production")
	}

	checkpointRoot := ".data/checkpoints"
	if production {
		checkpointRoot = "/checkpoints"
	}
	cfg := Config{
		Environment:             env,
		HTTPAddr:                value(lookup, "HTTP_ADDR", ":8080"),
		PublicOrigin:            value(lookup, "PUBLIC_ORIGIN", "http://localhost:8080"),
		PasskeyRPID:             value(lookup, "PASSKEY_RP_ID", "localhost"),
		PasskeyOrigins:          splitCSV(value(lookup, "PASSKEY_ORIGINS", "http://localhost:8080")),
		CoderURL:                value(lookup, "CODER_URL", "http://coder:7080"),
		CoderOrganizationID:     value(lookup, "CODER_ORGANIZATION_ID", "default"),
		CoderOwnerID:            value(lookup, "CODER_OWNER_ID", "me"),
		CoderTemplateID:         value(lookup, "CODER_TEMPLATE_ID", ""),
		BaseDomain:              value(lookup, "BASE_DOMAIN", ""),
		APIHost:                 value(lookup, "API_HOST", ""),
		PreviewDomain:           value(lookup, "PREVIEW_DOMAIN", ""),
		WorkspaceDiskProbePath:  value(lookup, "WORKSPACE_DISK_PROBE_PATH", "."),
		CheckpointRoot:          value(lookup, "CHECKPOINT_ROOT", checkpointRoot),
		CheckpointInterval:      15 * time.Minute,
		CheckpointRetention:     30 * 24 * time.Hour,
		CheckpointMaxBytes:      512 << 20,
		CheckpointMaxCount:      128,
		LifecycleScanInterval:   time.Minute,
		LifecycleWarningLead:    24 * time.Hour,
		MetricsAddr:             value(lookup, "METRICS_ADDR", "127.0.0.1:9090"),
		MaintenanceEnabled:      true,
		MaintenanceWeekday:      time.Sunday,
		MaintenanceHourUTC:      4,
		MaintenanceWarningLead:  24 * time.Hour,
		MaintenanceUrgentLead:   5 * time.Minute,
		MaintenanceScanInterval: time.Minute,
		IOSBundleID:             value(lookup, "IOS_BUNDLE_ID", ""),
		APNSTeamID:              value(lookup, "APNS_TEAM_ID", ""),
		APNSSandboxKeyID:        value(lookup, "APNS_KEY_ID_SANDBOX", ""),
		APNSProductionKeyID:     value(lookup, "APNS_KEY_ID_PRODUCTION", ""),
		GitHubClientID:          value(lookup, "GITHUB_CLIENT_ID", ""),
		AccessTTL:               15 * time.Minute,
		RefreshTTL:              30 * 24 * time.Hour,
		BootstrapTTL:            15 * time.Minute,
		MaxRunning:              10,
	}

	var err error
	if cfg.DatabaseURL, err = secret(lookup, readFile, "DATABASE_URL", "DATABASE_URL_FILE", production); err != nil {
		return Config{}, err
	}
	if cfg.CoderToken, err = secret(lookup, readFile, "CODER_TOKEN", "CODER_TOKEN_FILE", production); err != nil {
		return Config{}, err
	}
	if cfg.GitHubClientSecret, err = secret(lookup, readFile, "GITHUB_CLIENT_SECRET", "GITHUB_CLIENT_SECRET_FILE", production); err != nil {
		return Config{}, err
	}
	if cfg.GitHubWebhookSecret, err = secret(lookup, readFile, "GITHUB_WEBHOOK_SECRET", "GITHUB_WEBHOOK_SECRET_FILE", production); err != nil {
		return Config{}, err
	}
	if cfg.GitHubPrivateKey, err = secretBytes(lookup, readFile, "GITHUB_APP_PRIVATE_KEY", "GITHUB_APP_PRIVATE_KEY_FILE", production); err != nil {
		return Config{}, err
	}
	if cfg.APNSSandboxPrivateKey, err = secretBytes(lookup, readFile, "APNS_SANDBOX_PRIVATE_KEY", "APNS_SANDBOX_PRIVATE_KEY_FILE", production); err != nil {
		return Config{}, err
	}
	if cfg.APNSProductionPrivateKey, err = secretBytes(lookup, readFile, "APNS_PRODUCTION_PRIVATE_KEY", "APNS_PRODUCTION_PRIVATE_KEY_FILE", production); err != nil {
		return Config{}, err
	}
	if cfg.MasterKey, err = encodedSecret(lookup, readFile, "MASTER_KEY_B64", "MASTER_KEY_FILE", production); err != nil {
		return Config{}, err
	}
	if cfg.SessionPepper, err = encodedSecret(lookup, readFile, "SESSION_PEPPER_B64", "SESSION_PEPPER_FILE", production); err != nil {
		return Config{}, err
	}

	cfg.GitHubEnabled, err = boolValue(lookup, "GITHUB_ENABLED", production)
	if err != nil {
		return Config{}, err
	}
	cfg.APNSEnabled, err = boolValue(lookup, "APNS_ENABLED", production)
	if err != nil {
		return Config{}, err
	}
	cfg.CodexAppServerEvents, err = boolValue(lookup, "CODEX_APP_SERVER_EVENTS", false)
	if err != nil {
		return Config{}, err
	}
	cfg.MaintenanceEnabled, err = boolValue(lookup, "MAINTENANCE_ENABLED", true)
	if err != nil {
		return Config{}, err
	}
	if raw := value(lookup, "MAINTENANCE_WEEKDAY", "Sunday"); raw != "" {
		cfg.MaintenanceWeekday, err = parseWeekday(raw)
		if err != nil {
			return Config{}, err
		}
	}
	if raw := value(lookup, "MAINTENANCE_HOUR_UTC", ""); raw != "" {
		cfg.MaintenanceHourUTC, err = strconv.Atoi(raw)
		if err != nil {
			return Config{}, fmt.Errorf("MAINTENANCE_HOUR_UTC must be an integer")
		}
	}
	if raw := value(lookup, "MAINTENANCE_WARNING_LEAD", ""); raw != "" {
		cfg.MaintenanceWarningLead, err = time.ParseDuration(raw)
		if err != nil {
			return Config{}, fmt.Errorf("MAINTENANCE_WARNING_LEAD: %w", err)
		}
	}
	if raw := value(lookup, "MAINTENANCE_URGENT_WARNING_LEAD", ""); raw != "" {
		cfg.MaintenanceUrgentLead, err = time.ParseDuration(raw)
		if err != nil {
			return Config{}, fmt.Errorf("MAINTENANCE_URGENT_WARNING_LEAD: %w", err)
		}
	}
	if raw := value(lookup, "MAINTENANCE_SCAN_INTERVAL", ""); raw != "" {
		cfg.MaintenanceScanInterval, err = time.ParseDuration(raw)
		if err != nil {
			return Config{}, fmt.Errorf("MAINTENANCE_SCAN_INTERVAL: %w", err)
		}
	}
	if raw := value(lookup, "GITHUB_APP_ID", ""); raw != "" {
		cfg.GitHubAppID, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || cfg.GitHubAppID <= 0 {
			return Config{}, fmt.Errorf("GITHUB_APP_ID must be a positive integer")
		}
	}

	if raw := value(lookup, "ACCESS_TTL", ""); raw != "" {
		cfg.AccessTTL, err = time.ParseDuration(raw)
		if err != nil {
			return Config{}, fmt.Errorf("ACCESS_TTL: %w", err)
		}
	}
	if raw := value(lookup, "REFRESH_TTL", ""); raw != "" {
		cfg.RefreshTTL, err = time.ParseDuration(raw)
		if err != nil {
			return Config{}, fmt.Errorf("REFRESH_TTL: %w", err)
		}
	}
	if raw := value(lookup, "BOOTSTRAP_TTL", ""); raw != "" {
		cfg.BootstrapTTL, err = time.ParseDuration(raw)
		if err != nil {
			return Config{}, fmt.Errorf("BOOTSTRAP_TTL: %w", err)
		}
	}
	if raw := value(lookup, "MAX_RUNNING_WORKSPACES", ""); raw != "" {
		cfg.MaxRunning, err = strconv.Atoi(raw)
		if err != nil {
			return Config{}, fmt.Errorf("MAX_RUNNING_WORKSPACES must be an integer")
		}
	}
	if raw := value(lookup, "CHECKPOINT_INTERVAL", ""); raw != "" {
		cfg.CheckpointInterval, err = time.ParseDuration(raw)
		if err != nil {
			return Config{}, fmt.Errorf("CHECKPOINT_INTERVAL: %w", err)
		}
	}
	if raw := value(lookup, "CHECKPOINT_RETENTION", ""); raw != "" {
		cfg.CheckpointRetention, err = time.ParseDuration(raw)
		if err != nil {
			return Config{}, fmt.Errorf("CHECKPOINT_RETENTION: %w", err)
		}
	}
	if raw := value(lookup, "CHECKPOINT_MAX_WORKSPACE_BYTES", ""); raw != "" {
		cfg.CheckpointMaxBytes, err = strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return Config{}, fmt.Errorf("CHECKPOINT_MAX_WORKSPACE_BYTES must be an integer")
		}
	}
	if raw := value(lookup, "CHECKPOINT_MAX_COUNT", ""); raw != "" {
		cfg.CheckpointMaxCount, err = strconv.Atoi(raw)
		if err != nil {
			return Config{}, fmt.Errorf("CHECKPOINT_MAX_COUNT must be an integer")
		}
	}
	if raw := value(lookup, "LIFECYCLE_SCAN_INTERVAL", ""); raw != "" {
		cfg.LifecycleScanInterval, err = time.ParseDuration(raw)
		if err != nil {
			return Config{}, fmt.Errorf("LIFECYCLE_SCAN_INTERVAL: %w", err)
		}
	}
	if raw := value(lookup, "LIFECYCLE_WARNING_LEAD", ""); raw != "" {
		cfg.LifecycleWarningLead, err = time.ParseDuration(raw)
		if err != nil {
			return Config{}, fmt.Errorf("LIFECYCLE_WARNING_LEAD: %w", err)
		}
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if c.HTTPAddr == "" || c.MaxRunning < 1 || c.MaxRunning > 10 || strings.TrimSpace(c.WorkspaceDiskProbePath) == "" {
		return fmt.Errorf("invalid listener or workspace maximum")
	}
	if c.AccessTTL <= 0 || c.AccessTTL > time.Hour || c.RefreshTTL <= c.AccessTTL || c.BootstrapTTL <= 0 || c.BootstrapTTL > time.Hour {
		return fmt.Errorf("invalid session lifetimes")
	}
	if c.LifecycleScanInterval < time.Second || c.LifecycleScanInterval > time.Hour ||
		c.LifecycleWarningLead < time.Minute || c.LifecycleWarningLead > 30*24*time.Hour {
		return fmt.Errorf("invalid lifecycle scan interval or retention warning lead")
	}
	host, portText, err := net.SplitHostPort(c.MetricsAddr)
	port, portErr := strconv.Atoi(portText)
	if err != nil || portErr != nil || port < 1 || port > 65535 || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return fmt.Errorf("METRICS_ADDR must use a numeric loopback address and port")
	}
	if c.MaintenanceWeekday < time.Sunday || c.MaintenanceWeekday > time.Saturday ||
		c.MaintenanceHourUTC < 0 || c.MaintenanceHourUTC > 23 ||
		c.MaintenanceWarningLead < time.Hour || c.MaintenanceWarningLead > 6*24*time.Hour ||
		c.MaintenanceUrgentLead < time.Minute || c.MaintenanceUrgentLead > time.Hour ||
		c.MaintenanceScanInterval < time.Second || c.MaintenanceScanInterval > time.Hour {
		return fmt.Errorf("invalid maintenance schedule or timing")
	}
	if c.CheckpointRoot != "" {
		absoluteCheckpointRoot := filepath.IsAbs(c.CheckpointRoot) || path.IsAbs(filepath.ToSlash(c.CheckpointRoot))
		if strings.TrimSpace(c.CheckpointRoot) == "" || (c.Environment == "production" && !absoluteCheckpointRoot) ||
			c.CheckpointInterval < time.Minute || c.CheckpointInterval > 24*time.Hour ||
			c.CheckpointRetention < time.Hour || c.CheckpointRetention > 365*24*time.Hour ||
			c.CheckpointMaxBytes < 5<<20 || c.CheckpointMaxBytes > 100<<30 ||
			c.CheckpointMaxCount < 1 || c.CheckpointMaxCount > 10_000 {
			return fmt.Errorf("invalid checkpoint storage, interval, retention, or quota (root=%q interval=%s retention=%s bytes=%d count=%d)",
				c.CheckpointRoot, c.CheckpointInterval, c.CheckpointRetention, c.CheckpointMaxBytes, c.CheckpointMaxCount)
		}
	}
	origin, err := url.Parse(c.PublicOrigin)
	if err != nil || origin.Host == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" ||
		(origin.Scheme != "http" && origin.Scheme != "https") || (c.Environment == "production" && origin.Scheme != "https") {
		return fmt.Errorf("PUBLIC_ORIGIN must be an absolute %s URL", map[bool]string{true: "HTTPS", false: "HTTP(S)"}[c.Environment == "production"])
	}
	if c.PasskeyRPID == "" || len(c.PasskeyOrigins) == 0 {
		return fmt.Errorf("passkey RP ID and origins are required")
	}
	coderURL, err := url.Parse(c.CoderURL)
	if err != nil || coderURL.Scheme == "" || coderURL.Host == "" || coderURL.User != nil || coderURL.RawQuery != "" || coderURL.Fragment != "" {
		return fmt.Errorf("CODER_URL must be an absolute URL without credentials, query, or fragment")
	}
	for _, raw := range c.PasskeyOrigins {
		u, parseErr := url.Parse(raw)
		if parseErr != nil || u.Host == "" || (c.Environment == "production" && u.Scheme != "https") || u.Path != "" {
			return fmt.Errorf("invalid passkey origin %q", raw)
		}
	}
	if c.Environment == "production" {
		missing := make([]string, 0)
		for name, present := range map[string]bool{
			"DATABASE_URL_FILE":              len(c.DatabaseURL) > 0,
			"MASTER_KEY_FILE (32 bytes)":     len(c.MasterKey) == 32,
			"SESSION_PEPPER_FILE (32 bytes)": len(c.SessionPepper) == 32,
			"CODER_TOKEN_FILE":               len(c.CoderToken) > 0,
			"CODER_ORGANIZATION_ID":          c.CoderOrganizationID != "",
			"CODER_OWNER_ID":                 c.CoderOwnerID != "",
			"CODER_TEMPLATE_ID":              c.CoderTemplateID != "",
			"BASE_DOMAIN":                    c.BaseDomain != "" && !strings.Contains(c.BaseDomain, "example"),
			"API_HOST":                       c.APIHost != "" && !strings.Contains(c.APIHost, "example"),
			"PREVIEW_DOMAIN":                 c.PreviewDomain != "" && !strings.Contains(c.PreviewDomain, "example"),
			"WORKSPACE_DISK_PROBE_PATH":      c.WorkspaceDiskProbePath != "" && c.WorkspaceDiskProbePath != ".",
		} {
			if !present {
				missing = append(missing, name)
			}
		}
		if len(missing) > 0 {
			return fmt.Errorf("production configuration incomplete: %s", strings.Join(missing, ", "))
		}
	}
	if c.GitHubEnabled && (c.GitHubAppID <= 0 || c.GitHubClientID == "" || len(c.GitHubPrivateKey) == 0 || c.GitHubClientSecret == "") {
		return fmt.Errorf("GitHub is enabled but App ID, client ID, private key, or client secret is missing")
	}
	if c.APNSEnabled && (c.APNSTeamID == "" || c.IOSBundleID == "" || c.APNSProductionKeyID == "" || len(c.APNSProductionPrivateKey) == 0) {
		return fmt.Errorf("APNs is enabled but production Team ID, bundle ID, key ID, or private key is missing")
	}
	return nil
}

func value(lookup Lookup, name, fallback string) string {
	if v, ok := lookup(name); ok {
		return strings.TrimSpace(v)
	}
	return fallback
}

func boolValue(lookup Lookup, name string, fallback bool) (bool, error) {
	raw, ok := lookup(name)
	if !ok || strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	v, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		return false, fmt.Errorf("%s must be true or false", name)
	}
	return v, nil
}

func splitCSV(raw string) []string {
	out := make([]string, 0)
	for _, part := range strings.Split(raw, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func parseWeekday(raw string) (time.Weekday, error) {
	for day := time.Sunday; day <= time.Saturday; day++ {
		if strings.EqualFold(strings.TrimSpace(raw), day.String()) {
			return day, nil
		}
	}
	return time.Sunday, fmt.Errorf("MAINTENANCE_WEEKDAY must be Sunday through Saturday")
}

func secret(lookup Lookup, readFile ReadFile, directName, fileName string, requireFile bool) (string, error) {
	b, err := secretBytes(lookup, readFile, directName, fileName, requireFile)
	return strings.TrimSpace(string(b)), err
}

func secretBytes(lookup Lookup, readFile ReadFile, directName, fileName string, requireFile bool) ([]byte, error) {
	direct, directOK := lookup(directName)
	path, fileOK := lookup(fileName)
	direct = strings.TrimSpace(direct)
	path = strings.TrimSpace(path)
	if direct != "" && path != "" {
		return nil, fmt.Errorf("set exactly one of %s and %s", directName, fileName)
	}
	if requireFile && direct != "" {
		return nil, fmt.Errorf("%s is not allowed in production; use %s", directName, fileName)
	}
	if path != "" {
		b, err := readFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", fileName, err)
		}
		return bytesTrimSpace(b), nil
	}
	if directOK && direct != "" {
		return []byte(direct), nil
	}
	if fileOK && path == "" {
		return nil, fmt.Errorf("%s is empty", fileName)
	}
	return nil, nil
}

func encodedSecret(lookup Lookup, readFile ReadFile, directName, fileName string, requireFile bool) ([]byte, error) {
	b, err := secretBytes(lookup, readFile, directName, fileName, requireFile)
	if err != nil || len(b) == 0 {
		return b, err
	}
	if len(b) != 32 {
		if decoded, decodeErr := base64.StdEncoding.DecodeString(string(b)); decodeErr == nil {
			b = decoded
		}
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("%s/%s must contain exactly 32 raw bytes or their base64 encoding", directName, fileName)
	}
	return b, nil
}

func bytesTrimSpace(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}
