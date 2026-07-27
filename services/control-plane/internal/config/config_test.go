package config

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func env(values map[string]string) Lookup {
	return func(k string) (string, bool) { v, ok := values[k]; return v, ok }
}

func files(values map[string][]byte) ReadFile {
	return func(path string) ([]byte, error) { return values[path], nil }
}

func TestDevelopmentDefaults(t *testing.T) {
	t.Parallel()
	cfg, err := load(env(map[string]string{}), files(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTPAddr != ":8080" || cfg.GitHubEnabled || cfg.APNSEnabled ||
		cfg.MaxRunning != 10 || cfg.DeploymentProfile != "development" {
		t.Fatalf("unexpected development defaults: %#v", cfg)
	}
}

func TestProductionRejectsDirectSecret(t *testing.T) {
	t.Parallel()
	_, err := load(env(map[string]string{
		"APP_ENV":      "production",
		"DATABASE_URL": "postgres://direct",
	}), files(nil))
	if err == nil || !strings.Contains(err.Error(), "not allowed in production") {
		t.Fatalf("expected direct-secret rejection, got %v", err)
	}
}

func TestProductionRequiresCompleteFailClosedConfig(t *testing.T) {
	t.Parallel()
	key := []byte("0123456789abcdef0123456789abcdef")
	vals := map[string]string{
		"APP_ENV":                   "production",
		"DEPLOYMENT_PROFILE":        "owner_pc_beta",
		"MAX_RUNNING_WORKSPACES":    "1",
		"PUBLIC_ORIGIN":             "https://api.codex.test",
		"PASSKEY_RP_ID":             "api.codex.test",
		"PASSKEY_ORIGINS":           "https://api.codex.test",
		"DATABASE_URL_FILE":         "/db",
		"MASTER_KEY_FILE":           "/master",
		"SESSION_PEPPER_FILE":       "/pepper",
		"CODER_TOKEN_FILE":          "/coder",
		"CODER_ORGANIZATION_ID":     "organization-id",
		"CODER_OWNER_ID":            "me",
		"CODER_TEMPLATE_ID":         "template-id",
		"BASE_DOMAIN":               "codex.test",
		"API_HOST":                  "api.codex.test",
		"PREVIEW_DOMAIN":            "preview.codex.test",
		"WORKSPACE_DISK_PROBE_PATH": "/workspace-disk-probe",
		"GITHUB_ENABLED":            "false",
		"APNS_ENABLED":              "false",
	}
	cfg, err := load(env(vals), files(map[string][]byte{
		"/db":     []byte("postgres://private"),
		"/master": []byte(base64.StdEncoding.EncodeToString(key)),
		"/pepper": key,
		"/coder":  []byte("token"),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.MasterKey) != 32 || len(cfg.SessionPepper) != 32 {
		t.Fatal("keys were not decoded")
	}
}

func TestProductionDeploymentProfileIsFailClosed(t *testing.T) {
	t.Parallel()
	base := Config{
		Environment:             "production",
		DeploymentProfile:       "owner_pc_beta",
		HTTPAddr:                ":8080",
		PublicOrigin:            "https://api.codex.test",
		PasskeyRPID:             "codex.test",
		PasskeyOrigins:          []string{"https://api.codex.test"},
		CoderURL:                "http://coder:7080",
		WorkspaceDiskProbePath:  "/workspace-disk-probe",
		AccessTTL:               15 * time.Minute,
		RefreshTTL:              24 * time.Hour,
		BootstrapTTL:            15 * time.Minute,
		LifecycleScanInterval:   time.Minute,
		LifecycleWarningLead:    time.Hour,
		MetricsAddr:             "127.0.0.1:9090",
		MaintenanceWeekday:      time.Sunday,
		MaintenanceWarningLead:  time.Hour,
		MaintenanceUrgentLead:   5 * time.Minute,
		MaintenanceScanInterval: time.Minute,
		MaxRunning:              1,
	}
	for _, change := range []func(*Config){
		func(c *Config) { c.DeploymentProfile = "fixed_price_vps" },
		func(c *Config) { c.DeploymentProfile = "development" },
		func(c *Config) { c.DeploymentProfile = "unknown" },
		func(c *Config) { c.MaxRunning = 2 },
	} {
		candidate := base
		change(&candidate)
		if err := candidate.Validate(); err == nil {
			t.Fatalf("accepted unsafe production profile: %#v", candidate)
		}
	}
}

func TestPasskeyOriginRejectsPath(t *testing.T) {
	t.Parallel()
	cfg := Config{
		Environment: "development", HTTPAddr: ":8080", PublicOrigin: "http://localhost:8080",
		PasskeyRPID: "localhost", PasskeyOrigins: []string{"http://localhost:8080/path"},
		AccessTTL: 1, RefreshTTL: 2, MaxRunning: 10,
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid origin path")
	}
}

func TestPublicOriginRejectsAmbientURLComponents(t *testing.T) {
	t.Parallel()
	for _, origin := range []string{
		"https://user@example.test", "https://example.test/path",
		"https://example.test?query=1", "https://example.test/#fragment", "ftp://example.test",
	} {
		cfg := Config{
			Environment: "development", HTTPAddr: ":8080", PublicOrigin: origin,
			PasskeyRPID: "example.test", PasskeyOrigins: []string{"https://example.test"},
			WorkspaceDiskProbePath: ".", AccessTTL: 15, RefreshTTL: 30, BootstrapTTL: 15,
			MaxRunning: 10,
		}
		if err := cfg.Validate(); err == nil {
			t.Fatalf("accepted public origin %q", origin)
		}
	}
}
