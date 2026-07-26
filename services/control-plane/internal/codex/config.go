package codex

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
)

const PinnedVersion = "0.145.0"

type RuntimeConfig struct {
	SafetyMode   core.SafetyMode
	Network      bool
	WritableRoot string
	EventMode    string
}

func RenderConfig(cfg RuntimeConfig) (string, error) {
	if !cfg.SafetyMode.Valid() {
		return "", errors.New("invalid Codex safety mode")
	}
	if cfg.WritableRoot == "" || !filepath.IsAbs(cfg.WritableRoot) || strings.ContainsAny(cfg.WritableRoot, "\r\n\x00") {
		return "", errors.New("Codex writable root must be an absolute clean path")
	}
	sandbox := "workspace-write"
	approval := "on-request"
	if cfg.SafetyMode == core.SafetySafe {
		sandbox = "read-only"
	}
	if cfg.SafetyMode == core.SafetyFullAccess {
		sandbox = "danger-full-access"
		approval = "never"
	}
	root := strings.ReplaceAll(filepath.ToSlash(cfg.WritableRoot), `"`, `\"`)
	var out strings.Builder
	fmt.Fprintf(&out, "# Managed by Codex Mobile for Codex CLI %s.\n", PinnedVersion)
	fmt.Fprintf(&out, "sandbox_mode = %q\napproval_policy = %q\n", sandbox, approval)
	// The trusted workspace launcher encrypts Codex's file-backed auth state
	// whenever no Codex process is using it. Keeping this explicit prevents an
	// arbitrary Dev Container from silently selecting an unavailable keyring or
	// a plaintext fallback with different semantics.
	out.WriteString("cli_auth_credentials_store = \"file\"\n")
	out.WriteString("forced_login_method = \"chatgpt\"\n")
	out.WriteString("check_for_update_on_startup = false\n")
	out.WriteString("web_search = \"disabled\"\n")
	out.WriteString("[tui]\n")
	out.WriteString("notifications = [\"agent-turn-complete\", \"approval-requested\"]\n")
	out.WriteString("notification_method = \"osc9\"\n")
	out.WriteString("notification_condition = \"always\"\n")
	if cfg.SafetyMode == core.SafetyBalanced {
		out.WriteString("[sandbox_workspace_write]\n")
		fmt.Fprintf(&out, "writable_roots = [%q]\n", root)
		fmt.Fprintf(&out, "network_access = %t\n", cfg.Network)
	}
	if cfg.EventMode == "app-server" {
		out.WriteString("# Experimental app-server events are feature-flagged by the control plane.\n")
	}
	return out.String(), nil
}

func WriteConfig(path string, cfg RuntimeConfig) error {
	content, err := RenderConfig(cfg)
	if err != nil {
		return err
	}
	if filepath.Base(path) != "config.toml" {
		return errors.New("Codex config destination must end in config.toml")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*.toml")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func LaunchArgs(resumeThreadID string) ([]string, error) {
	if resumeThreadID == "" {
		return []string{"--strict-config"}, nil
	}
	if !safeThreadID.MatchString(resumeThreadID) {
		return nil, errors.New("invalid Codex thread ID")
	}
	return []string{"--strict-config", "resume", resumeThreadID}, nil
}

func DeviceAuthArgs() []string { return []string{"login", "--device-auth"} }

var safeThreadID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

func VerifyVersion(output string) error {
	fields := strings.Fields(strings.TrimSpace(output))
	if len(fields) == 0 || fields[len(fields)-1] != PinnedVersion {
		return fmt.Errorf("Codex CLI version mismatch: require %s", PinnedVersion)
	}
	return nil
}
