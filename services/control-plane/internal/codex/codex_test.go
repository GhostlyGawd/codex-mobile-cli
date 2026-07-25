package codex

import (
	"strings"
	"testing"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
)

func TestRenderModesAndNotifications(t *testing.T) {
	root := t.TempDir()
	for _, test := range []struct {
		mode            core.SafetyMode
		sandbox         string
		approval        string
		containsNetwork bool
	}{
		{core.SafetySafe, "read-only", "on-request", false},
		{core.SafetyBalanced, "workspace-write", "on-request", true},
		{core.SafetyFullAccess, "danger-full-access", "never", false},
	} {
		out, err := RenderConfig(RuntimeConfig{SafetyMode: test.mode, Network: true, WritableRoot: root})
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"sandbox_mode = \"" + test.sandbox + "\"", "approval_policy = \"" + test.approval + "\"", "cli_auth_credentials_store = \"file\"", "forced_login_method = \"chatgpt\"", "check_for_update_on_startup = false", "notifications = [\"agent-turn-complete\", \"approval-requested\"]", "notification_method = \"osc9\"", "notification_condition = \"always\""} {
			if !strings.Contains(out, want) {
				t.Fatalf("mode %s missing %q in %s", test.mode, want, out)
			}
		}
		if strings.Contains(out, "network_access") != test.containsNetwork {
			t.Fatalf("unexpected network setting for %s", test.mode)
		}
		if strings.Contains(out, "api_key") {
			t.Fatal("must never configure pay-as-you-go API keys")
		}
	}
}

func TestLaunchArgsAndVersion(t *testing.T) {
	if args, _ := LaunchArgs(""); len(args) != 1 || args[0] != "--strict-config" {
		t.Fatalf("unexpected new TUI args: %#v", args)
	}
	args, err := LaunchArgs("019-thread:id")
	if err != nil || strings.Join(args, " ") != "--strict-config resume 019-thread:id" {
		t.Fatalf("unexpected resume args: %#v %v", args, err)
	}
	if _, err := LaunchArgs("--bad"); err == nil {
		t.Fatal("expected unsafe thread ID rejection")
	}
	if err := VerifyVersion("codex-cli 0.144.5\n"); err != nil {
		t.Fatal(err)
	}
	if err := VerifyVersion("codex-cli 0.145.0"); err == nil {
		t.Fatal("expected pin mismatch")
	}
}

func TestOSC9ProviderHandlesSplitTerminatorsWithoutLeakingContent(t *testing.T) {
	p := &OSC9Provider{}
	if events := p.Observe([]byte("normal\x1b]9;Approval requested for SECRET")); len(events) != 0 {
		t.Fatal("incomplete notification must remain buffered")
	}
	events := p.Observe([]byte("\x1b\\tail\x1b]9;Agent turn complete\x07"))
	if len(events) != 2 || events[0].Kind != EventNeedsAttention || events[1].Kind != EventNeedsAttention {
		t.Fatalf("unexpected events: %#v", events)
	}
	for _, event := range events {
		if strings.Contains(event.GenericSummary, "SECRET") || event.StructuredDetail {
			t.Fatalf("terminal content leaked: %#v", event)
		}
	}
}
