package workspacehelper

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/gitops"
)

func TestCheckpointGitSubprocessPinsDirectoryEnvironmentAndDeadline(t *testing.T) {
	executable, err := gitops.TrustedExecutable()
	if err != nil {
		t.Fatal(err)
	}
	root, hooks := t.TempDir(), t.TempDir()
	command, cancel, err := newCheckpointGitCommand(context.Background(), executable, root, hooks, "status", "--porcelain")
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	wantArgs := []string{
		executable, "--no-pager", "-C", filepath.Clean(root),
		"-c", "core.fsmonitor=false",
		"-c", "core.hooksPath=" + filepath.Clean(hooks),
		"-c", "diff.external=",
		"status", "--porcelain",
	}
	if !reflect.DeepEqual(command.Args, wantArgs) {
		t.Fatalf("checkpoint Git argv = %#v, want %#v", command.Args, wantArgs)
	}
	if command.Path != executable || command.Dir != filepath.Clean(root) {
		t.Fatalf("checkpoint Git path/dir = %q / %q", command.Path, command.Dir)
	}
	if command.Stdin == nil || command.WaitDelay != checkpointGitWaitDelay {
		t.Fatal("checkpoint Git did not configure noninteractive bounded execution")
	}
	environment := "\n"
	for _, entry := range command.Env {
		environment += entry + "\n"
	}
	for _, required := range []string{"GIT_ATTR_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull, "GIT_PAGER=cat"} {
		if !containsEnvironmentEntry(environment, required) {
			t.Fatalf("checkpoint Git environment omitted %q: %s", required, environment)
		}
	}

	started := time.Now()
	bounded, stop := boundedCheckpointGitContext(context.Background())
	defer stop()
	deadline, ok := bounded.Deadline()
	if !ok || deadline.Sub(started) < checkpointGitTimeout-time.Second || deadline.Sub(started) > checkpointGitTimeout+time.Second {
		t.Fatalf("checkpoint Git deadline = %v (ok=%v)", deadline, ok)
	}
}

func TestCheckpointGitHonorsCanceledContext(t *testing.T) {
	root := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	if _, err := runCheckpointGit(ctx, root, "version"); err == nil {
		t.Fatal("canceled checkpoint Git command succeeded")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("canceled checkpoint Git command took %s", elapsed)
	}
}

func TestTmuxSubprocessPinsExecutableDirectoryEnvironmentAndDeadline(t *testing.T) {
	temporaryRoot := t.TempDir()
	command, cancel, err := newTmuxCommand(context.Background(), temporaryRoot, "has-session", "-t", "cm-test")
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	if command.Path != "/usr/bin/tmux" || command.Dir != filepath.Clean(temporaryRoot) {
		t.Fatalf("tmux path/dir = %q / %q", command.Path, command.Dir)
	}
	wantArgs := []string{"/usr/bin/tmux", "has-session", "-t", "cm-test"}
	if !reflect.DeepEqual(command.Args, wantArgs) {
		t.Fatalf("tmux argv = %#v", command.Args)
	}
	wantEnvironment := []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "LANG=C", "TMPDIR=" + filepath.Clean(temporaryRoot)}
	if !reflect.DeepEqual(command.Env, wantEnvironment) || command.Stdin == nil || command.Stdout == nil || command.Stderr == nil || command.WaitDelay != tmuxCommandWaitDelay {
		t.Fatalf("tmux subprocess boundary = %#v", command)
	}

	started := time.Now()
	bounded, stop := boundedTmuxCommandContext(context.Background())
	defer stop()
	deadline, ok := bounded.Deadline()
	if !ok || deadline.Sub(started) < tmuxCommandTimeout-time.Second || deadline.Sub(started) > tmuxCommandTimeout+time.Second {
		t.Fatalf("tmux deadline = %v (ok=%v)", deadline, ok)
	}
}

func TestInteractiveCodexIsTheDocumentedTerminalBoundException(t *testing.T) {
	root := t.TempDir()
	environment := []string{"PATH=/opt/codex-mobile-helper:/usr/bin", "TERM=xterm-256color"}
	command := newInteractiveCodexCommand(TrustedCodexPath, []string{"resume", "thread-1"}, root, environment)
	if command.Path != TrustedCodexPath || command.Dir != root {
		t.Fatalf("interactive Codex path/dir = %q / %q", command.Path, command.Dir)
	}
	if !reflect.DeepEqual(command.Args, []string{TrustedCodexPath, "resume", "thread-1"}) || !reflect.DeepEqual(command.Env, environment) {
		t.Fatalf("interactive Codex argv/env = %#v / %#v", command.Args, command.Env)
	}
	if command.Stdin != os.Stdin || command.Stdout != os.Stdout || command.Stderr != os.Stderr || command.WaitDelay != 0 {
		t.Fatal("interactive Codex did not own the terminal streams for its tab lifetime")
	}
}

func containsEnvironmentEntry(joined, entry string) bool {
	return entry != "" && strings.Contains(joined, "\n"+entry+"\n")
}
