package gitops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestGitSubprocessBoundaryPinsExecutableDirectoryEnvironmentAndDeadline(t *testing.T) {
	executable, err := TrustedExecutable()
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(executable) {
		t.Fatalf("Git executable is not absolute: %q", executable)
	}
	if runtime.GOOS != "windows" && executable != trustedUnixGitPath {
		t.Fatalf("production Git executable = %q, want %q", executable, trustedUnixGitPath)
	}

	root := t.TempDir()
	environment := []string{"ONLY_TRUSTED=value"}
	command, cancel, err := newGitCommand(context.Background(), executable, root, environment, "version")
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	wantArgs := []string{
		executable, "--no-pager",
		"-c", "core.hooksPath=" + os.DevNull,
		"-c", "core.fsmonitor=false",
		"-c", "diff.external=",
		"-C", filepath.Clean(root), "version",
	}
	if !reflect.DeepEqual(command.Args, wantArgs) {
		t.Fatalf("Git argv = %#v, want %#v", command.Args, wantArgs)
	}
	if command.Path != executable || command.Dir != filepath.Clean(root) {
		t.Fatalf("Git command path/dir = %q / %q", command.Path, command.Dir)
	}
	if !reflect.DeepEqual(command.Env, environment) {
		t.Fatalf("Git environment = %#v", command.Env)
	}
	if command.WaitDelay != gitCommandWaitDelay {
		t.Fatalf("Git wait delay = %s", command.WaitDelay)
	}

	started := time.Now()
	bounded, stop := boundedGitCommandContext(context.Background())
	defer stop()
	deadline, ok := bounded.Deadline()
	if !ok || deadline.Sub(started) < gitCommandTimeout-time.Second || deadline.Sub(started) > gitCommandTimeout+time.Second {
		t.Fatalf("Git deadline = %v (ok=%v)", deadline, ok)
	}
}

func TestGitSubprocessHonorsCanceledContextWithoutStarting(t *testing.T) {
	executable, err := TrustedExecutable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancelParent := context.WithCancel(context.Background())
	cancelParent()
	command, cancel, err := newGitCommand(ctx, executable, t.TempDir(), gitEnv(), "version")
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	started := time.Now()
	if err := command.Run(); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Git command error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("canceled Git command took %s", elapsed)
	}
}

func TestGitEnvironmentIsAnExplicitAllowlist(t *testing.T) {
	joined := "\n" + strings.Join(gitEnv(), "\n") + "\n"
	for _, required := range []string{"\nGIT_ATTR_NOSYSTEM=1\n", "\nGIT_CONFIG_NOSYSTEM=1\n", "\nGIT_TERMINAL_PROMPT=0\n", "\nGIT_PAGER=cat\n"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("Git environment omitted %q: %s", required, joined)
		}
	}
	for _, forbidden := range []string{"GIT_ASKPASS=", "GIT_EXEC_PATH=", "BASH_ENV=", "CODER_AGENT_TOKEN=", "DATABASE_URL="} {
		if strings.Contains(joined, "\n"+forbidden) {
			t.Fatalf("Git environment inherited %q", forbidden)
		}
	}
}
