package workspacehelper

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestInspectRuntimeActivityIgnoresVerifiedManagedInfrastructure(t *testing.T) {
	root := fakeProc(t)
	links := make(map[string]string)
	writeFakeProcess(t, root, 10, 1, "coder-agent", 'S')
	writeFakeProcess(t, root, 20, 10, "workspace-helper", 'R')
	writeFakeProcess(t, root, 30, 1, "tmux: server", 'S')
	writeFakeExecutable(root, links, 30, trustedTmuxPath)
	writeFakeProcess(t, root, 31, 30, "bash", 'S')
	writeFakeExecutable(root, links, 31, "/usr/bin/bash")
	writeFakeCommandLine(t, root, 31, "/bin/bash", "-l")
	writeFakeProcess(t, root, 40, 1, "tmux: server", 'S')
	writeFakeExecutable(root, links, 40, trustedTmuxPath)
	writeFakeProcess(t, root, 41, 40, "workspace-helper", 'S')
	writeFakeExecutable(root, links, 41, trustedWorkspaceHelperPath)
	writeFakeProcess(t, root, 42, 41, "codex", 'S')
	writeFakeExecutable(root, links, 42, TrustedCodexPath)

	activity, err := inspectRuntimeActivityWithReadlink(root, 20, fakeReadlink(links))
	if err != nil {
		t.Fatal(err)
	}
	if activity.Busy || activity.ActiveProcessCount != 0 {
		t.Fatalf("idle runtime reported busy: %#v", activity)
	}
}

func TestInspectRuntimeActivityCannotSpoofLegacyBaselineNames(t *testing.T) {
	legacyNames := []string{
		"sh", "bash", "zsh", "fish", "dash", "tmux", "sshd", "systemd", "tini", "dumb-init",
		"coder", "coder-agent", "workspace-helper", "codex", "codex-cli",
	}
	for _, name := range legacyNames {
		t.Run(name, func(t *testing.T) {
			root := fakeProc(t)
			links := make(map[string]string)
			writeFakeProcess(t, root, 10, 1, "coder-agent", 'S')
			writeFakeProcess(t, root, 20, 10, "workspace-helper", 'R')
			writeFakeProcess(t, root, 30, 1, name, 'S')
			writeFakeExecutable(root, links, 30, "/workspaces/repository/hostile-worker")

			activity, err := inspectRuntimeActivityWithReadlink(root, 20, fakeReadlink(links))
			if err != nil {
				t.Fatal(err)
			}
			if !activity.Busy || activity.ActiveProcessCount != 1 || activity.Reason != "foreground-or-background-process" {
				t.Fatalf("spoofed process name %q evaded activity detection: %#v", name, activity)
			}
		})
	}
}

func TestInspectRuntimeActivityRejectsUnmanagedTrustedShell(t *testing.T) {
	root := fakeProc(t)
	links := make(map[string]string)
	writeFakeProcess(t, root, 10, 1, "coder-agent", 'S')
	writeFakeProcess(t, root, 20, 10, "workspace-helper", 'R')
	writeFakeProcess(t, root, 30, 1, "tmux: server", 'S')
	writeFakeExecutable(root, links, 30, trustedTmuxPath)
	writeFakeProcess(t, root, 31, 30, "bash", 'S')
	writeFakeExecutable(root, links, 31, "/usr/bin/bash")
	writeFakeCommandLine(t, root, 31, "/bin/bash", "-c", "sleep 3600")

	activity, err := inspectRuntimeActivityWithReadlink(root, 20, fakeReadlink(links))
	if err != nil {
		t.Fatal(err)
	}
	if !activity.Busy || activity.ActiveProcessCount != 1 {
		t.Fatalf("unmanaged trusted shell evaded activity detection: %#v", activity)
	}
}

func TestInspectRuntimeActivityCountsRunnableTrustedShell(t *testing.T) {
	root := fakeProc(t)
	links := make(map[string]string)
	writeFakeProcess(t, root, 10, 1, "coder-agent", 'S')
	writeFakeProcess(t, root, 20, 10, "workspace-helper", 'R')
	writeFakeProcess(t, root, 30, 1, "tmux: server", 'S')
	writeFakeExecutable(root, links, 30, trustedTmuxPath)
	writeFakeProcess(t, root, 31, 30, "bash", 'R')
	writeFakeExecutable(root, links, 31, "/usr/bin/bash")
	writeFakeCommandLine(t, root, 31, "/bin/bash", "-l")

	activity, err := inspectRuntimeActivityWithReadlink(root, 20, fakeReadlink(links))
	if err != nil {
		t.Fatal(err)
	}
	if !activity.Busy || activity.ActiveProcessCount != 1 || activity.Reason != "foreground-or-background-process" {
		t.Fatalf("runnable trusted shell evaded activity detection: %#v", activity)
	}
}

func TestInspectRuntimeActivityCountsListenerOwnedByManagedInfrastructure(t *testing.T) {
	root := fakeProc(t)
	links := make(map[string]string)
	writeFakeProcess(t, root, 10, 1, "coder-agent", 'S')
	writeFakeProcess(t, root, 20, 10, "workspace-helper", 'R')
	writeFakeProcess(t, root, 30, 1, "tmux: server", 'S')
	writeFakeExecutable(root, links, 30, trustedTmuxPath)
	writeFakeListeningSocket(t, root, links, 30, "4242")

	activity, err := inspectRuntimeActivityWithReadlink(root, 20, fakeReadlink(links))
	if err != nil {
		t.Fatal(err)
	}
	if !activity.Busy || activity.ActiveProcessCount != 0 || activity.ListeningPortCount != 1 || activity.Reason != "listening-development-service" {
		t.Fatalf("managed process listener evaded activity detection: %#v", activity)
	}
}

func TestInspectRuntimeActivityFindsForegroundOrBackgroundJob(t *testing.T) {
	root := fakeProc(t)
	writeFakeProcess(t, root, 10, 1, "coder-agent", 'S')
	writeFakeProcess(t, root, 20, 10, "workspace-helper", 'R')
	writeFakeProcess(t, root, 30, 1, "node", 'S')

	activity, err := inspectRuntimeActivity(root, 20)
	if err != nil {
		t.Fatal(err)
	}
	if !activity.Busy || activity.ActiveProcessCount != 1 || activity.Reason != "foreground-or-background-process" {
		t.Fatalf("active runtime was not preserved: %#v", activity)
	}
}

func fakeProc(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	for _, name := range []string{"tcp", "tcp6"} {
		if err := os.WriteFile(filepath.Join(root, "net", name), []byte(header), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func writeFakeProcess(t *testing.T, root string, pid, ppid int, name string, state byte) {
	t.Helper()
	directory := filepath.Join(root, fmt.Sprint(pid))
	if err := os.MkdirAll(filepath.Join(directory, "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	value := fmt.Sprintf("Name:\t%s\nState:\t%c (state)\nPPid:\t%d\n", name, state, ppid)
	if err := os.WriteFile(filepath.Join(directory, "status"), []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeFakeExecutable(root string, links map[string]string, pid int, target string) {
	links[filepath.Join(root, fmt.Sprint(pid), "exe")] = target
}

func writeFakeCommandLine(t *testing.T, root string, pid int, arguments ...string) {
	t.Helper()
	var value []byte
	for _, argument := range arguments {
		value = append(value, argument...)
		value = append(value, 0)
	}
	if err := os.WriteFile(filepath.Join(root, fmt.Sprint(pid), "cmdline"), value, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeFakeListeningSocket(t *testing.T, root string, links map[string]string, pid int, inode string) {
	t.Helper()
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	listener := "0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 " + inode + "\n"
	if err := os.WriteFile(filepath.Join(root, "net", "tcp"), []byte(header+listener), 0o600); err != nil {
		t.Fatal(err)
	}
	fd := filepath.Join(root, fmt.Sprint(pid), "fd", "3")
	if err := os.WriteFile(fd, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	links[fd] = "socket:[" + inode + "]"
}

func fakeReadlink(links map[string]string) func(string) (string, error) {
	return func(link string) (string, error) {
		target, ok := links[link]
		if !ok {
			return "", os.ErrNotExist
		}
		return target, nil
	}
}
