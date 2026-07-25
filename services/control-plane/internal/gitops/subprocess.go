package gitops

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

const (
	gitCommandTimeout   = 30 * time.Second
	gitCommandWaitDelay = 2 * time.Second
	trustedUnixGitPath  = "/usr/bin/git"
)

// TrustedExecutable resolves the development-host Git binary once while
// pinning production Unix launches to the root-owned image path. The Windows
// branch exists only for portable development and tests; workspaces run Linux.
func TrustedExecutable() (string, error) {
	if runtime.GOOS != "windows" {
		info, err := os.Stat(trustedUnixGitPath)
		if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
			return "", errors.New("trusted Git executable is unavailable")
		}
		return trustedUnixGitPath, nil
	}
	path, err := exec.LookPath("git")
	if err != nil {
		return "", errors.New("git is not installed")
	}
	path, err = filepath.Abs(path)
	if err != nil || !filepath.IsAbs(path) {
		return "", errors.New("git executable path is invalid")
	}
	return filepath.Clean(path), nil
}

func boundedGitCommandContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, gitCommandTimeout)
}

func newGitCommand(parent context.Context, executable, root string, environment []string, args ...string) (*exec.Cmd, context.CancelFunc, error) {
	if parent == nil || !filepath.IsAbs(executable) || !filepath.IsAbs(root) {
		return nil, nil, errors.New("invalid Git subprocess boundary")
	}
	root = filepath.Clean(root)
	commandContext, cancel := boundedGitCommandContext(parent)
	fixed := []string{
		"--no-pager",
		"-c", "core.hooksPath=" + os.DevNull,
		"-c", "core.fsmonitor=false",
		"-c", "diff.external=",
		"-C", root,
	}
	command := exec.CommandContext(commandContext, executable, append(fixed, args...)...)
	command.Dir = root
	command.Env = append([]string(nil), environment...)
	command.WaitDelay = gitCommandWaitDelay
	return command, cancel, nil
}
