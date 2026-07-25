//go:build !windows

package workspacehelper

import "syscall"

func execTerminal(executable string, args, environment []string) error {
	return syscall.Exec(executable, append([]string{executable}, args...), environment)
}
