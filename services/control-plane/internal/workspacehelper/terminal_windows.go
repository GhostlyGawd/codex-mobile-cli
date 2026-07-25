//go:build windows

package workspacehelper

import "errors"

func execTerminal(string, []string, []string) error {
	return errors.New("workspace terminal launcher requires Linux")
}
