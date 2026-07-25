//go:build !linux

package workspacehelper

import (
	"os"
	"sync"
)

// The production helper is Linux-only. This process lock keeps package tests
// deterministic on development hosts without pretending to provide a portable
// cross-process credential boundary.
var codexAuthDevelopmentLock sync.Mutex

type codexAuthLock struct{}

func acquireCodexAuthLock(string) (*codexAuthLock, error) {
	codexAuthDevelopmentLock.Lock()
	return &codexAuthLock{}, nil
}

func (*codexAuthLock) Close() error {
	codexAuthDevelopmentLock.Unlock()
	return nil
}

func codexProcessAlive(pid int) bool { return pid == os.Getpid() }

func codexPrivatePermissions(os.FileInfo) bool { return true }
