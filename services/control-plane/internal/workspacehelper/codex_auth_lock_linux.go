//go:build linux

package workspacehelper

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

type codexAuthLock struct{ file *os.File }

func acquireCodexAuthLock(path string) (*codexAuthLock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &codexAuthLock{file: file}, nil
}

func (l *codexAuthLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	err := unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
	closeErr := l.file.Close()
	l.file = nil
	return errors.Join(err, closeErr)
}

func codexProcessAlive(pid int) bool {
	err := unix.Kill(pid, 0)
	return err == nil || errors.Is(err, unix.EPERM)
}

func codexPrivatePermissions(info os.FileInfo) bool { return info.Mode().Perm()&0o077 == 0 }
