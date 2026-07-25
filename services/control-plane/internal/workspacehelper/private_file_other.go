//go:build !linux

package workspacehelper

import (
	"errors"
	"io"
	"os"
	"path/filepath"
)

func ensurePrivateDirectoryPlatform(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errCodexAuthUnavailable
	}
	return os.Chmod(path, 0o700)
}

func readPrivateFilePlatform(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || !codexPrivatePermissions(info) || info.Size() < 0 || info.Size() > maximum {
		return nil, errCodexAuthUnavailable
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) || !openedInfo.Mode().IsRegular() {
		return nil, errCodexAuthUnavailable
	}
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(content)) > maximum {
		wipeBytes(content)
		return nil, errCodexAuthUnavailable
	}
	return content, nil
}

func removePrivateFilePlatform(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > 4*maxCodexAuthBytes {
		return errCodexAuthUnavailable
	}
	return os.Remove(path)
}

func writePrivateFilePlatform(target string, content []byte) error {
	if err := ensurePrivateDirectoryPlatform(filepath.Dir(target)); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(target), ".workspace-state-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, target); err != nil {
		if removeErr := os.Remove(target); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return err
		}
		return os.Rename(temporaryName, target)
	}
	return nil
}
