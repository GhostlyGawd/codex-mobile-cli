//go:build linux

package workspacehelper

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const maximumPrivateRemovalBytes = 4 * maxCodexAuthBytes

func ensurePrivateDirectoryPlatform(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	how := &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, path, how)
	if err != nil {
		return errCodexAuthUnavailable
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errCodexAuthUnavailable
	}
	return unix.Fchmod(fd, 0o700)
}

func readPrivateFilePlatform(path string, maximum int64) ([]byte, error) {
	if maximum < 0 {
		return nil, errCodexAuthUnavailable
	}
	parent, base, err := openPrivateParent(path)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parent)
	fd, err := unix.Openat(parent, base, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "private-state")
	if file == nil {
		_ = unix.Close(fd)
		return nil, errCodexAuthUnavailable
	}
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o077 != 0 || stat.Nlink != 1 || stat.Size < 0 || stat.Size > maximum {
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
	parent, base, err := openPrivateParent(path)
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	var stat unix.Stat_t
	if err := unix.Fstatat(parent, base, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Size < 0 || stat.Size > maximumPrivateRemovalBytes {
		return errCodexAuthUnavailable
	}
	// Unlink is deliberately performed without reopening and overwriting the
	// pathname. Secure erasure is not reliable on copy-on-write storage, and a
	// pathname wipe creates a symlink/hard-link overwrite primitive.
	return unix.Unlinkat(parent, base, 0)
}

func writePrivateFilePlatform(target string, content []byte) error {
	if err := ensurePrivateDirectoryPlatform(filepath.Dir(target)); err != nil {
		return err
	}
	parent, base, err := openPrivateParent(target)
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	var temporaryName string
	var temporary *os.File
	for attempt := 0; attempt < 16; attempt++ {
		randomBytes := make([]byte, 16)
		if _, err := io.ReadFull(rand.Reader, randomBytes); err != nil {
			wipeBytes(randomBytes)
			return err
		}
		temporaryName = ".workspace-state-" + hex.EncodeToString(randomBytes)
		wipeBytes(randomBytes)
		fd, openErr := unix.Openat(parent, temporaryName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if errors.Is(openErr, unix.EEXIST) {
			continue
		}
		if openErr != nil {
			return openErr
		}
		temporary = os.NewFile(uintptr(fd), "private-state-temporary")
		if temporary == nil {
			_ = unix.Close(fd)
			_ = unix.Unlinkat(parent, temporaryName, 0)
			return errCodexAuthUnavailable
		}
		break
	}
	if temporary == nil {
		return errCodexAuthUnavailable
	}
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = unix.Unlinkat(parent, temporaryName, 0)
		}
	}()
	if _, err := temporary.Write(content); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := unix.Renameat(parent, temporaryName, parent, base); err != nil {
		return err
	}
	committed = true
	return unix.Fsync(parent)
}

func openPrivateParent(path string) (int, string, error) {
	if !filepath.IsAbs(path) {
		return -1, "", errCodexAuthUnavailable
	}
	base := filepath.Base(path)
	if base == "." || base == string(filepath.Separator) || base == "" {
		return -1, "", errCodexAuthUnavailable
	}
	how := &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, filepath.Dir(path), how)
	if err != nil {
		return -1, "", err
	}
	return fd, base, nil
}
