//go:build linux

package gitops

import (
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func readScannerFile(root, relative string, limit int) ([]byte, error) {
	rootFD, err := unix.Open(root, unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(rootFD)
	how := &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	}
	fd, err := unix.Openat2(rootFD, filepath.FromSlash(relative), how)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "secret-scan")
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open scanner file")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > int64(limit) {
		return nil, errors.New("invalid scanner file")
	}
	content, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil || len(content) > limit {
		clear(content)
		return nil, errors.New("invalid scanner file")
	}
	return content, nil
}
