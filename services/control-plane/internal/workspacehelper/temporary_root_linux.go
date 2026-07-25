//go:build linux

package workspacehelper

import (
	"errors"

	"golang.org/x/sys/unix"
)

const ramfsMagic = 0x858458f6

func requireMemoryBackedTemporaryRoot(path string) error {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return errors.New("workspace runtime tmpfs is unavailable")
	}
	if uint64(stat.Type) != uint64(unix.TMPFS_MAGIC) && uint64(stat.Type) != ramfsMagic {
		return errors.New("workspace runtime state requires a memory-backed temporary filesystem")
	}
	return nil
}
