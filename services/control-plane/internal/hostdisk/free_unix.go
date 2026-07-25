//go:build !windows

package hostdisk

import (
	"errors"
	"math"
	"strings"

	"golang.org/x/sys/unix"
)

// FreeGiB returns the free blocks available to the unprivileged control-plane
// user on the filesystem containing path. Production points this at an empty,
// read-only bind mount on the same filesystem as workspace volumes; no host
// data needs to be exposed to measure capacity.
func FreeGiB(path string) (int64, error) {
	if strings.TrimSpace(path) == "" {
		return 0, errors.New("disk probe path is required")
	}
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, err
	}
	bytes := uint64(stat.Bavail) * uint64(stat.Bsize)
	if stat.Bavail != 0 && bytes/uint64(stat.Bavail) != uint64(stat.Bsize) {
		return math.MaxInt64 >> 30, nil
	}
	return int64(bytes >> 30), nil
}
