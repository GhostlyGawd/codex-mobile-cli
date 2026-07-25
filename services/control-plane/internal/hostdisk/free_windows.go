//go:build windows

package hostdisk

import (
	"errors"
	"strings"

	"golang.org/x/sys/windows"
)

// FreeGiB is the Windows development equivalent of the production filesystem
// probe. It uses the caller-visible free-byte count for the selected volume.
func FreeGiB(path string) (int64, error) {
	if strings.TrimSpace(path) == "" {
		return 0, errors.New("disk probe path is required")
	}
	root, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var available uint64
	if err := windows.GetDiskFreeSpaceEx(root, &available, nil, nil); err != nil {
		return 0, err
	}
	return int64(available >> 30), nil
}
