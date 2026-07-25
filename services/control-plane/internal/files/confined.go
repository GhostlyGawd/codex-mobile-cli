package files

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
)

type fileSnapshot struct {
	content  []byte
	size     int64
	modified time.Time
	mode     fs.FileMode
}

// confinedFS is the security boundary for workspace filesystem operations.
// Implementations resolve every path relative to a pinned workspace root and
// atomically install staged saves. Only Linux provides an exact cross-process
// ETag CAS via rename-exchange; portable implementations revalidate immediately
// before rename but cannot make that check conditional on the rename syscall.
type confinedFS interface {
	read(normalized string, maxBytes int64) (fileSnapshot, error)
	saveCAS(normalized string, content []byte, expectedETag string, maxBytes int64, hooks saveHooks) (fileSnapshot, error)
	tree(ctx context.Context, maxEntries int, sampleFiles bool) ([]Entry, error)
	close() error
}

type saveHooks struct {
	beforeFinalValidation func()
	afterFinalValidation  func()
}

func snapshotFromOpenFile(f *os.File, maxBytes int64) (fileSnapshot, error) {
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return fileSnapshot{}, err
	}
	if !info.Mode().IsRegular() {
		return fileSnapshot{}, fmt.Errorf("%w: not a regular file", core.ErrInvalid)
	}
	if info.Size() > maxBytes {
		return fileSnapshot{}, fmt.Errorf("%w: file exceeds %d bytes", core.ErrInvalid, maxBytes)
	}
	content, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return fileSnapshot{}, err
	}
	if int64(len(content)) > maxBytes {
		return fileSnapshot{}, fmt.Errorf("%w: file exceeds %d bytes", core.ErrInvalid, maxBytes)
	}
	after, err := f.Stat()
	if err != nil {
		return fileSnapshot{}, err
	}
	if info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) {
		return fileSnapshot{}, fmt.Errorf("%w: file changed while it was read", core.ErrPrecondition)
	}
	return fileSnapshot{content: content, size: int64(len(content)), modified: after.ModTime().UTC(), mode: after.Mode().Perm()}, nil
}

func validateRegular(info fs.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: symbolic links are not exposed", core.ErrForbidden)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: target is not a regular file", core.ErrInvalid)
	}
	return nil
}
