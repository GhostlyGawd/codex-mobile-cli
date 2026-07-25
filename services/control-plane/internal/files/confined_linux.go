//go:build linux

package files

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"golang.org/x/sys/unix"
)

type linuxConfinedFS struct {
	rootFD int
}

func newConfinedFS(root string) (confinedFS, error) {
	fd, err := openAbsoluteDirectoryNoFollow(root)
	if err != nil {
		return nil, fmt.Errorf("pin workspace root: %w", err)
	}
	return &linuxConfinedFS{rootFD: fd}, nil
}

func openAbsoluteDirectoryNoFollow(absolute string) (int, error) {
	if !strings.HasPrefix(absolute, "/") {
		return -1, fmt.Errorf("%w: workspace root must be absolute", core.ErrInvalid)
	}
	current, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	for _, component := range strings.Split(strings.Trim(absolute, "/"), "/") {
		if component == "" {
			continue
		}
		var stat unix.Stat_t
		if err := unix.Fstatat(current, component, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			_ = unix.Close(current)
			return -1, mapLinuxPathError(err)
		}
		if stat.Mode&unix.S_IFMT == unix.S_IFLNK {
			_ = unix.Close(current)
			return -1, fmt.Errorf("%w: workspace root includes a symbolic link", core.ErrForbidden)
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
			_ = unix.Close(current)
			return -1, fmt.Errorf("%w: workspace root component is not a directory", core.ErrInvalid)
		}
		next, err := unix.Openat(current, component, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		_ = unix.Close(current)
		if err != nil {
			return -1, mapLinuxPathError(err)
		}
		current = next
	}
	return current, nil
}

func (l *linuxConfinedFS) close() error { return unix.Close(l.rootFD) }

func (l *linuxConfinedFS) read(normalized string, maxBytes int64) (fileSnapshot, error) {
	parentFD, name, err := l.openParent(normalized)
	if err != nil {
		return fileSnapshot{}, err
	}
	defer unix.Close(parentFD)
	return snapshotAt(parentFD, name, maxBytes)
}

func (l *linuxConfinedFS) saveCAS(normalized string, content []byte, expectedETag string, maxBytes int64, hooks saveHooks) (fileSnapshot, error) {
	parentFD, name, err := l.openParent(normalized)
	if err != nil {
		return fileSnapshot{}, err
	}
	defer unix.Close(parentFD)

	mode := os.FileMode(0o644)
	current, currentErr := snapshotAt(parentFD, name, maxBytes)
	switch {
	case currentErr == nil:
		if Binary(current.content) {
			return fileSnapshot{}, fmt.Errorf("%w: binary files cannot be overwritten", core.ErrInvalid)
		}
		if expectedETag == "" {
			return fileSnapshot{}, fmt.Errorf("%w: file already exists", core.ErrConflict)
		}
		if etag(current.content) != expectedETag {
			return fileSnapshot{}, fmt.Errorf("%w: file changed since it was read", core.ErrPrecondition)
		}
		mode = current.mode
	case errors.Is(currentErr, os.ErrNotExist):
		if expectedETag != "" {
			return fileSnapshot{}, fmt.Errorf("%w: expected file does not exist", core.ErrPrecondition)
		}
	default:
		return fileSnapshot{}, currentErr
	}

	tmpName, tmpFD, err := createTempAt(parentFD)
	if err != nil {
		return fileSnapshot{}, err
	}
	committed := false
	defer func() {
		_ = unix.Close(tmpFD)
		if !committed {
			_ = unix.Unlinkat(parentFD, tmpName, 0)
		}
	}()
	if err := unix.Fchmod(tmpFD, uint32(mode.Perm())); err != nil {
		return fileSnapshot{}, err
	}
	if err := writeAllFD(tmpFD, content); err != nil {
		return fileSnapshot{}, err
	}
	if err := unix.Fsync(tmpFD); err != nil {
		return fileSnapshot{}, err
	}
	if hooks.beforeFinalValidation != nil {
		hooks.beforeFinalValidation()
	}

	if expectedETag == "" {
		if err := renameNoReplace(parentFD, tmpName, name); err != nil {
			if errors.Is(err, unix.EEXIST) {
				return fileSnapshot{}, fmt.Errorf("%w: file already exists", core.ErrConflict)
			}
			return fileSnapshot{}, err
		}
		committed = true
	} else {
		// Revalidate once staging is complete, then exchange the paths. The
		// exchange lets us hash the exact inode displaced at the commit boundary,
		// rather than trusting a path check performed before rename.
		latest, err := snapshotAt(parentFD, name, maxBytes)
		if errors.Is(err, os.ErrNotExist) || (err == nil && etag(latest.content) != expectedETag) {
			return fileSnapshot{}, fmt.Errorf("%w: file changed since it was read", core.ErrPrecondition)
		}
		if err != nil {
			return fileSnapshot{}, err
		}
		if hooks.afterFinalValidation != nil {
			hooks.afterFinalValidation()
		}
		if err := unix.Renameat2(parentFD, tmpName, parentFD, name, unix.RENAME_EXCHANGE); err != nil {
			return fileSnapshot{}, fmt.Errorf("atomic compare-and-swap is unavailable: %w", err)
		}
		victim, victimErr := snapshotAt(parentFD, tmpName, maxBytes)
		if victimErr != nil || etag(victim.content) != expectedETag {
			rollbackErr := unix.Renameat2(parentFD, tmpName, parentFD, name, unix.RENAME_EXCHANGE)
			if rollbackErr != nil {
				return fileSnapshot{}, fmt.Errorf("restore file after compare-and-swap conflict: %w", rollbackErr)
			}
			if victimErr != nil {
				return fileSnapshot{}, victimErr
			}
			return fileSnapshot{}, fmt.Errorf("%w: file changed at commit", core.ErrPrecondition)
		}
		if err := unix.Unlinkat(parentFD, tmpName, 0); err != nil {
			// The destination is already committed, so this cleanup error has an
			// uncertain API outcome despite the successful namespace operation.
			return fileSnapshot{}, fmt.Errorf("remove displaced file: %w", err)
		}
		committed = true
	}
	if err := unix.Fsync(parentFD); err != nil {
		// The namespace operation above succeeded even though durability could
		// not be confirmed. Treat this as commit-uncertain at the API boundary.
		return fileSnapshot{}, fmt.Errorf("sync parent directory: %w", err)
	}
	// A failure here follows a successful namespace commit. Callers must
	// reconcile with a fresh Read/ETag before retrying any failed save.
	return snapshotAt(parentFD, name, maxBytes)
}

func (l *linuxConfinedFS) tree(ctx context.Context, maxEntries int, sampleFiles bool) ([]Entry, error) {
	rootFD, err := unix.Openat(l.rootFD, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, mapLinuxPathError(err)
	}
	entries := make([]Entry, 0)
	if err := walkLinuxDirectory(ctx, rootFD, "", maxEntries, sampleFiles, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func walkLinuxDirectory(ctx context.Context, dirFD int, prefix string, maxEntries int, sampleFiles bool, result *[]Entry) error {
	dir := os.NewFile(uintptr(dirFD), "workspace-directory")
	if dir == nil {
		_ = unix.Close(dirFD)
		return errors.New("open workspace directory descriptor")
	}
	defer dir.Close()
	dirEntries, err := dir.ReadDir(-1)
	if err != nil {
		return err
	}
	sort.Slice(dirEntries, func(i, j int) bool { return dirEntries[i].Name() < dirEntries[j].Name() })
	for _, dirEntry := range dirEntries {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := dirEntry.Name()
		if strings.HasPrefix(name, ".codex-mobile-save-") {
			continue
		}
		relative := name
		if prefix != "" {
			relative = prefix + "/" + name
		}
		var stat unix.Stat_t
		if err := unix.Fstatat(int(dir.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return mapLinuxPathError(err)
		}
		kind := stat.Mode & unix.S_IFMT
		isDir := kind == unix.S_IFDIR
		if isDir && (name == ".git" || name == ".codex-mobile") {
			continue
		}
		entry := Entry{Path: relative, Directory: isDir, Sensitive: Sensitive(relative)}
		if kind == unix.S_IFLNK || (kind != unix.S_IFDIR && kind != unix.S_IFREG) {
			entry.Sensitive = true
		}
		if len(*result) >= maxEntries {
			return fmt.Errorf("file tree exceeds %d entries", maxEntries)
		}
		*result = append(*result, entry)
		if isDir {
			childFD, err := openDirectoryAt(int(dir.Fd()), name)
			if err != nil {
				return err
			}
			if err := walkLinuxDirectory(ctx, childFD, relative, maxEntries, sampleFiles, result); err != nil {
				return err
			}
			continue
		}
		if kind != unix.S_IFREG {
			continue
		}
		(*result)[len(*result)-1].Size = stat.Size
		if sampleFiles && !entry.Sensitive && stat.Size <= 8192 {
			fd, err := openRegularAt(int(dir.Fd()), name)
			if err != nil {
				return err
			}
			f := os.NewFile(uintptr(fd), relative)
			sample, readErr := io.ReadAll(io.LimitReader(f, 8192))
			closeErr := f.Close()
			if readErr != nil {
				return readErr
			}
			if closeErr != nil {
				return closeErr
			}
			(*result)[len(*result)-1].Binary = Binary(sample)
		}
	}
	return nil
}

func (l *linuxConfinedFS) openParent(normalized string) (int, string, error) {
	directory, name := path.Split(normalized)
	directory = strings.TrimSuffix(directory, "/")
	fd, err := unix.Openat(l.rootFD, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, "", mapLinuxPathError(err)
	}
	if directory == "" {
		return fd, name, nil
	}
	for _, component := range strings.Split(directory, "/") {
		next, err := openDirectoryAt(fd, component)
		_ = unix.Close(fd)
		if err != nil {
			return -1, "", err
		}
		fd = next
	}
	return fd, name, nil
}

func openDirectoryAt(parentFD int, name string) (int, error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return -1, mapLinuxPathError(err)
	}
	if stat.Mode&unix.S_IFMT == unix.S_IFLNK {
		return -1, fmt.Errorf("%w: symbolic links are not exposed", core.ErrForbidden)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return -1, fmt.Errorf("%w: path component is not a directory", core.ErrInvalid)
	}
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, mapLinuxPathError(err)
	}
	return fd, nil
}

func openRegularAt(parentFD int, name string) (int, error) {
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return -1, mapLinuxPathError(err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("%w: target is not a regular file", core.ErrInvalid)
	}
	return fd, nil
}

func snapshotAt(parentFD int, name string, maxBytes int64) (fileSnapshot, error) {
	fd, err := openRegularAt(parentFD, name)
	if err != nil {
		return fileSnapshot{}, err
	}
	f := os.NewFile(uintptr(fd), name)
	if f == nil {
		_ = unix.Close(fd)
		return fileSnapshot{}, errors.New("open workspace file descriptor")
	}
	return snapshotFromOpenFile(f, maxBytes)
}

func createTempAt(parentFD int) (string, int, error) {
	for attempt := 0; attempt < 32; attempt++ {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return "", -1, err
		}
		name := ".codex-mobile-save-" + hex.EncodeToString(random[:])
		fd, err := unix.Openat(parentFD, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		if err == nil {
			return name, fd, nil
		}
		if !errors.Is(err, unix.EEXIST) {
			return "", -1, mapLinuxPathError(err)
		}
	}
	return "", -1, errors.New("create unique temporary workspace file")
}

func writeAllFD(fd int, content []byte) error {
	for len(content) > 0 {
		written, err := unix.Write(fd, content)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		content = content[written:]
	}
	return nil
}

func renameNoReplace(parentFD int, source, destination string) error {
	err := unix.Renameat2(parentFD, source, parentFD, destination, unix.RENAME_NOREPLACE)
	if !errors.Is(err, unix.ENOSYS) && !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.EOPNOTSUPP) {
		return err
	}
	if err := unix.Linkat(parentFD, source, parentFD, destination, 0); err != nil {
		return err
	}
	return unix.Unlinkat(parentFD, source, 0)
}

func mapLinuxPathError(err error) error {
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EXDEV) || errors.Is(err, unix.ENOTDIR) {
		return fmt.Errorf("%w: symbolic links are not exposed", core.ErrForbidden)
	}
	return err
}
