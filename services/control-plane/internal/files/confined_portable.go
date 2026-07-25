//go:build !linux

package files

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
)

type portableConfinedFS struct {
	root *os.Root
}

func newConfinedFS(root string) (confinedFS, error) {
	pinned, err := os.OpenRoot(root)
	if err != nil {
		return nil, fmt.Errorf("pin workspace root: %w", err)
	}
	return &portableConfinedFS{root: pinned}, nil
}

func (p *portableConfinedFS) close() error { return p.root.Close() }

func (p *portableConfinedFS) read(normalized string, maxBytes int64) (fileSnapshot, error) {
	parent, name, err := p.openParent(normalized)
	if err != nil {
		return fileSnapshot{}, err
	}
	defer parent.Close()
	// Link/Rename has already committed. A failure in this final read therefore
	// requires fresh Read/ETag reconciliation rather than a blind save retry.
	return portableSnapshotAt(parent, name, maxBytes)
}

func (p *portableConfinedFS) saveCAS(normalized string, content []byte, expectedETag string, maxBytes int64, hooks saveHooks) (fileSnapshot, error) {
	parent, name, err := p.openParent(normalized)
	if err != nil {
		return fileSnapshot{}, err
	}
	defer parent.Close()

	mode := os.FileMode(0o644)
	current, currentErr := portableSnapshotAt(parent, name, maxBytes)
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

	tmpName, tmp, err := portableCreateTemp(parent)
	if err != nil {
		return fileSnapshot{}, err
	}
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = parent.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(mode.Perm()); err != nil {
		return fileSnapshot{}, err
	}
	if err := writeAll(tmp, content); err != nil {
		return fileSnapshot{}, err
	}
	if err := tmp.Sync(); err != nil {
		return fileSnapshot{}, err
	}
	if err := tmp.Close(); err != nil {
		return fileSnapshot{}, err
	}
	if hooks.beforeFinalValidation != nil {
		hooks.beforeFinalValidation()
	}

	if expectedETag == "" {
		// A hard-link install is atomic and fails rather than replacing a file
		// created after the initial existence check.
		if err := parent.Link(tmpName, name); err != nil {
			if errors.Is(err, fs.ErrExist) {
				return fileSnapshot{}, fmt.Errorf("%w: file already exists", core.ErrConflict)
			}
			return fileSnapshot{}, err
		}
		if err := parent.Remove(tmpName); err != nil {
			// Link already installed the destination. This error is therefore a
			// commit-uncertain cleanup failure, not proof that creation failed.
			return fileSnapshot{}, err
		}
		committed = true
	} else {
		latest, err := portableSnapshotAt(parent, name, maxBytes)
		if errors.Is(err, os.ErrNotExist) || (err == nil && etag(latest.content) != expectedETag) {
			return fileSnapshot{}, fmt.Errorf("%w: file changed since it was read", core.ErrPrecondition)
		}
		if err != nil {
			return fileSnapshot{}, err
		}
		if hooks.afterFinalValidation != nil {
			hooks.afterFinalValidation()
		}
		// Portable platforms do not expose conditional rename-exchange. This
		// recheck catches deterministic races, but an uncooperative cross-process
		// writer can still change the target between this check and Rename. The
		// authoritative external-writer CAS guarantee is Linux-only.
		latest, err = portableSnapshotAt(parent, name, maxBytes)
		if errors.Is(err, os.ErrNotExist) || (err == nil && etag(latest.content) != expectedETag) {
			return fileSnapshot{}, fmt.Errorf("%w: file changed at commit", core.ErrPrecondition)
		}
		if err != nil {
			return fileSnapshot{}, err
		}
		if err := parent.Rename(tmpName, name); err != nil {
			return fileSnapshot{}, err
		}
		// From this point a final-read failure is commit-uncertain: Rename has
		// already changed the destination and callers must reconcile by reading.
		committed = true
	}
	return portableSnapshotAt(parent, name, maxBytes)
}

func (p *portableConfinedFS) tree(ctx context.Context, maxEntries int, sampleFiles bool) ([]Entry, error) {
	root, err := p.root.OpenRoot(".")
	if err != nil {
		return nil, err
	}
	entries := make([]Entry, 0)
	if err := walkPortableDirectory(ctx, root, "", maxEntries, sampleFiles, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func walkPortableDirectory(ctx context.Context, directory *os.Root, prefix string, maxEntries int, sampleFiles bool, result *[]Entry) error {
	defer directory.Close()
	dir, err := directory.Open(".")
	if err != nil {
		return err
	}
	dirEntries, readErr := dir.ReadDir(-1)
	closeErr := dir.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
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
		info, err := directory.Lstat(name)
		if err != nil {
			return err
		}
		isSymlink := info.Mode()&os.ModeSymlink != 0
		isDir := info.IsDir()
		if isDir && (name == ".git" || name == ".codex-mobile") {
			continue
		}
		entry := Entry{Path: relative, Directory: isDir, Sensitive: Sensitive(relative)}
		if isSymlink || (!isDir && !info.Mode().IsRegular()) {
			entry.Sensitive = true
		}
		if len(*result) >= maxEntries {
			return fmt.Errorf("file tree exceeds %d entries", maxEntries)
		}
		*result = append(*result, entry)
		if isSymlink {
			continue
		}
		if isDir {
			child, err := directory.OpenRoot(name)
			if err != nil {
				return err
			}
			openedInfo, err := child.Stat(".")
			if err != nil {
				_ = child.Close()
				return err
			}
			if !os.SameFile(info, openedInfo) {
				_ = child.Close()
				return fmt.Errorf("%w: directory changed during traversal", core.ErrForbidden)
			}
			if err := walkPortableDirectory(ctx, child, relative, maxEntries, sampleFiles, result); err != nil {
				return err
			}
			continue
		}
		if !info.Mode().IsRegular() {
			continue
		}
		(*result)[len(*result)-1].Size = info.Size()
		if sampleFiles && !entry.Sensitive && info.Size() <= 8192 {
			f, err := portableOpenStable(directory, name)
			if err != nil {
				return err
			}
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

func (p *portableConfinedFS) openParent(normalized string) (*os.Root, string, error) {
	parts := strings.Split(normalized, "/")
	name := filepath.FromSlash(parts[len(parts)-1])
	current, err := p.root.OpenRoot(".")
	if err != nil {
		return nil, "", err
	}
	for _, slashComponent := range parts[:len(parts)-1] {
		component := filepath.FromSlash(slashComponent)
		info, err := current.Lstat(component)
		if err != nil {
			_ = current.Close()
			return nil, "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			_ = current.Close()
			return nil, "", fmt.Errorf("%w: symbolic links are not exposed", core.ErrForbidden)
		}
		if !info.IsDir() {
			_ = current.Close()
			return nil, "", fmt.Errorf("%w: path component is not a directory", core.ErrInvalid)
		}
		next, err := current.OpenRoot(component)
		if err != nil {
			_ = current.Close()
			return nil, "", err
		}
		openedInfo, err := next.Stat(".")
		if err != nil || !os.SameFile(info, openedInfo) {
			_ = next.Close()
			_ = current.Close()
			if err != nil {
				return nil, "", err
			}
			return nil, "", fmt.Errorf("%w: directory changed while resolving path", core.ErrForbidden)
		}
		_ = current.Close()
		current = next
	}
	return current, name, nil
}

func portableSnapshotAt(parent *os.Root, name string, maxBytes int64) (fileSnapshot, error) {
	f, err := portableOpenStable(parent, name)
	if err != nil {
		return fileSnapshot{}, err
	}
	return snapshotFromOpenFile(f, maxBytes)
}

func portableOpenStable(parent *os.Root, name string) (*os.File, error) {
	before, err := parent.Lstat(name)
	if err != nil {
		return nil, err
	}
	if err := validateRegular(before); err != nil {
		return nil, err
	}
	f, err := parent.Open(name)
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !os.SameFile(before, after) {
		_ = f.Close()
		return nil, fmt.Errorf("%w: file changed while opening", core.ErrForbidden)
	}
	return f, nil
}

func portableCreateTemp(parent *os.Root) (string, *os.File, error) {
	for attempt := 0; attempt < 32; attempt++ {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return "", nil, err
		}
		name := ".codex-mobile-save-" + hex.EncodeToString(random[:])
		f, err := parent.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			return name, f, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return "", nil, err
		}
	}
	return "", nil, errors.New("create unique temporary workspace file")
}

func writeAll(w io.Writer, content []byte) error {
	for len(content) > 0 {
		written, err := w.Write(content)
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
