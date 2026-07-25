package gitops

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
)

const maximumNativeIndexBytes = 64 << 20

// indexSnapshot holds Git's real index.lock for the complete native mutation.
// Ordinary terminal Git processes therefore fail with their normal lock
// contention rather than changing the index between a scan and a mutation.
type indexSnapshot struct {
	indexPath    string
	lockPath     string
	snapshotPath string
	lock         *os.File
	lockInfo     os.FileInfo
	installed    bool
}

func (s *Service) beginIndexSnapshot(ctx context.Context) (*indexSnapshot, error) {
	rawPath, err := s.run(ctx, nil, nil, "rev-parse", "--git-path", "index")
	if err != nil {
		return nil, err
	}
	indexName := strings.TrimSpace(string(rawPath))
	clear(rawPath)
	if indexName == "" || strings.ContainsRune(indexName, 0) {
		return nil, errors.New("Git index path is invalid")
	}
	indexPath := indexName
	if !filepath.IsAbs(indexPath) {
		indexPath = filepath.Join(s.root, filepath.FromSlash(indexPath))
	}
	indexPath, err = filepath.Abs(indexPath)
	if err != nil {
		return nil, errors.New("Git index path is invalid")
	}
	relative, err := filepath.Rel(s.root, indexPath)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, errors.New("Git index must remain beneath the workspace")
	}
	if err := rejectSymlinkPath(s.root, filepath.Dir(indexPath)); err != nil {
		return nil, errors.New("Git index path is unsafe")
	}
	info, err := os.Lstat(indexPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 0 || info.Size() > maximumNativeIndexBytes {
		return nil, errors.New("Git index is unavailable")
	}
	lockPath := indexPath + ".lock"
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("%w: Git index is locked by another operation", core.ErrConflict)
	}
	if err != nil {
		return nil, errors.New("Git index lock is unavailable")
	}
	lockInfo, err := lock.Stat()
	if err != nil {
		_ = lock.Close()
		_ = os.Remove(lockPath)
		return nil, errors.New("Git index lock is unavailable")
	}
	tx := &indexSnapshot{indexPath: indexPath, lockPath: lockPath, lock: lock, lockInfo: lockInfo}
	fail := func(cause error) (*indexSnapshot, error) {
		tx.close()
		return nil, cause
	}
	content, err := readScannerFile(s.root, filepath.ToSlash(relative), maximumNativeIndexBytes)
	if err != nil {
		return fail(errors.New("Git index snapshot failed"))
	}
	defer clear(content)
	temporary, err := os.CreateTemp(filepath.Dir(indexPath), ".codex-mobile-index-*")
	if err != nil {
		return fail(errors.New("Git index snapshot failed"))
	}
	tx.snapshotPath = temporary.Name()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fail(errors.New("Git index snapshot failed"))
	}
	if _, err := io.Copy(temporary, bytes.NewReader(content)); err != nil {
		_ = temporary.Close()
		return fail(errors.New("Git index snapshot failed"))
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fail(errors.New("Git index snapshot failed"))
	}
	if err := temporary.Close(); err != nil {
		return fail(errors.New("Git index snapshot failed"))
	}
	return tx, nil
}

func (tx *indexSnapshot) environment() []string {
	return []string{"GIT_INDEX_FILE=" + tx.snapshotPath}
}

func (tx *indexSnapshot) install() error {
	if tx == nil || tx.lock == nil || tx.installed {
		return errors.New("Git index transaction is unavailable")
	}
	source, err := os.Open(tx.snapshotPath)
	if err != nil {
		return errors.New("Git index transaction failed")
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maximumNativeIndexBytes {
		return errors.New("Git index transaction failed")
	}
	if err := tx.lock.Truncate(0); err != nil {
		return errors.New("Git index transaction failed")
	}
	if _, err := tx.lock.Seek(0, io.SeekStart); err != nil {
		return errors.New("Git index transaction failed")
	}
	written, err := io.Copy(tx.lock, io.LimitReader(source, maximumNativeIndexBytes+1))
	if err != nil || written != info.Size() || written > maximumNativeIndexBytes {
		return errors.New("Git index transaction failed")
	}
	if err := tx.lock.Sync(); err != nil {
		return errors.New("Git index transaction failed")
	}
	pathInfo, pathErr := os.Lstat(tx.lockPath)
	if pathErr != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(tx.lockInfo, pathInfo) {
		return errors.New("Git index lock changed during native mutation")
	}
	if err := tx.lock.Close(); err != nil {
		tx.lock = nil
		return errors.New("Git index transaction failed")
	}
	tx.lock = nil
	if err := os.Rename(tx.lockPath, tx.indexPath); err != nil {
		return errors.New("Git index transaction failed")
	}
	tx.installed = true
	return nil
}

func (tx *indexSnapshot) close() {
	if tx == nil {
		return
	}
	if tx.lock != nil {
		_ = tx.lock.Close()
		tx.lock = nil
	}
	if !tx.installed && tx.lockPath != "" {
		if pathInfo, err := os.Lstat(tx.lockPath); err == nil && pathInfo.Mode()&os.ModeSymlink == 0 && tx.lockInfo != nil && os.SameFile(tx.lockInfo, pathInfo) {
			_ = os.Remove(tx.lockPath)
		}
	}
	if tx.snapshotPath != "" {
		_ = os.Remove(tx.snapshotPath)
	}
}

func rejectSymlinkPath(root, target string) error {
	relative, err := filepath.Rel(root, target)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("path escapes root")
	}
	current := root
	for _, segment := range strings.Split(relative, string(filepath.Separator)) {
		if segment == "" || segment == "." {
			continue
		}
		current = filepath.Join(current, segment)
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("unsafe path")
		}
	}
	return nil
}
