package files

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
)

const (
	DefaultMaxFileBytes = 2 * 1024 * 1024
	DefaultMaxEntries   = 5000
	DefaultSearchBytes  = 2 * 1024 * 1024
	DefaultSearchScan   = 64 * 1024 * 1024
)

type File struct {
	Path     string    `json:"path"`
	Content  []byte    `json:"content"`
	ETag     string    `json:"etag"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
}

type Entry struct {
	Path      string `json:"path"`
	Directory bool   `json:"directory"`
	Size      int64  `json:"size,omitempty"`
	Sensitive bool   `json:"sensitive"`
	Binary    bool   `json:"binary"`
}

type SearchMatch struct {
	Path   string `json:"path"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
	Text   string `json:"text"`
}

type Service struct {
	root           string
	maxFileBytes   int64
	maxEntries     int
	maxSearchBytes int64
	maxSearchScan  int64
	filesystem     confinedFS
	commitMu       sync.Mutex
	closeOnce      sync.Once
	closeErr       error

	// saveHooks are per-service dependency-injection seams used by deterministic
	// concurrency tests. Production constructors leave them empty.
	saveHooks saveHooks
}

func New(root string) (*Service, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("resolve workspace root: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return nil, errors.New("workspace root must be a directory")
	}
	filesystem, err := newConfinedFS(filepath.Clean(resolved))
	if err != nil {
		return nil, err
	}
	return &Service{
		root:           filepath.Clean(resolved),
		maxFileBytes:   DefaultMaxFileBytes,
		maxEntries:     DefaultMaxEntries,
		maxSearchBytes: DefaultSearchBytes,
		maxSearchScan:  DefaultSearchScan,
		filesystem:     filesystem,
	}, nil
}

// Close releases the pinned workspace root. A Service remains safe to abandon
// at process exit, but short-lived callers should close it deterministically.
func (s *Service) Close() error {
	s.closeOnce.Do(func() { s.closeErr = s.filesystem.close() })
	return s.closeErr
}

func (s *Service) Read(relative string) (File, error) {
	_, normalized, err := s.clean(relative)
	if err != nil {
		return File{}, err
	}
	if Sensitive(normalized) {
		return File{}, fmt.Errorf("%w: sensitive path is unavailable", core.ErrForbidden)
	}
	snapshot, err := s.filesystem.read(normalized, s.maxFileBytes)
	if err != nil {
		return File{}, err
	}
	if Binary(snapshot.content) {
		return File{}, fmt.Errorf("%w: binary file is read-only and content is not returned", core.ErrInvalid)
	}
	return File{Path: normalized, Content: snapshot.content, ETag: etag(snapshot.content), Size: snapshot.size, Modified: snapshot.modified}, nil
}

// Save performs create-only when expectedETag is empty and compare-and-swap for
// existing files otherwise. Linux exchanges the staged and destination names,
// verifies the exact displaced file, and rolls back a commit-boundary conflict.
func (s *Service) Save(relative string, content []byte, expectedETag string) (File, error) {
	if int64(len(content)) > s.maxFileBytes || Binary(content) {
		return File{}, fmt.Errorf("%w: invalid or oversized text content", core.ErrInvalid)
	}
	_, normalized, err := s.clean(relative)
	if err != nil {
		return File{}, err
	}
	if Sensitive(normalized) {
		return File{}, fmt.Errorf("%w: sensitive path is unavailable", core.ErrForbidden)
	}
	s.commitMu.Lock()
	defer s.commitMu.Unlock()
	snapshot, err := s.filesystem.saveCAS(normalized, content, expectedETag, s.maxFileBytes, s.saveHooks)
	if err != nil {
		return File{}, err
	}
	if Binary(snapshot.content) {
		return File{}, fmt.Errorf("%w: committed file is unexpectedly binary", core.ErrInvalid)
	}
	return File{Path: normalized, Content: snapshot.content, ETag: etag(snapshot.content), Size: snapshot.size, Modified: snapshot.modified}, nil
}

func (s *Service) Tree() ([]Entry, error) {
	return s.filesystem.tree(context.Background(), s.maxEntries, true)
}

func (s *Service) Search(ctx context.Context, query string, limit int) ([]SearchMatch, error) {
	query = strings.TrimSpace(query)
	if query == "" || len(query) > 256 {
		return nil, fmt.Errorf("%w: query must be 1-256 characters", core.ErrInvalid)
	}
	if limit < 1 || limit > 500 {
		return nil, fmt.Errorf("%w: result limit must be 1-500", core.ErrInvalid)
	}
	searchCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := searchCtx.Err(); err != nil {
		return nil, err
	}
	entries, err := s.filesystem.tree(searchCtx, s.maxEntries, false)
	if err != nil {
		return nil, err
	}
	matches := make([]SearchMatch, 0, limit)
	queryBytes := []byte(query)
	var scannedBytes int64
	var outputBytes int64
	for _, entry := range entries {
		if err := searchCtx.Err(); err != nil {
			return nil, err
		}
		if entry.Directory || entry.Sensitive || entry.Binary || entry.Size > s.maxFileBytes || entry.Path == ".codex" || strings.HasPrefix(entry.Path, ".codex/") {
			continue
		}
		snapshot, err := s.filesystem.read(entry.Path, s.maxFileBytes)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if Binary(snapshot.content) {
			continue
		}
		scannedBytes += int64(len(snapshot.content))
		if scannedBytes > s.maxSearchScan {
			return nil, errors.New("search input limit exceeded")
		}
		lines := bytes.Split(snapshot.content, []byte{'\n'})
		for lineIndex, rawLine := range lines {
			if err := searchCtx.Err(); err != nil {
				return nil, err
			}
			column := bytes.Index(rawLine, queryBytes)
			if column < 0 {
				continue
			}
			line := strings.TrimSuffix(string(rawLine), "\r")
			outputBytes += int64(len(entry.Path) + len(line) + 64)
			if outputBytes > s.maxSearchBytes {
				return nil, errors.New("search output limit exceeded")
			}
			matches = append(matches, SearchMatch{Path: entry.Path, Line: lineIndex + 1, Column: column + 1, Text: line})
			if len(matches) == limit {
				return matches, nil
			}
		}
	}
	return matches, nil
}

func (s *Service) clean(relative string) (string, string, error) {
	native := filepath.FromSlash(relative)
	if relative == "" || strings.ContainsRune(relative, 0) || strings.Contains(relative, "\\") || !filepath.IsLocal(native) {
		return "", "", fmt.Errorf("%w: invalid path", core.ErrInvalid)
	}
	normalized := filepath.ToSlash(filepath.Clean(native))
	if normalized == "." || normalized == ".." || strings.HasPrefix(normalized, "../") {
		return "", "", fmt.Errorf("%w: path escapes workspace", core.ErrInvalid)
	}
	full := filepath.Join(s.root, filepath.FromSlash(normalized))
	rel, err := filepath.Rel(s.root, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", "", fmt.Errorf("%w: path escapes workspace", core.ErrInvalid)
	}
	return full, normalized, nil
}

func Sensitive(relative string) bool {
	path := strings.ToLower(filepath.ToSlash(relative))
	base := strings.ToLower(filepath.Base(path))
	if strings.HasPrefix(base, ".env") || strings.HasPrefix(base, ".codex-mobile-save-") || base == "auth.json" || base == ".git-credentials" || base == "credentials" || base == ".npmrc" || base == ".pypirc" || base == "id_rsa" || base == "id_ed25519" {
		return true
	}
	if strings.HasSuffix(base, ".pem") || strings.HasSuffix(base, ".key") || strings.HasSuffix(base, ".p8") || strings.HasSuffix(base, ".p12") {
		return true
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "secrets" || segment == ".ssh" || segment == ".aws" || segment == ".gnupg" || segment == ".codex-mobile" {
			return true
		}
	}
	return false
}

func Binary(content []byte) bool {
	if len(content) > 8192 {
		content = content[:8192]
	}
	return bytes.IndexByte(content, 0) >= 0
}

func etag(content []byte) string {
	sum := sha256.Sum256(content)
	return `"sha256-` + hex.EncodeToString(sum[:]) + `"`
}
