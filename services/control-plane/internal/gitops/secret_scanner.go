package gitops

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	workspacefiles "github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/files"
)

const (
	minimumScannableSecretBytes = 8
	maximumScannerSecrets       = 50
	maximumScannerSecretBytes   = 64 << 10
	maximumScannerPatterns      = 1024
	maximumScannerPatternBytes  = 32 << 10
	maximumScannerDerivedBytes  = 2 << 20
	maximumScannerFiles         = 5000
	maximumScannerObjects       = 10000
	maximumScannerFileBytes     = 4 << 20
	maximumScannerTotalBytes    = 64 << 20
	maximumGitBlobListBytes     = 8 << 20
)

var (
	ErrSecretDetected = errors.New("content contains a granted runtime secret")
	ErrSecretScan     = errors.New("content could not be safely scanned for granted runtime secrets")
)

var secretDiagnosticReplacement = []byte("[REDACTED]")

// ValueSecretScanner blocks exact granted values and common transport
// encodings. It deliberately ignores dangerously short values rather than
// matching ordinary source text. Call Close as soon as the Git operation ends.
type ValueSecretScanner struct {
	mu       sync.Mutex
	patterns [][]byte
	gitPath  string
	closed   bool
}

func NewValueSecretScanner(values ...[]byte) (*ValueSecretScanner, error) {
	if len(values) > maximumScannerSecrets {
		return nil, ErrSecretScan
	}
	patterns := make([][]byte, 0, len(values)*8)
	buckets := make(map[[32]byte][]int)
	totalValues, totalPatterns := 0, 0
	add := func(pattern []byte) error {
		defer clear(pattern)
		if len(pattern) < minimumScannableSecretBytes {
			return nil
		}
		if len(pattern) > maximumScannerPatternBytes || len(patterns) >= maximumScannerPatterns || totalPatterns+len(pattern) > maximumScannerDerivedBytes {
			return ErrSecretScan
		}
		hash := sha256.Sum256(pattern)
		for _, index := range buckets[hash] {
			if bytes.Equal(patterns[index], pattern) {
				return nil
			}
		}
		patterns = append(patterns, bytes.Clone(pattern))
		buckets[hash] = append(buckets[hash], len(patterns)-1)
		totalPatterns += len(pattern)
		return nil
	}
	fail := func(err error) (*ValueSecretScanner, error) {
		for _, pattern := range patterns {
			clear(pattern)
		}
		return nil, err
	}
	for _, value := range values {
		if len(value) == 0 || len(value) > 8192 || bytes.IndexByte(value, 0) >= 0 {
			return fail(ErrSecretScan)
		}
		totalValues += len(value)
		if totalValues > maximumScannerSecretBytes {
			return fail(ErrSecretScan)
		}
		if len(value) < minimumScannableSecretBytes {
			continue
		}
		forms := encodedSecretForms(value)
		for _, form := range forms {
			if err := add(form); err != nil {
				for _, remaining := range forms {
					clear(remaining)
				}
				return fail(err)
			}
		}
	}
	sort.Slice(patterns, func(i, j int) bool {
		if len(patterns[i]) == len(patterns[j]) {
			return bytes.Compare(patterns[i], patterns[j]) < 0
		}
		return len(patterns[i]) > len(patterns[j])
	})
	gitPath, err := TrustedExecutable()
	if err != nil {
		return fail(ErrSecretScan)
	}
	return &ValueSecretScanner{patterns: patterns, gitPath: gitPath}, nil
}

func encodedSecretForms(value []byte) [][]byte {
	forms := make([][]byte, 0, 16)
	forms = append(forms, bytes.Clone(value))
	lowerHex := make([]byte, hex.EncodedLen(len(value)))
	hex.Encode(lowerHex, value)
	forms = append(forms, lowerHex, bytes.ToUpper(lowerHex))
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		encoded := make([]byte, encoding.EncodedLen(len(value)))
		encoding.Encode(encoded, value)
		forms = append(forms, encoded)
		if encoding == base64.StdEncoding {
			for _, width := range []int{64, 76} {
				forms = append(forms, wrapEncoded(encoded, width, []byte{'\n'}), wrapEncoded(encoded, width, []byte{'\r', '\n'}))
			}
		}
	}
	queryEncoded := []byte(url.QueryEscape(string(value)))
	pathEncoded := []byte(url.PathEscape(string(value)))
	forms = append(forms, queryEncoded, lowerPercentHex(queryEncoded), pathEncoded, lowerPercentHex(pathEncoded))
	return forms
}

func wrapEncoded(value []byte, width int, separator []byte) []byte {
	if width <= 0 || len(value) <= width {
		return bytes.Clone(value)
	}
	lines := (len(value) - 1) / width
	result := make([]byte, 0, len(value)+lines*len(separator))
	for offset := 0; offset < len(value); offset += width {
		if offset != 0 {
			result = append(result, separator...)
		}
		end := min(offset+width, len(value))
		result = append(result, value[offset:end]...)
	}
	return result
}

func lowerPercentHex(value []byte) []byte {
	result := bytes.Clone(value)
	for index := 0; index+2 < len(result); index++ {
		if result[index] != '%' {
			continue
		}
		for offset := 1; offset <= 2; offset++ {
			if result[index+offset] >= 'A' && result[index+offset] <= 'F' {
				result[index+offset] += 'a' - 'A'
			}
		}
		index += 2
	}
	return result
}

func (s *ValueSecretScanner) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	for _, pattern := range s.patterns {
		clear(pattern)
	}
	s.patterns = nil
	s.closed = true
}

// Redact removes every derived active-grant form from bounded diagnostics.
// The returned buffer is independent; callers should clear it after use.
func (s *ValueSecretScanner) Redact(input []byte) []byte {
	if s == nil || len(input) == 0 {
		return bytes.Clone(input)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return bytes.Clone(secretDiagnosticReplacement)
	}
	output := bytes.Clone(input)
	for _, pattern := range s.patterns {
		if !bytes.Contains(output, pattern) {
			continue
		}
		replaced := bytes.ReplaceAll(output, pattern, secretDiagnosticReplacement)
		clear(output)
		output = replaced
	}
	return output
}

func (s *ValueSecretScanner) Scan(ctx context.Context, root string, paths []string) error {
	if s == nil {
		return ErrSecretScan
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrSecretScan
	}
	if len(s.patterns) == 0 {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return ErrSecretScan
	}
	if len(paths) > 0 {
		return s.scanWorktree(ctx, absRoot, paths)
	}
	return s.scanIndex(ctx, absRoot)
}

// ScanBytes checks bounded metadata supplied to a native Git mutation. It is
// used for filenames, branch names, author identities, and commit messages in
// addition to repository content.
func (s *ValueSecretScanner) ScanBytes(values ...[]byte) error {
	if s == nil {
		return ErrSecretScan
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrSecretScan
	}
	total := 0
	for _, value := range values {
		total += len(value)
		if total > maximumScannerFileBytes {
			return ErrSecretScan
		}
		if err := s.match(value); err != nil {
			return err
		}
	}
	return nil
}

// ScanTree scans the exact immutable tree prepared for a stage or commit. Git
// tree records are also checked so filenames cannot carry a granted value.
func (s *ValueSecretScanner) ScanTree(ctx context.Context, root, treeID string) error {
	if s == nil {
		return ErrSecretScan
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || !validGitObjectID([]byte(treeID)) {
		return ErrSecretScan
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return ErrSecretScan
	}
	return s.scanTree(ctx, absRoot, treeID)
}

// ScanReachable scans every object reachable from tip that is not already
// reachable from one of the authoritative remote object IDs. Push uses the
// exact scanned tip rather than a movable branch name.
func (s *ValueSecretScanner) ScanReachable(ctx context.Context, root, tip string, remoteObjectIDs []string) error {
	if s == nil {
		return ErrSecretScan
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || !validGitObjectID([]byte(tip)) || len(remoteObjectIDs) > maximumScannerObjects {
		return ErrSecretScan
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return ErrSecretScan
	}
	revisions := make([]byte, 0, (len(remoteObjectIDs)+1)*66)
	revisions = append(revisions, tip...)
	revisions = append(revisions, '\n')
	for _, objectID := range remoteObjectIDs {
		if !validGitObjectID([]byte(objectID)) {
			clear(revisions)
			return ErrSecretScan
		}
		revisions = append(revisions, '^')
		revisions = append(revisions, objectID...)
		revisions = append(revisions, '\n')
	}
	listing, err := s.runGitInput(ctx, absRoot, maximumGitBlobListBytes, revisions, "rev-list", "--objects", "--no-object-names", "--stdin")
	clear(revisions)
	if err != nil {
		return ErrSecretScan
	}
	defer clear(listing)
	objectIDs := bytes.Fields(listing)
	if len(objectIDs) > maximumScannerObjects {
		return ErrSecretScan
	}
	total := 0
	seen := make(map[string]struct{}, len(objectIDs))
	for _, rawObjectID := range objectIDs {
		if !validGitObjectID(rawObjectID) {
			return ErrSecretScan
		}
		objectID := string(rawObjectID)
		if _, duplicate := seen[objectID]; duplicate {
			continue
		}
		seen[objectID] = struct{}{}
		objectType, typeErr := s.runGit(ctx, absRoot, 32, "cat-file", "-t", objectID)
		if typeErr != nil {
			return ErrSecretScan
		}
		typeName := strings.TrimSpace(string(objectType))
		clear(objectType)
		if typeName != "blob" && typeName != "tree" && typeName != "commit" && typeName != "tag" {
			return ErrSecretScan
		}
		content, contentErr := s.runGit(ctx, absRoot, maximumScannerFileBytes, "cat-file", typeName, objectID)
		if contentErr != nil {
			return ErrSecretScan
		}
		total += len(content)
		if total > maximumScannerTotalBytes {
			clear(content)
			return ErrSecretScan
		}
		if typeName == "tree" {
			if err := s.validateRawTree(content, len(objectID)/2); err != nil {
				clear(content)
				return err
			}
		}
		matchErr := s.match(content)
		clear(content)
		if matchErr != nil {
			return matchErr
		}
	}
	return nil
}

func (s *ValueSecretScanner) scanWorktree(ctx context.Context, root string, paths []string) error {
	files, total := 0, int64(0)
	for _, path := range paths {
		if path == "" || filepath.IsAbs(path) || strings.Contains(path, "\\") || strings.ContainsRune(path, 0) {
			return ErrSecretScan
		}
		clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(path)))
		if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || sensitiveScannerPath(clean) {
			return ErrSecretScan
		}
		if err := s.match([]byte(clean)); err != nil {
			return err
		}
		full := filepath.Join(root, filepath.FromSlash(clean))
		info, err := os.Lstat(full)
		if errors.Is(err, os.ErrNotExist) {
			continue // A staged deletion has no content to disclose.
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return ErrSecretScan
		}
		if info.Mode().IsRegular() {
			if err := s.scanWorktreeFile(ctx, root, clean, &files, &total); err != nil {
				return err
			}
			continue
		}
		if !info.IsDir() {
			return ErrSecretScan
		}
		err = filepath.WalkDir(full, func(candidate string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return ErrSecretScan
			}
			relative, err := filepath.Rel(root, candidate)
			if err != nil {
				return ErrSecretScan
			}
			relative = filepath.ToSlash(relative)
			if candidate == full {
				return nil
			}
			if sensitiveScannerPath(relative) {
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return ErrSecretScan
			}
			if err := s.match([]byte(relative)); err != nil {
				return err
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return ErrSecretScan
			}
			if entry.IsDir() {
				return nil
			}
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() {
				return ErrSecretScan
			}
			return s.scanWorktreeFile(ctx, root, relative, &files, &total)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *ValueSecretScanner) scanWorktreeFile(ctx context.Context, root, relative string, files *int, total *int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	(*files)++
	if *files > maximumScannerFiles {
		return ErrSecretScan
	}
	content, err := readScannerFile(root, relative, maximumScannerFileBytes)
	if err != nil {
		return ErrSecretScan
	}
	defer clear(content)
	*total += int64(len(content))
	if *total > maximumScannerTotalBytes {
		return ErrSecretScan
	}
	return s.match(content)
}

func (s *ValueSecretScanner) scanIndex(ctx context.Context, root string) error {
	listing, err := s.runGit(ctx, root, maximumGitBlobListBytes, "ls-files", "--stage", "-z")
	if err != nil {
		return ErrSecretScan
	}
	defer clear(listing)
	unique := make(map[string]struct{})
	for _, record := range bytes.Split(listing, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		metadata, path, ok := bytes.Cut(record, []byte{'\t'})
		fields := bytes.Fields(metadata)
		if !ok || len(fields) != 3 || string(fields[2]) != "0" || !validGitObjectID(fields[1]) {
			return ErrSecretScan
		}
		if len(path) == 0 || sensitiveScannerPath(string(path)) {
			return ErrSecretScan
		}
		if err := s.match(path); err != nil {
			return err
		}
		if string(fields[0]) == "160000" {
			continue // A gitlink contains only a commit object ID; .gitmodules is scanned separately.
		}
		if string(fields[0]) != "100644" && string(fields[0]) != "100755" && string(fields[0]) != "120000" {
			return ErrSecretScan
		}
		unique[string(fields[1])] = struct{}{}
		if len(unique) > maximumScannerFiles {
			return ErrSecretScan
		}
	}
	total := 0
	for objectID := range unique {
		if err := ctx.Err(); err != nil {
			return err
		}
		content, err := s.runGit(ctx, root, maximumScannerFileBytes, "cat-file", "blob", objectID)
		if err != nil {
			return ErrSecretScan
		}
		total += len(content)
		if total > maximumScannerTotalBytes {
			clear(content)
			return ErrSecretScan
		}
		matchErr := s.match(content)
		clear(content)
		if matchErr != nil {
			return matchErr
		}
	}
	return nil
}

func (s *ValueSecretScanner) scanTree(ctx context.Context, root, treeID string) error {
	listing, err := s.runGit(ctx, root, maximumGitBlobListBytes, "ls-tree", "-r", "-z", "--full-tree", treeID)
	if err != nil {
		return ErrSecretScan
	}
	defer clear(listing)
	unique := make(map[string]struct{})
	for _, record := range bytes.Split(listing, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		metadata, path, ok := bytes.Cut(record, []byte{'\t'})
		fields := bytes.Fields(metadata)
		if !ok || len(fields) != 3 || !validGitObjectID(fields[2]) || len(path) == 0 {
			return ErrSecretScan
		}
		if err := s.match(path); err != nil {
			return err
		}
		mode, objectType := string(fields[0]), string(fields[1])
		if mode == "160000" && objectType == "commit" {
			continue
		}
		if (mode != "100644" && mode != "100755" && mode != "120000") || objectType != "blob" {
			return ErrSecretScan
		}
		unique[string(fields[2])] = struct{}{}
		if len(unique) > maximumScannerFiles {
			return ErrSecretScan
		}
	}
	total := 0
	for objectID := range unique {
		if err := ctx.Err(); err != nil {
			return err
		}
		content, err := s.runGit(ctx, root, maximumScannerFileBytes, "cat-file", "blob", objectID)
		if err != nil {
			return ErrSecretScan
		}
		total += len(content)
		if total > maximumScannerTotalBytes {
			clear(content)
			return ErrSecretScan
		}
		matchErr := s.match(content)
		clear(content)
		if matchErr != nil {
			return matchErr
		}
	}
	return nil
}

func (s *ValueSecretScanner) validateRawTree(content []byte, objectIDBytes int) error {
	if objectIDBytes != 20 && objectIDBytes != 32 {
		return ErrSecretScan
	}
	for len(content) > 0 {
		space := bytes.IndexByte(content, ' ')
		if space < 1 {
			return ErrSecretScan
		}
		mode := content[:space]
		content = content[space+1:]
		nul := bytes.IndexByte(content, 0)
		if nul < 1 || len(content) < nul+1+objectIDBytes {
			return ErrSecretScan
		}
		name := content[:nul]
		if bytes.ContainsAny(name, "/\\") || sensitiveScannerPath(string(name)) {
			return ErrSecretScan
		}
		if err := s.match(name); err != nil {
			return err
		}
		modeText := string(mode)
		if modeText != "40000" && modeText != "040000" && modeText != "100644" && modeText != "100755" && modeText != "120000" && modeText != "160000" {
			return ErrSecretScan
		}
		content = content[nul+1+objectIDBytes:]
	}
	return nil
}

func (s *ValueSecretScanner) runGit(ctx context.Context, root string, limit int, args ...string) ([]byte, error) {
	return s.runGitInput(ctx, root, limit, nil, args...)
}

func (s *ValueSecretScanner) runGitInput(ctx context.Context, root string, limit int, input []byte, args ...string) ([]byte, error) {
	command, cancel, err := newGitCommand(ctx, s.gitPath, root, gitEnv(), args...)
	if err != nil {
		return nil, ErrSecretScan
	}
	defer cancel()
	if input != nil {
		command.Stdin = bytes.NewReader(input)
	} else {
		command.Stdin = strings.NewReader("")
	}
	var output cappedBuffer
	output.max = limit
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil || output.err != nil {
		clear(output.Bytes())
		return nil, ErrSecretScan
	}
	result := bytes.Clone(output.Bytes())
	clear(output.Bytes())
	return result, nil
}

func (s *ValueSecretScanner) match(content []byte) error {
	for _, pattern := range s.patterns {
		if bytes.Contains(content, pattern) {
			return ErrSecretDetected
		}
	}
	return nil
}

func validGitObjectID(value []byte) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func sensitiveScannerPath(path string) bool {
	if workspacefiles.Sensitive(path) {
		return true
	}
	for _, segment := range strings.Split(strings.ToLower(filepath.ToSlash(path)), "/") {
		if segment == ".git" || segment == ".codex-mobile" || segment == ".codex" {
			return true
		}
	}
	return false
}
