package attachments

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	MaximumCount      = 4
	MaximumFileBytes  = 5 << 20
	MaximumTotalBytes = 8 << 20
	StagingTTL        = 30 * time.Minute

	// DefaultRoot is a dedicated, noexec tmpfs mounted by the Coder template.
	// It is intentionally outside the repository and all persistent volumes.
	DefaultRoot = "/codex-mobile-attachments"
)

type Upload struct {
	MediaType string `json:"media_type"`
	Content   []byte `json:"content_base64"`
}

type Staged struct {
	ID        string    `json:"id"`
	Path      string    `json:"path"`
	MediaType string    `json:"media_type"`
	SizeBytes int       `json:"size_bytes"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Stager struct {
	root   string
	random io.Reader
	now    func() time.Time
}

func NewStager(root string, random io.Reader, now func() time.Time) (*Stager, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("attachment staging root is required")
	}
	absolute, err := filepath.Abs(root)
	if err != nil || !filepath.IsAbs(absolute) {
		return nil, errors.New("attachment staging root must be absolute")
	}
	if random == nil {
		random = rand.Reader
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Stager{root: filepath.Clean(absolute), random: random, now: now}, nil
}

func Validate(uploads []Upload) error {
	if len(uploads) < 1 || len(uploads) > MaximumCount {
		return fmt.Errorf("attachment count must be between one and %d", MaximumCount)
	}
	total := 0
	for index := range uploads {
		upload := &uploads[index]
		if len(upload.Content) < 1 || len(upload.Content) > MaximumFileBytes {
			return fmt.Errorf("attachment %d exceeds the file size limit", index+1)
		}
		total += len(upload.Content)
		if total > MaximumTotalBytes {
			return errors.New("attachments exceed the total size limit")
		}
		if _, err := canonicalExtension(upload.MediaType, upload.Content); err != nil {
			return fmt.Errorf("attachment %d: %w", index+1, err)
		}
	}
	return nil
}

func (s *Stager) Stage(ctx context.Context, uploads []Upload) ([]Staged, error) {
	if err := Validate(uploads); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.ensureRoot(); err != nil {
		return nil, err
	}
	if err := s.CleanupExpired(ctx); err != nil {
		return nil, err
	}

	expiresAt := s.now().UTC().Add(StagingTTL).Truncate(time.Second)
	batchRandom, err := s.randomID(18)
	if err != nil {
		return nil, err
	}
	batchName := "stage-" + strconv.FormatInt(expiresAt.Unix(), 10) + "-" + batchRandom
	root, err := os.OpenRoot(s.root)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if err := root.Mkdir(batchName, 0o700); err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = root.RemoveAll(batchName)
		}
	}()

	result := make([]Staged, 0, len(uploads))
	for index := range uploads {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		upload := &uploads[index]
		extension, err := canonicalExtension(upload.MediaType, upload.Content)
		if err != nil {
			return nil, err
		}
		fileRandom, err := s.randomID(18)
		if err != nil {
			return nil, err
		}
		id := "att_" + fileRandom
		name := batchName + "/" + id + "." + extension
		file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, err
		}
		writeErr := writeAll(ctx, file, upload.Content)
		if writeErr == nil {
			writeErr = file.Sync()
		}
		closeErr := file.Close()
		if writeErr != nil {
			return nil, writeErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		result = append(result, Staged{
			ID: id, Path: filepath.ToSlash(filepath.Join(s.root, filepath.FromSlash(name))),
			MediaType: upload.MediaType, SizeBytes: len(upload.Content), ExpiresAt: expiresAt,
		})
	}
	committed = true
	return result, nil
}

func (s *Stager) CleanupExpired(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.ensureRoot(); err != nil {
		return err
	}
	root, err := os.OpenRoot(s.root)
	if err != nil {
		return err
	}
	defer root.Close()
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, readErr := directory.ReadDir(MaximumCount * 1024)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	now := s.now().UTC()
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		expiresAt, ok := expiryFromStageName(entry.Name())
		if !ok || now.Before(expiresAt) {
			continue
		}
		if err := root.RemoveAll(entry.Name()); err != nil {
			return err
		}
	}
	return nil
}

func (s *Stager) ensureRoot() error {
	if err := os.MkdirAll(s.root, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(s.root)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("attachment staging root is not a directory")
	}
	return os.Chmod(s.root, 0o700)
}

func (s *Stager) randomID(size int) (string, error) {
	value := make([]byte, size)
	if _, err := io.ReadFull(s.random, value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func expiryFromStageName(name string) (time.Time, bool) {
	if !strings.HasPrefix(name, "stage-") {
		return time.Time{}, false
	}
	remainder := strings.TrimPrefix(name, "stage-")
	separator := strings.IndexByte(remainder, '-')
	if separator < 1 || len(remainder[separator+1:]) < 16 {
		return time.Time{}, false
	}
	unix, err := strconv.ParseInt(remainder[:separator], 10, 64)
	if err != nil || unix < 1 {
		return time.Time{}, false
	}
	return time.Unix(unix, 0).UTC(), true
}

func canonicalExtension(mediaType string, content []byte) (string, error) {
	switch mediaType {
	case "image/png":
		if len(content) >= 8 && string(content[:8]) == "\x89PNG\r\n\x1a\n" {
			return "png", nil
		}
	case "image/jpeg":
		if len(content) >= 3 && content[0] == 0xff && content[1] == 0xd8 && content[2] == 0xff {
			return "jpg", nil
		}
	case "image/heic":
		if validHEIC(content) {
			return "heic", nil
		}
	case "application/pdf":
		if len(content) >= 5 && string(content[:5]) == "%PDF-" {
			return "pdf", nil
		}
	case "application/json":
		if textContent(content) && json.Valid(content) {
			return "json", nil
		}
	case "text/markdown":
		if textContent(content) {
			return "md", nil
		}
	case "text/csv":
		if textContent(content) {
			return "csv", nil
		}
	case "text/plain":
		if textContent(content) {
			return "txt", nil
		}
	default:
		return "", errors.New("media type is not allowed")
	}
	return "", errors.New("content does not match its declared media type")
}

func validHEIC(content []byte) bool {
	if len(content) < 12 || string(content[4:8]) != "ftyp" {
		return false
	}
	boxSize := int(binary.BigEndian.Uint32(content[:4]))
	if boxSize < 12 || boxSize > len(content) {
		return false
	}
	for offset := 8; offset+4 <= boxSize; offset += 4 {
		switch string(content[offset : offset+4]) {
		case "heic", "heix", "hevc", "hevx", "mif1":
			return true
		}
	}
	return false
}

func textContent(content []byte) bool {
	return utf8.Valid(content) && !strings.ContainsRune(string(content), '\x00')
}

func writeAll(ctx context.Context, destination io.Writer, content []byte) error {
	for len(content) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		chunk := min(len(content), 64<<10)
		written, err := destination.Write(content[:chunk])
		if err != nil {
			return err
		}
		if written <= 0 || written > chunk {
			return io.ErrShortWrite
		}
		content = content[written:]
	}
	return nil
}
