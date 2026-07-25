package checkpoint

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	workspacefiles "github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/files"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/gitops"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/workspacehelper"
)

const (
	metadataVersion          = 1
	DefaultRetention         = 30 * 24 * time.Hour
	DefaultMaxWorkspaceBytes = 512 << 20
	DefaultMaxCheckpoints    = 128
	maxMetadataBytes         = workspacehelper.MaxCheckpointManifestBytes
)

type Runner interface {
	RunHelper(context.Context, string, []byte) ([]byte, error)
}

type Config struct {
	Root              string
	Retention         time.Duration
	MaxWorkspaceBytes int64
	MaxCheckpoints    int
}

type Metadata struct {
	Version          int       `json:"version"`
	ID               string    `json:"id"`
	WorkspaceID      string    `json:"workspace_id"`
	Reason           string    `json:"reason"`
	CreatedAt        time.Time `json:"created_at"`
	ArchiveSHA256    string    `json:"archive_sha256"`
	CompressedBytes  int64     `json:"compressed_bytes"`
	ExpandedBytes    int64     `json:"expanded_bytes"`
	FileCount        int       `json:"file_count"`
	DeletedCount     int       `json:"deleted_count"`
	OmittedSensitive int       `json:"omitted_sensitive"`
	OmittedUnsafe    int       `json:"omitted_unsafe"`
	Head             string    `json:"head,omitempty"`
}

type Service struct {
	root              string
	retention         time.Duration
	maxWorkspaceBytes int64
	maxCheckpoints    int
	runner            Runner
	random            io.Reader
	now               func() time.Time
	mu                sync.Mutex
	operationMu       sync.Mutex
	operations        map[string]*operationGate
}

type operationGate struct {
	mu   sync.Mutex
	refs int
}

func New(cfg Config, runner Runner) (*Service, error) {
	if runner == nil {
		return nil, errors.New("checkpoint helper runner is required")
	}
	if strings.TrimSpace(cfg.Root) == "" {
		return nil, errors.New("checkpoint root is required")
	}
	if cfg.Retention == 0 {
		cfg.Retention = DefaultRetention
	}
	if cfg.MaxWorkspaceBytes == 0 {
		cfg.MaxWorkspaceBytes = DefaultMaxWorkspaceBytes
	}
	if cfg.MaxCheckpoints == 0 {
		cfg.MaxCheckpoints = DefaultMaxCheckpoints
	}
	if cfg.Retention < time.Hour || cfg.Retention > 365*24*time.Hour ||
		cfg.MaxWorkspaceBytes < workspacehelper.MaxCheckpointArchiveBytes || cfg.MaxWorkspaceBytes > 100<<30 ||
		cfg.MaxCheckpoints < 1 || cfg.MaxCheckpoints > 10_000 {
		return nil, errors.New("invalid checkpoint retention or quota")
	}
	abs, err := filepath.Abs(cfg.Root)
	if err != nil {
		return nil, fmt.Errorf("resolve checkpoint root: %w", err)
	}
	if info, err := os.Lstat(abs); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("checkpoint root cannot be a symbolic link")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect checkpoint root: %w", err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("create checkpoint root: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("resolve checkpoint root links: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return nil, errors.New("checkpoint root must be a directory")
	}
	if err := os.Chmod(resolved, 0o700); err != nil {
		return nil, fmt.Errorf("protect checkpoint root: %w", err)
	}
	return &Service{
		root: filepath.Clean(resolved), retention: cfg.Retention,
		maxWorkspaceBytes: cfg.MaxWorkspaceBytes, maxCheckpoints: cfg.MaxCheckpoints,
		runner: runner, random: rand.Reader, now: func() time.Time { return time.Now().UTC() },
		operations: make(map[string]*operationGate),
	}, nil
}

// Create derives live Git risk inside the workspace. Clean work returns an
// empty checkpoint ID. Dirty or unpushed work is exported by the fixed helper
// protocol, revalidated, and atomically persisted outside the workspace.
func (s *Service) Create(ctx context.Context, workspaceID, providerResourceID, reason string) (string, bool, bool, error) {
	if !safeWorkspaceID.MatchString(workspaceID) {
		return "", false, false, fmt.Errorf("%w: invalid checkpoint request", core.ErrInvalid)
	}
	releaseOperation := s.acquireOperation(workspaceID)
	defer releaseOperation()
	return s.create(ctx, workspaceID, providerResourceID, reason, false, nil)
}

// CreateRequired persists a recovery boundary even when the checkout is
// currently clean. An empty manifest remains useful proof of the exact
// pre-operation state and gives every destructive action a visible token.
func (s *Service) CreateRequired(ctx context.Context, workspaceID, providerResourceID, reason string) (string, bool, bool, error) {
	if !safeWorkspaceID.MatchString(workspaceID) {
		return "", false, false, fmt.Errorf("%w: invalid checkpoint request", core.ErrInvalid)
	}
	releaseOperation := s.acquireOperation(workspaceID)
	defer releaseOperation()
	return s.createRequired(ctx, workspaceID, providerResourceID, reason)
}

func (s *Service) createRequired(ctx context.Context, workspaceID, providerResourceID, reason string) (string, bool, bool, error) {
	return s.createRequiredPaths(ctx, workspaceID, providerResourceID, reason, nil)
}

func (s *Service) createRequiredPaths(ctx context.Context, workspaceID, providerResourceID, reason string, paths []string) (string, bool, bool, error) {
	id, dirty, unpushed, err := s.create(ctx, workspaceID, providerResourceID, reason, true, paths)
	if err == nil && id == "" {
		return "", dirty, unpushed, errors.New("required checkpoint was not persisted")
	}
	return id, dirty, unpushed, err
}

func (s *Service) create(ctx context.Context, workspaceID, providerResourceID, reason string, force bool, paths []string) (string, bool, bool, error) {
	if ctx == nil || !safeWorkspaceID.MatchString(workspaceID) || !safeProviderID.MatchString(providerResourceID) || !safeReason.MatchString(reason) {
		return "", false, false, fmt.Errorf("%w: invalid checkpoint request", core.ErrInvalid)
	}
	request, err := json.Marshal(workspacehelper.Request{
		Version: workspacehelper.Version, Operation: workspacehelper.OpCheckpointExport,
		CheckpointWorkspaceID: workspaceID, CheckpointForce: force, CheckpointSeal: checkpointSealsRuntime(reason), Paths: append([]string(nil), paths...),
	})
	if err != nil {
		return "", false, false, err
	}
	data, err := s.runner.RunHelper(ctx, providerResourceID, request)
	if err != nil {
		return "", false, false, fmt.Errorf("run checkpoint helper: %w", err)
	}
	response, err := workspacehelper.DecodeResponse(data)
	if err != nil {
		return "", false, false, fmt.Errorf("decode checkpoint helper: %w", err)
	}
	if response.GitStatus == nil {
		return "", false, false, errors.New("checkpoint helper omitted live Git status")
	}
	dirty, unpushed := response.GitStatus.Dirty, response.GitStatus.Unpushed
	if !dirty && !unpushed && !force {
		if response.Checkpoint != nil {
			return "", dirty, unpushed, errors.New("checkpoint helper exported a clean workspace")
		}
		return "", dirty, unpushed, nil
	}
	if response.Checkpoint == nil {
		return "", dirty, unpushed, errors.New("checkpoint helper omitted recovery archive")
	}
	export := response.Checkpoint
	if base64.StdEncoding.DecodedLen(len(export.ArchiveBase64)) > workspacehelper.MaxCheckpointArchiveBytes {
		return "", dirty, unpushed, errors.New("checkpoint archive exceeds size limit")
	}
	archive, err := base64.StdEncoding.DecodeString(export.ArchiveBase64)
	if err != nil || len(archive) == 0 || len(archive) > workspacehelper.MaxCheckpointArchiveBytes {
		return "", dirty, unpushed, errors.New("checkpoint archive encoding is invalid")
	}
	digest := sha256.Sum256(archive)
	wantDigest, err := hex.DecodeString(export.ArchiveSHA256)
	if err != nil || len(wantDigest) != sha256.Size || subtle.ConstantTimeCompare(digest[:], wantDigest) != 1 {
		return "", dirty, unpushed, errors.New("checkpoint archive integrity check failed")
	}
	manifest, summary, err := validateArchive(archive)
	if err != nil {
		return "", dirty, unpushed, fmt.Errorf("validate checkpoint archive: %w", err)
	}
	if manifest.WorkspaceID != workspaceID || manifest.Head != export.Head || int64(len(archive)) != export.CompressedBytes ||
		summary.expandedBytes != export.ExpandedBytes || summary.fileCount != export.FileCount ||
		manifest.OmittedSensitive != export.OmittedSensitive || manifest.OmittedUnsafe != export.OmittedUnsafe {
		return "", dirty, unpushed, errors.New("checkpoint archive summary does not match manifest")
	}

	now := s.now().UTC()
	id, err := s.checkpointID(now)
	if err != nil {
		return "", dirty, unpushed, err
	}
	metadata := Metadata{
		Version: metadataVersion, ID: id, WorkspaceID: workspaceID, Reason: reason, CreatedAt: now,
		ArchiveSHA256: hex.EncodeToString(digest[:]), CompressedBytes: int64(len(archive)),
		ExpandedBytes: summary.expandedBytes, FileCount: summary.fileCount,
		DeletedCount:     summary.deletedCount,
		OmittedSensitive: manifest.OmittedSensitive, OmittedUnsafe: manifest.OmittedUnsafe, Head: manifest.Head,
	}
	if err := s.persist(metadata, archive); err != nil {
		return "", dirty, unpushed, err
	}
	return id, dirty, unpushed, nil
}

func checkpointSealsRuntime(reason string) bool {
	return reason == "before-suspend" || reason == "before-idle-suspend" || reason == "before-delete"
}

// ListVerified reports every recorded checkpoint without treating one corrupt
// archive as proof that its neighbors are corrupt. Restore still revalidates
// the selected archive and fails closed.
func (s *Service) ListVerified(ctx context.Context, workspaceID string) ([]VerifiedMetadata, error) {
	items, err := s.List(workspaceID)
	if err != nil {
		return nil, err
	}
	result := make([]VerifiedMetadata, 0, len(items))
	for _, item := range items {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		verified := false
		archiveVersion := 0
		metadata, archive, loadErr := s.load(workspaceID, item.ID)
		if loadErr == nil {
			manifest, summary, validateErr := validateArchive(archive)
			verified = validateErr == nil && checkpointMatches(metadata, manifest, summary)
			if validateErr == nil {
				archiveVersion = manifest.Version
			}
		}
		result = append(result, VerifiedMetadata{
			Metadata: item, HashVerified: verified, ArchiveVersion: archiveVersion,
			WorkspaceRestoreSupported: verified && archiveVersion == workspacehelper.CheckpointArchiveVersion,
		})
	}
	return result, nil
}

type VerifiedMetadata struct {
	Metadata
	HashVerified              bool `json:"hash_verified"`
	ArchiveVersion            int  `json:"archive_version"`
	WorkspaceRestoreSupported bool `json:"workspace_restore_supported"`
}

// RestoreFile performs an explicit file-level restore through the same fixed
// helper boundary. It does not restore provider volumes, processes, Git index
// state, or server backups.
func (s *Service) RestoreFile(ctx context.Context, workspaceID, providerResourceID, checkpointID, path string) error {
	if ctx == nil || !safeWorkspaceID.MatchString(workspaceID) || !safeProviderID.MatchString(providerResourceID) || !safeCheckpointID.MatchString(checkpointID) {
		return fmt.Errorf("%w: invalid checkpoint restore request", core.ErrInvalid)
	}
	releaseOperation := s.acquireOperation(workspaceID)
	defer releaseOperation()
	clean, err := cleanArchivePath(path)
	if err != nil || workspacefiles.Sensitive(clean) {
		return fmt.Errorf("%w: checkpoint path is unavailable", core.ErrForbidden)
	}
	metadata, archive, err := s.load(workspaceID, checkpointID)
	if err != nil {
		return err
	}
	manifest, summary, err := validateArchive(archive)
	if err != nil {
		return fmt.Errorf("validate checkpoint before restore: %w", err)
	}
	if !checkpointMatches(metadata, manifest, summary) {
		return errors.New("checkpoint metadata and manifest do not match")
	}
	entry, content, err := archiveFile(archive, manifest, clean)
	if err != nil {
		return err
	}
	defer wipe(content)
	return s.restoreFileContent(ctx, providerResourceID, clean, entry, content)
}

func (s *Service) restoreFileContent(ctx context.Context, providerResourceID, clean string, entry workspacehelper.CheckpointEntry, content []byte) error {
	request, err := json.Marshal(workspacehelper.Request{
		Version: workspacehelper.Version, Operation: workspacehelper.OpCheckpointRestoreFile,
		Path: clean, Content: base64.StdEncoding.EncodeToString(content),
		CheckpointContentSHA256: entry.SHA256, CheckpointMode: entry.Mode,
	})
	if err != nil {
		return err
	}
	defer wipe(request)
	response, err := s.runner.RunHelper(ctx, providerResourceID, request)
	if err != nil {
		return fmt.Errorf("run checkpoint restore helper: %w", err)
	}
	if _, err := workspacehelper.DecodeResponse(response); err != nil {
		return fmt.Errorf("decode checkpoint restore helper: %w", err)
	}
	return nil
}

// RestoreFileProtected creates a mandatory pre-restore boundary, then restores
// one file from the already verified immutable checkpoint. Legacy v1 archives
// remain eligible for this narrow recovery operation.
func (s *Service) RestoreFileProtected(ctx context.Context, workspaceID, providerResourceID, checkpointID, path string, confirmed bool) (string, error) {
	if !safeWorkspaceID.MatchString(workspaceID) {
		return "", fmt.Errorf("%w: invalid checkpoint restore request", core.ErrInvalid)
	}
	releaseOperation := s.acquireOperation(workspaceID)
	defer releaseOperation()
	if !confirmed {
		return "", fmt.Errorf("%w: explicit checkpoint restore confirmation required", core.ErrPrecondition)
	}
	metadata, archive, err := s.load(workspaceID, checkpointID)
	if err != nil {
		return "", err
	}
	manifest, summary, err := validateArchive(archive)
	if err != nil || !checkpointMatches(metadata, manifest, summary) {
		if err == nil {
			err = errors.New("checkpoint metadata and archive do not match")
		}
		return "", fmt.Errorf("validate checkpoint before restore: %w", err)
	}
	clean, err := cleanArchivePath(path)
	if err != nil || workspacefiles.Sensitive(clean) {
		return "", fmt.Errorf("%w: checkpoint path is unavailable", core.ErrForbidden)
	}
	entry, content, err := archiveFile(archive, manifest, clean)
	if err != nil {
		return "", err
	}
	defer wipe(content)
	preRestoreID, _, _, err := s.createRequiredPaths(ctx, workspaceID, providerResourceID, "before-checkpoint-file-restore", []string{clean})
	if err != nil {
		return "", fmt.Errorf("checkpoint before file restore: %w", err)
	}
	if err := s.restoreFileContent(ctx, providerResourceID, clean, entry, content); err != nil {
		return preRestoreID, err
	}
	return preRestoreID, nil
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

type RestoreWorkspaceResult struct {
	RestoredCheckpointID   string
	PreRestoreCheckpointID string
	GitStatus              gitops.Status
}

// RestoreWorkspace applies the checkpoint's recorded delta over the current
// checkout. Files outside that delta are intentionally unchanged. Only v2
// archives carry the identity and deletion semantics needed for this operation.
func (s *Service) RestoreWorkspace(ctx context.Context, workspaceID, providerResourceID, checkpointID string, confirmed bool) (RestoreWorkspaceResult, error) {
	if ctx == nil || !safeWorkspaceID.MatchString(workspaceID) || !safeProviderID.MatchString(providerResourceID) || !safeCheckpointID.MatchString(checkpointID) {
		return RestoreWorkspaceResult{}, fmt.Errorf("%w: invalid checkpoint restore request", core.ErrInvalid)
	}
	releaseOperation := s.acquireOperation(workspaceID)
	defer releaseOperation()
	if !confirmed {
		return RestoreWorkspaceResult{}, fmt.Errorf("%w: explicit checkpoint restore confirmation required", core.ErrPrecondition)
	}
	metadata, archive, err := s.load(workspaceID, checkpointID)
	if err != nil {
		return RestoreWorkspaceResult{}, err
	}
	manifest, summary, err := validateArchive(archive)
	if err != nil || !checkpointMatches(metadata, manifest, summary) {
		if err == nil {
			err = errors.New("checkpoint metadata and archive do not match")
		}
		return RestoreWorkspaceResult{}, fmt.Errorf("validate checkpoint before restore: %w", err)
	}
	if manifest.Version != workspacehelper.CheckpointArchiveVersion {
		return RestoreWorkspaceResult{}, fmt.Errorf("%w: legacy checkpoint version %d supports file restore only", core.ErrPrecondition, manifest.Version)
	}
	if manifest.WorkspaceID != workspaceID {
		return RestoreWorkspaceResult{}, fmt.Errorf("%w: checkpoint workspace identity mismatch", core.ErrForbidden)
	}
	paths := make([]string, 0, len(manifest.Entries))
	for _, entry := range manifest.Entries {
		paths = append(paths, entry.Path)
	}
	preRestoreID, _, _, err := s.createRequiredPaths(ctx, workspaceID, providerResourceID, "before-checkpoint-workspace-restore", paths)
	if err != nil {
		return RestoreWorkspaceResult{}, fmt.Errorf("checkpoint before workspace restore: %w", err)
	}
	request, err := json.Marshal(workspacehelper.Request{
		Version: workspacehelper.Version, Operation: workspacehelper.OpCheckpointRestoreWorkspace,
		CheckpointWorkspaceID: workspaceID, CheckpointArchiveSHA256: metadata.ArchiveSHA256,
		CheckpointID: checkpointID, Content: base64.StdEncoding.EncodeToString(archive), Confirmed: true,
	})
	if err != nil {
		return RestoreWorkspaceResult{PreRestoreCheckpointID: preRestoreID}, err
	}
	data, err := s.runner.RunHelper(ctx, providerResourceID, request)
	for index := range request {
		request[index] = 0
	}
	if err != nil {
		return RestoreWorkspaceResult{PreRestoreCheckpointID: preRestoreID}, fmt.Errorf("run checkpoint restore helper: %w", err)
	}
	response, err := workspacehelper.DecodeResponse(data)
	if err != nil {
		return RestoreWorkspaceResult{PreRestoreCheckpointID: preRestoreID}, helperRestoreError(response, err)
	}
	if response.GitStatus == nil {
		return RestoreWorkspaceResult{PreRestoreCheckpointID: preRestoreID}, errors.New("checkpoint restore helper omitted updated Git status")
	}
	return RestoreWorkspaceResult{
		RestoredCheckpointID: checkpointID, PreRestoreCheckpointID: preRestoreID, GitStatus: *response.GitStatus,
	}, nil
}

// acquireOperation serializes checkpoint creation and restore for one
// workspace. Entries are retained only while a holder or waiter exists, so
// deleted or attacker-selected workspace identifiers cannot grow the service
// for the process lifetime.
func (s *Service) acquireOperation(workspaceID string) func() {
	s.operationMu.Lock()
	if s.operations == nil {
		s.operations = make(map[string]*operationGate)
	}
	gate := s.operations[workspaceID]
	if gate == nil {
		gate = &operationGate{}
		s.operations[workspaceID] = gate
	}
	gate.refs++
	s.operationMu.Unlock()

	gate.mu.Lock()
	return func() {
		s.operationMu.Lock()
		gate.refs--
		if gate.refs == 0 && s.operations[workspaceID] == gate {
			delete(s.operations, workspaceID)
		}
		gate.mu.Unlock()
		s.operationMu.Unlock()
	}
}

func helperRestoreError(response workspacehelper.Response, fallback error) error {
	switch response.ErrorCode {
	case "invalid":
		return fmt.Errorf("%w: checkpoint restore helper rejected the archive", core.ErrInvalid)
	case "forbidden":
		return fmt.Errorf("%w: checkpoint restore path is unavailable", core.ErrForbidden)
	case "not_found":
		return fmt.Errorf("%w: checkpoint restore target is unavailable", core.ErrNotFound)
	case "conflict":
		return fmt.Errorf("%w: checkpoint restore conflicted with workspace state", core.ErrConflict)
	case "precondition":
		return fmt.Errorf("%w: checkpoint restore precondition failed", core.ErrPrecondition)
	default:
		return fallback
	}
}

func (s *Service) List(workspaceID string) ([]Metadata, error) {
	if !safeWorkspaceID.MatchString(workspaceID) {
		return nil, fmt.Errorf("%w: invalid workspace ID", core.ErrInvalid)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listLocked(workspaceID)
}

func (s *Service) Latest(ctx context.Context, workspaceID string) (string, error) {
	if ctx == nil {
		return "", errors.New("checkpoint context is required")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	items, err := s.List(workspaceID)
	if err != nil {
		return "", err
	}
	if len(items) == 0 {
		return "", fmt.Errorf("%w: no local checkpoint protects this workspace", core.ErrNotFound)
	}
	latest := items[len(items)-1]
	metadata, archive, err := s.load(workspaceID, latest.ID)
	if err != nil {
		return "", fmt.Errorf("verify latest local checkpoint: %w", err)
	}
	manifest, summary, err := validateArchive(archive)
	if err != nil || !checkpointMatches(metadata, manifest, summary) {
		if err == nil {
			err = errors.New("checkpoint metadata and archive summary do not match")
		}
		return "", fmt.Errorf("verify latest local checkpoint: %w", err)
	}
	return latest.ID, nil
}

func (s *Service) persist(metadata Metadata, archive []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if int64(len(archive)) > s.maxWorkspaceBytes {
		return errors.New("checkpoint exceeds workspace storage quota")
	}
	directory, err := s.workspaceDirectory(metadata.WorkspaceID, true)
	if err != nil {
		return err
	}
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	archivePath := filepath.Join(directory, metadata.ID+".zip")
	metadataPath := filepath.Join(directory, metadata.ID+".json")
	for _, target := range []string{archivePath, metadataPath} {
		if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
			if err == nil {
				return errors.New("checkpoint ID collision")
			}
			return err
		}
	}
	if err := atomicPrivateWrite(archivePath, archive); err != nil {
		return fmt.Errorf("write checkpoint archive: %w", err)
	}
	if err := atomicPrivateWrite(metadataPath, metadataBytes); err != nil {
		_ = os.Remove(archivePath)
		return fmt.Errorf("write checkpoint metadata: %w", err)
	}
	// Prune only after both new files are durable. This can exceed the logical
	// quota by at most one bounded archive during the write, but a disk/rename
	// failure never destroys the last known-good recovery point first.
	return s.pruneLocked(metadata.WorkspaceID, metadata.CreatedAt)
}

func (s *Service) load(workspaceID, checkpointID string) (Metadata, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	directory, err := s.workspaceDirectory(workspaceID, false)
	if err != nil {
		return Metadata{}, nil, err
	}
	metadata, err := readMetadata(filepath.Join(directory, checkpointID+".json"))
	if err != nil {
		return Metadata{}, nil, err
	}
	if metadata.WorkspaceID != workspaceID || metadata.ID != checkpointID {
		return Metadata{}, nil, errors.New("checkpoint metadata identity mismatch")
	}
	archive, err := os.ReadFile(filepath.Join(directory, checkpointID+".zip"))
	if err != nil {
		return Metadata{}, nil, err
	}
	if len(archive) == 0 || len(archive) > workspacehelper.MaxCheckpointArchiveBytes || int64(len(archive)) != metadata.CompressedBytes {
		return Metadata{}, nil, errors.New("checkpoint archive size mismatch")
	}
	digest := sha256.Sum256(archive)
	if !strings.EqualFold(hex.EncodeToString(digest[:]), metadata.ArchiveSHA256) {
		return Metadata{}, nil, errors.New("checkpoint archive digest mismatch")
	}
	return metadata, archive, nil
}

func (s *Service) checkpointID(now time.Time) (string, error) {
	random := make([]byte, 12)
	if _, err := io.ReadFull(s.random, random); err != nil {
		return "", fmt.Errorf("generate checkpoint ID: %w", err)
	}
	return "cp_" + now.Format("20060102T150405.000000000Z") + "_" + hex.EncodeToString(random), nil
}

func (s *Service) workspaceDirectory(workspaceID string, create bool) (string, error) {
	directory := filepath.Join(s.root, workspaceID)
	if create {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return "", err
		}
		if err := os.Chmod(directory, 0o700); err != nil {
			return "", err
		}
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("checkpoint workspace path is not a private directory")
	}
	return directory, nil
}

func (s *Service) pruneLocked(workspaceID string, now time.Time) error {
	metadata, err := s.listLocked(workspaceID)
	if err != nil {
		return err
	}
	total := int64(0)
	retained := make([]Metadata, 0, len(metadata))
	for _, item := range metadata {
		if now.Sub(item.CreatedAt) > s.retention {
			if err := s.removeLocked(workspaceID, item.ID); err != nil {
				return err
			}
			continue
		}
		total += item.CompressedBytes
		retained = append(retained, item)
	}
	for len(retained) > s.maxCheckpoints || total > s.maxWorkspaceBytes {
		oldest := retained[0]
		if err := s.removeLocked(workspaceID, oldest.ID); err != nil {
			return err
		}
		total -= oldest.CompressedBytes
		retained = retained[1:]
	}
	return nil
}

func (s *Service) listLocked(workspaceID string) ([]Metadata, error) {
	directory, err := s.workspaceDirectory(workspaceID, false)
	if errors.Is(err, os.ErrNotExist) {
		return []Metadata{}, nil
	}
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	result := make([]Metadata, 0)
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if !safeCheckpointID.MatchString(id) {
			continue
		}
		metadata, err := readMetadata(filepath.Join(directory, entry.Name()))
		if err != nil {
			return nil, err
		}
		if metadata.WorkspaceID != workspaceID || metadata.ID != id {
			return nil, errors.New("checkpoint metadata identity mismatch")
		}
		result = append(result, metadata)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].ID < result[j].ID
		}
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})
	return result, nil
}

func (s *Service) removeLocked(workspaceID, checkpointID string) error {
	directory, err := s.workspaceDirectory(workspaceID, false)
	if err != nil {
		return err
	}
	for _, suffix := range []string{".json", ".zip"} {
		if err := os.Remove(filepath.Join(directory, checkpointID+suffix)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func readMetadata(path string) (Metadata, error) {
	file, err := os.Open(path)
	if err != nil {
		return Metadata{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maxMetadataBytes+1))
	decoder.DisallowUnknownFields()
	var metadata Metadata
	if err := decoder.Decode(&metadata); err != nil {
		return Metadata{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Metadata{}, errors.New("checkpoint metadata has trailing data")
	}
	if metadata.Version != metadataVersion || !safeCheckpointID.MatchString(metadata.ID) ||
		!safeWorkspaceID.MatchString(metadata.WorkspaceID) || !safeReason.MatchString(metadata.Reason) ||
		metadata.CreatedAt.IsZero() || len(metadata.ArchiveSHA256) != 2*sha256.Size ||
		metadata.CompressedBytes <= 0 || metadata.CompressedBytes > workspacehelper.MaxCheckpointArchiveBytes ||
		metadata.ExpandedBytes < 0 || metadata.ExpandedBytes > workspacehelper.MaxCheckpointExpandedBytes ||
		metadata.FileCount < 0 || metadata.FileCount > workspacehelper.MaxCheckpointEntries ||
		metadata.DeletedCount < 0 || metadata.DeletedCount > workspacehelper.MaxCheckpointEntries ||
		metadata.OmittedSensitive < 0 || metadata.OmittedUnsafe < 0 {
		return Metadata{}, errors.New("checkpoint metadata is invalid")
	}
	return metadata, nil
}

func atomicPrivateWrite(target string, content []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(target), ".checkpoint-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(name)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, target); err != nil {
		return err
	}
	committed = true
	return nil
}

type archiveSummary struct {
	fileCount     int
	deletedCount  int
	expandedBytes int64
}

func validateArchive(data []byte) (workspacehelper.CheckpointManifest, archiveSummary, error) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return workspacehelper.CheckpointManifest{}, archiveSummary{}, err
	}
	if len(reader.File) == 0 || len(reader.File) > workspacehelper.MaxCheckpointEntries+1 {
		return workspacehelper.CheckpointManifest{}, archiveSummary{}, errors.New("invalid checkpoint archive entry count")
	}
	files := make(map[string]*zip.File, len(reader.File))
	foldedNames := make(map[string]bool, len(reader.File))
	for _, file := range reader.File {
		if _, duplicate := files[file.Name]; duplicate {
			return workspacehelper.CheckpointManifest{}, archiveSummary{}, errors.New("duplicate checkpoint archive entry")
		}
		foldedName := strings.ToLower(file.Name)
		if foldedNames[foldedName] {
			return workspacehelper.CheckpointManifest{}, archiveSummary{}, errors.New("case-conflicting checkpoint archive entry")
		}
		foldedNames[foldedName] = true
		if file.Name != workspacehelper.CheckpointManifestName {
			path, err := cleanArchiveEntryName(file.Name)
			if err != nil || workspacefiles.Sensitive(path) || !file.Mode().IsRegular() || file.Mode()&os.ModeSymlink != 0 ||
				(file.Method != zip.Store && file.Method != zip.Deflate) || file.UncompressedSize64 > workspacehelper.MaxCheckpointFileBytes {
				return workspacehelper.CheckpointManifest{}, archiveSummary{}, errors.New("unsafe checkpoint archive entry")
			}
		}
		files[file.Name] = file
	}
	manifestFile, ok := files[workspacehelper.CheckpointManifestName]
	if !ok || manifestFile.UncompressedSize64 > maxMetadataBytes || !manifestFile.Mode().IsRegular() ||
		(manifestFile.Method != zip.Store && manifestFile.Method != zip.Deflate) {
		return workspacehelper.CheckpointManifest{}, archiveSummary{}, errors.New("checkpoint manifest is missing or oversized")
	}
	manifestBytes, err := readZipFile(manifestFile, maxMetadataBytes)
	if err != nil {
		return workspacehelper.CheckpointManifest{}, archiveSummary{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(manifestBytes))
	decoder.DisallowUnknownFields()
	var manifest workspacehelper.CheckpointManifest
	if err := decoder.Decode(&manifest); err != nil {
		return workspacehelper.CheckpointManifest{}, archiveSummary{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return workspacehelper.CheckpointManifest{}, archiveSummary{}, errors.New("checkpoint manifest has trailing data")
	}
	if (manifest.Version != 1 && manifest.Version != workspacehelper.CheckpointArchiveVersion) ||
		(manifest.Version == 1 && manifest.WorkspaceID != "") ||
		(manifest.Version == workspacehelper.CheckpointArchiveVersion && !safeWorkspaceID.MatchString(manifest.WorkspaceID)) ||
		len(manifest.Entries) > workspacehelper.MaxCheckpointEntries || manifest.OmittedSensitive < 0 || manifest.OmittedUnsafe < 0 || !validHead(manifest.Head) {
		return workspacehelper.CheckpointManifest{}, archiveSummary{}, errors.New("checkpoint manifest is invalid")
	}
	seen := make(map[string]bool, len(manifest.Entries))
	foldedPaths := make(map[string]bool, len(manifest.Entries))
	summary := archiveSummary{}
	for _, entry := range manifest.Entries {
		path, err := cleanArchivePath(entry.Path)
		if err != nil || path != entry.Path || workspacefiles.Sensitive(path) || seen[path] {
			return workspacehelper.CheckpointManifest{}, archiveSummary{}, errors.New("checkpoint manifest contains an unsafe path")
		}
		foldedPath := strings.ToLower(path)
		if foldedPaths[foldedPath] {
			return workspacehelper.CheckpointManifest{}, archiveSummary{}, errors.New("checkpoint manifest contains case-conflicting paths")
		}
		for parent := foldedPath; ; {
			separator := strings.LastIndexByte(parent, '/')
			if separator < 0 {
				break
			}
			parent = parent[:separator]
			if foldedPaths[parent] {
				return workspacehelper.CheckpointManifest{}, archiveSummary{}, errors.New("checkpoint manifest contains conflicting file hierarchy")
			}
		}
		for existing := range foldedPaths {
			if strings.HasPrefix(existing, foldedPath+"/") {
				return workspacehelper.CheckpointManifest{}, archiveSummary{}, errors.New("checkpoint manifest contains conflicting file hierarchy")
			}
		}
		foldedPaths[foldedPath] = true
		seen[path] = true
		archiveName := "files/" + path
		file, present := files[archiveName]
		if entry.Deleted {
			if entry.Untracked || entry.Size != 0 || entry.SHA256 != "" || present {
				return workspacehelper.CheckpointManifest{}, archiveSummary{}, errors.New("invalid deleted checkpoint entry")
			}
			summary.deletedCount++
			continue
		}
		if !present || entry.Size < 0 || entry.Size > workspacehelper.MaxCheckpointFileBytes || entry.Mode > 0o777 ||
			file.UncompressedSize64 != uint64(entry.Size) || len(entry.SHA256) != 2*sha256.Size {
			return workspacehelper.CheckpointManifest{}, archiveSummary{}, errors.New("checkpoint manifest file metadata is invalid")
		}
		content, err := readZipFile(file, workspacehelper.MaxCheckpointFileBytes)
		if err != nil {
			return workspacehelper.CheckpointManifest{}, archiveSummary{}, err
		}
		digest := sha256.Sum256(content)
		want, err := hex.DecodeString(entry.SHA256)
		if err != nil || subtle.ConstantTimeCompare(digest[:], want) != 1 {
			return workspacehelper.CheckpointManifest{}, archiveSummary{}, errors.New("checkpoint file digest mismatch")
		}
		summary.fileCount++
		summary.expandedBytes += entry.Size
		if summary.expandedBytes > workspacehelper.MaxCheckpointExpandedBytes {
			return workspacehelper.CheckpointManifest{}, archiveSummary{}, errors.New("checkpoint expanded data exceeds limit")
		}
		delete(files, archiveName)
	}
	delete(files, workspacehelper.CheckpointManifestName)
	if len(files) != 0 {
		return workspacehelper.CheckpointManifest{}, archiveSummary{}, errors.New("checkpoint archive contains unmanifested files")
	}
	return manifest, summary, nil
}

func checkpointMatches(metadata Metadata, manifest workspacehelper.CheckpointManifest, summary archiveSummary) bool {
	if manifest.Version == workspacehelper.CheckpointArchiveVersion && manifest.WorkspaceID != metadata.WorkspaceID {
		return false
	}
	deletedCountMatches := manifest.Version == 1 || summary.deletedCount == metadata.DeletedCount
	return manifest.Head == metadata.Head && summary.fileCount == metadata.FileCount &&
		deletedCountMatches && summary.expandedBytes == metadata.ExpandedBytes &&
		manifest.OmittedSensitive == metadata.OmittedSensitive && manifest.OmittedUnsafe == metadata.OmittedUnsafe
}

func archiveFile(data []byte, manifest workspacehelper.CheckpointManifest, path string) (workspacehelper.CheckpointEntry, []byte, error) {
	var entry workspacehelper.CheckpointEntry
	found := false
	for _, candidate := range manifest.Entries {
		if candidate.Path == path {
			entry, found = candidate, true
			break
		}
	}
	if !found || entry.Deleted {
		return workspacehelper.CheckpointEntry{}, nil, fmt.Errorf("%w: file is absent from checkpoint", core.ErrNotFound)
	}
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return workspacehelper.CheckpointEntry{}, nil, err
	}
	for _, file := range reader.File {
		if file.Name == "files/"+path {
			content, err := readZipFile(file, workspacehelper.MaxCheckpointFileBytes)
			return entry, content, err
		}
	}
	return workspacehelper.CheckpointEntry{}, nil, fmt.Errorf("%w: checkpoint file data", core.ErrNotFound)
}

func readZipFile(file *zip.File, maximum int64) ([]byte, error) {
	reader, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	content, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > maximum {
		return nil, errors.New("checkpoint archive entry exceeds limit")
	}
	return content, nil
}

func cleanArchiveEntryName(name string) (string, error) {
	if !strings.HasPrefix(name, "files/") {
		return "", errors.New("invalid checkpoint archive namespace")
	}
	return cleanArchivePath(strings.TrimPrefix(name, "files/"))
}

func cleanArchivePath(path string) (string, error) {
	if path == "" || len(path) > 4096 || filepath.IsAbs(path) || strings.Contains(path, "\\") || strings.ContainsRune(path, 0) {
		return "", errors.New("invalid checkpoint path")
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(path)))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || clean == ".git" || strings.HasPrefix(clean, ".git/") {
		return "", errors.New("checkpoint path escapes repository")
	}
	return clean, nil
}

func validHead(value string) bool {
	if value == "" {
		return true
	}
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

var safeWorkspaceID = regexp.MustCompile(`^ws_[a-z2-7]{16,64}$`)
var safeProviderID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var safeReason = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
var safeCheckpointID = regexp.MustCompile(`^cp_[0-9]{8}T[0-9]{6}\.[0-9]{9}Z_[0-9a-f]{24}$`)
