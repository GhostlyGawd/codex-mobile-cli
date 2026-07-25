package workspacehelper

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	workspacefiles "github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/files"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/gitops"
)

type restoreArchive struct {
	manifest CheckpointManifest
	content  map[string][]byte
}

type restoreJournalEntry struct {
	path       string
	backupPath string
	existed    bool
}

type restoreFaults struct {
	failApplyAfter    int
	failRollbackAfter int
}

func (h *Helper) checkpointRestoreWorkspace(ctx context.Context, request *Request) Response {
	if !request.Confirmed || !checkpointWorkspaceIDPattern.MatchString(request.CheckpointWorkspaceID) {
		return failure("invalid", "The checkpoint restore request was invalid.")
	}
	if base64.StdEncoding.DecodedLen(len(request.Content)) > MaxCheckpointArchiveBytes {
		return failure("invalid", "The checkpoint archive exceeded its size limit.")
	}
	archive, err := base64.StdEncoding.DecodeString(request.Content)
	if err != nil || len(archive) == 0 || len(archive) > MaxCheckpointArchiveBytes {
		return failure("invalid", "The checkpoint archive encoding was invalid.")
	}
	defer wipeBytes(archive)
	digest := sha256.Sum256(archive)
	want, err := hex.DecodeString(request.CheckpointArchiveSHA256)
	if err != nil || len(want) != sha256.Size || subtle.ConstantTimeCompare(digest[:], want) != 1 {
		return failure("invalid", "The checkpoint archive integrity check failed.")
	}
	validated, err := validateWorkspaceRestoreArchive(archive, request.CheckpointWorkspaceID)
	if errors.Is(err, errLegacyWorkspaceRestore) {
		return failure("precondition", "This legacy checkpoint supports file restore only; whole-workspace restore requires an identity-bound version 2 checkpoint.")
	}
	if err != nil {
		return failure("invalid", "The checkpoint archive was unsafe or invalid.")
	}
	defer validated.wipe()
	if err := applyWorkspaceRestore(ctx, h.root, validated, restoreFaults{failApplyAfter: -1, failRollbackAfter: -1}); err != nil {
		return fromError(err)
	}
	git, err := gitops.New(h.root, nil, nil)
	if err != nil {
		return fromError(err)
	}
	status, err := git.Status(ctx)
	if err != nil {
		return fromError(err)
	}
	return Response{Version: Version, OK: true, GitStatus: &status}
}

var errLegacyWorkspaceRestore = errors.New("legacy checkpoint does not support whole-workspace restore")

func validateWorkspaceRestoreArchive(data []byte, workspaceID string) (restoreArchive, error) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return restoreArchive{}, err
	}
	if len(reader.File) == 0 || len(reader.File) > MaxCheckpointEntries+1 {
		return restoreArchive{}, errors.New("invalid checkpoint archive entry count")
	}
	files := make(map[string]*zip.File, len(reader.File))
	foldedNames := make(map[string]bool, len(reader.File))
	for _, file := range reader.File {
		if !utf8.ValidString(file.Name) || strings.ContainsRune(file.Name, 0) {
			return restoreArchive{}, errors.New("invalid checkpoint archive name")
		}
		folded := strings.ToLower(file.Name)
		if _, exists := files[file.Name]; exists || foldedNames[folded] {
			return restoreArchive{}, errors.New("duplicate checkpoint archive name")
		}
		foldedNames[folded] = true
		if file.Method != zip.Store && file.Method != zip.Deflate {
			return restoreArchive{}, errors.New("unsupported checkpoint compression")
		}
		if !file.Mode().IsRegular() || file.Mode()&os.ModeSymlink != 0 {
			return restoreArchive{}, errors.New("non-regular checkpoint archive entry")
		}
		if file.Name != CheckpointManifestName {
			path, cleanErr := cleanRestoreArchiveName(file.Name)
			if cleanErr != nil || workspacefiles.Sensitive(path) || file.UncompressedSize64 > MaxCheckpointFileBytes {
				return restoreArchive{}, errors.New("unsafe checkpoint archive entry")
			}
		}
		files[file.Name] = file
	}
	manifestFile, present := files[CheckpointManifestName]
	if !present || manifestFile.UncompressedSize64 > MaxCheckpointManifestBytes {
		return restoreArchive{}, errors.New("checkpoint manifest missing or oversized")
	}
	manifestBytes, err := readRestoreZipFile(manifestFile, MaxCheckpointManifestBytes)
	if err != nil {
		return restoreArchive{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(manifestBytes))
	decoder.DisallowUnknownFields()
	var manifest CheckpointManifest
	if err := decoder.Decode(&manifest); err != nil {
		return restoreArchive{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return restoreArchive{}, errors.New("checkpoint manifest has trailing data")
	}
	if manifest.Version == 1 {
		return restoreArchive{}, errLegacyWorkspaceRestore
	}
	if manifest.Version != CheckpointArchiveVersion || manifest.WorkspaceID != workspaceID ||
		!checkpointWorkspaceIDPattern.MatchString(manifest.WorkspaceID) || len(manifest.Entries) > MaxCheckpointEntries ||
		manifest.OmittedSensitive < 0 || manifest.OmittedUnsafe < 0 || !validCheckpointHead(manifest.Head) {
		return restoreArchive{}, errors.New("checkpoint manifest identity or version mismatch")
	}
	result := restoreArchive{manifest: manifest, content: make(map[string][]byte, len(manifest.Entries))}
	seen := make(map[string]bool, len(manifest.Entries))
	foldedPaths := make(map[string]bool, len(manifest.Entries))
	var expanded int64
	for _, entry := range manifest.Entries {
		path, cleanErr := cleanCheckpointPath(entry.Path)
		if cleanErr != nil || path != entry.Path || workspacefiles.Sensitive(path) || seen[path] || !utf8.ValidString(path) {
			result.wipe()
			return restoreArchive{}, errors.New("unsafe checkpoint manifest path")
		}
		folded := strings.ToLower(path)
		if foldedPaths[folded] || restoreHierarchyConflict(foldedPaths, folded) {
			result.wipe()
			return restoreArchive{}, errors.New("case or hierarchy-conflicting checkpoint path")
		}
		foldedPaths[folded], seen[path] = true, true
		archiveName := "files/" + path
		file, hasFile := files[archiveName]
		if entry.Deleted {
			if entry.Untracked || entry.Size != 0 || entry.SHA256 != "" || entry.Mode != 0 || hasFile {
				result.wipe()
				return restoreArchive{}, errors.New("invalid deleted checkpoint entry")
			}
			continue
		}
		if !hasFile || entry.Size < 0 || entry.Size > MaxCheckpointFileBytes || entry.Mode > 0o777 ||
			file.UncompressedSize64 != uint64(entry.Size) || len(entry.SHA256) != 2*sha256.Size {
			result.wipe()
			return restoreArchive{}, errors.New("invalid checkpoint file metadata")
		}
		content, readErr := readRestoreZipFile(file, MaxCheckpointFileBytes)
		if readErr != nil {
			result.wipe()
			return restoreArchive{}, readErr
		}
		digest := sha256.Sum256(content)
		wantDigest, decodeErr := hex.DecodeString(entry.SHA256)
		if decodeErr != nil || subtle.ConstantTimeCompare(digest[:], wantDigest) != 1 {
			wipeBytes(content)
			result.wipe()
			return restoreArchive{}, errors.New("checkpoint file digest mismatch")
		}
		expanded += int64(len(content))
		if expanded > MaxCheckpointExpandedBytes {
			wipeBytes(content)
			result.wipe()
			return restoreArchive{}, errors.New("checkpoint expanded data exceeded limit")
		}
		result.content[path] = content
		delete(files, archiveName)
	}
	delete(files, CheckpointManifestName)
	if len(files) != 0 {
		result.wipe()
		return restoreArchive{}, errors.New("checkpoint archive contains unmanifested files")
	}
	return result, nil
}

func restoreHierarchyConflict(paths map[string]bool, path string) bool {
	for parent := path; ; {
		separator := strings.LastIndexByte(parent, '/')
		if separator < 0 {
			break
		}
		parent = parent[:separator]
		if paths[parent] {
			return true
		}
	}
	for existing := range paths {
		if strings.HasPrefix(existing, path+"/") {
			return true
		}
	}
	return false
}

func cleanRestoreArchiveName(name string) (string, error) {
	if !strings.HasPrefix(name, "files/") {
		return "", errors.New("invalid checkpoint archive namespace")
	}
	return cleanCheckpointPath(strings.TrimPrefix(name, "files/"))
}

func readRestoreZipFile(file *zip.File, maximum int64) ([]byte, error) {
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
		wipeBytes(content)
		return nil, errors.New("checkpoint archive entry exceeded limit")
	}
	return content, nil
}

func validCheckpointHead(value string) bool {
	if value == "" {
		return true
	}
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func (archive restoreArchive) wipe() {
	for _, content := range archive.content {
		wipeBytes(content)
	}
}

func applyWorkspaceRestore(ctx context.Context, rootPath string, archive restoreArchive, faults restoreFaults) error {
	if ctx == nil {
		return fmt.Errorf("%w: restore context is required", core.ErrInvalid)
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return err
	}
	defer root.Close()
	gitInfo, err := root.Lstat(".git")
	if err != nil || !gitInfo.IsDir() || gitInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: Git control directory is unavailable", core.ErrPrecondition)
	}
	lock, err := root.OpenFile(filepath.FromSlash(".git/index.lock"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("%w: Git is busy; close or wait for the terminal Git operation", core.ErrConflict)
	}
	lockInfo, _ := lock.Stat()
	_ = lock.Close()
	defer func() {
		if current, statErr := root.Lstat(filepath.FromSlash(".git/index.lock")); statErr == nil && lockInfo != nil && os.SameFile(lockInfo, current) {
			_ = root.Remove(filepath.FromSlash(".git/index.lock"))
		}
	}()

	stage, err := os.MkdirTemp(filepath.Dir(rootPath), ".codex-mobile-restore-stage-")
	if err != nil {
		return err
	}
	if err := os.Chmod(stage, 0o700); err != nil {
		_ = os.RemoveAll(stage)
		return err
	}
	defer os.RemoveAll(stage)

	entries := append([]CheckpointEntry(nil), archive.manifest.Entries...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	for index, entry := range entries {
		if entry.Deleted {
			continue
		}
		stagePath := filepath.Join(stage, fmt.Sprintf("%06d", index))
		file, createErr := os.OpenFile(stagePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if createErr != nil {
			return createErr
		}
		mode := fs.FileMode(entry.Mode)
		if mode == 0 {
			mode = 0o600
		}
		_, writeErr := file.Write(archive.content[entry.Path])
		if writeErr == nil {
			writeErr = file.Chmod(mode.Perm())
		}
		if writeErr == nil {
			writeErr = file.Sync()
		}
		closeErr := file.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
	}

	for _, entry := range entries {
		if err := preflightRestorePath(root, entry.Path); err != nil {
			return fmt.Errorf("%w: restore destination is unsafe", core.ErrPrecondition)
		}
	}
	journalPath, err := os.MkdirTemp(filepath.Join(rootPath, ".git"), "codex-mobile-restore-")
	if err != nil {
		return err
	}
	if err := os.Chmod(journalPath, 0o700); err != nil {
		_ = os.RemoveAll(journalPath)
		return err
	}
	journalRelative := filepath.Join(".git", filepath.Base(journalPath))
	if err := root.Mkdir(filepath.Join(journalRelative, "backups"), 0o700); err != nil {
		_ = os.RemoveAll(journalPath)
		return err
	}

	journal := make([]restoreJournalEntry, 0, len(entries))
	createdDirectories := make([]string, 0)
	applyErr := error(nil)
	for index, entry := range entries {
		if err := ctx.Err(); err != nil {
			applyErr = err
			break
		}
		if faults.failApplyAfter >= 0 && index >= faults.failApplyAfter {
			applyErr = errors.New("injected restore apply failure")
			break
		}
		path := filepath.FromSlash(entry.Path)
		backup := filepath.Join(journalRelative, "backups", fmt.Sprintf("%06d", index))
		record := restoreJournalEntry{path: path, backupPath: backup}
		if _, statErr := root.Lstat(path); statErr == nil {
			record.existed = true
			if renameErr := root.Rename(path, backup); renameErr != nil {
				applyErr = renameErr
				break
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			applyErr = statErr
			break
		}
		journal = append(journal, record)
		if entry.Deleted {
			continue
		}
		if err := ensureRestoreParents(root, filepath.Dir(path), &createdDirectories); err != nil {
			applyErr = err
			break
		}
		temporary := filepath.Join(filepath.Dir(path), fmt.Sprintf(".codex-mobile-restore-%06d", index))
		target, createErr := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if createErr != nil {
			applyErr = createErr
			break
		}
		source, openErr := os.Open(filepath.Join(stage, fmt.Sprintf("%06d", index)))
		if openErr == nil {
			_, openErr = io.Copy(target, io.LimitReader(source, MaxCheckpointFileBytes+1))
			_ = source.Close()
		}
		if openErr == nil {
			mode := fs.FileMode(entry.Mode)
			if mode == 0 {
				mode = 0o600
			}
			openErr = target.Chmod(mode.Perm())
		}
		if openErr == nil {
			openErr = target.Sync()
		}
		closeErr := target.Close()
		if openErr == nil {
			openErr = closeErr
		}
		if openErr == nil {
			openErr = root.Rename(temporary, path)
		}
		if openErr != nil {
			_ = root.Remove(temporary)
			applyErr = openErr
			break
		}
		syncRestoreDirectory(root, filepath.Dir(path))
	}
	if applyErr == nil {
		if err := root.RemoveAll(journalRelative); err != nil {
			return fmt.Errorf("%w: restored files but could not remove private rollback journal", core.ErrConflict)
		}
		syncRestoreDirectory(root, ".git")
		return nil
	}

	rollbackErr := rollbackWorkspaceRestore(root, journal, createdDirectories, faults.failRollbackAfter)
	if rollbackErr != nil {
		return fmt.Errorf("%w: restore failed and rollback incomplete; private journal retained at %s: %v", core.ErrConflict, journalRelative, rollbackErr)
	}
	if err := root.RemoveAll(journalRelative); err != nil {
		return fmt.Errorf("%w: restore failed, rollback completed, but journal cleanup failed", core.ErrConflict)
	}
	return fmt.Errorf("%w: restore failed and prior workspace state was rolled back", core.ErrConflict)
}

func preflightRestorePath(root *os.Root, path string) error {
	clean, err := cleanCheckpointPath(path)
	if err != nil || clean != path {
		return errors.New("unsafe restore path")
	}
	current := ""
	parts := strings.Split(filepath.FromSlash(path), string(filepath.Separator))
	for index, part := range parts {
		current = filepath.Join(current, part)
		info, statErr := root.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) {
			return nil
		}
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("unsafe restore path component")
		}
		if index < len(parts)-1 && !info.IsDir() {
			return errors.New("restore parent is not a directory")
		}
		if index == len(parts)-1 && !info.Mode().IsRegular() {
			return errors.New("restore target is not a regular file")
		}
	}
	return nil
}

func ensureRestoreParents(root *os.Root, parent string, created *[]string) error {
	if parent == "." || parent == "" {
		return nil
	}
	current := ""
	for _, part := range strings.Split(parent, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := root.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if err := root.Mkdir(current, 0o700); err != nil {
				return err
			}
			*created = append(*created, current)
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("unsafe restore parent")
		}
	}
	return nil
}

func rollbackWorkspaceRestore(root *os.Root, journal []restoreJournalEntry, createdDirectories []string, failAfter int) error {
	rolledBack := 0
	for index := len(journal) - 1; index >= 0; index-- {
		if failAfter >= 0 && rolledBack >= failAfter {
			return errors.New("injected rollback failure")
		}
		record := journal[index]
		if info, err := root.Lstat(record.path); err == nil {
			if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("restore target changed before rollback")
			}
			if err := root.Remove(record.path); err != nil {
				return err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if record.existed {
			if err := root.Rename(record.backupPath, record.path); err != nil {
				return err
			}
		}
		rolledBack++
	}
	for index := len(createdDirectories) - 1; index >= 0; index-- {
		if err := root.Remove(createdDirectories[index]); err != nil && !errors.Is(err, os.ErrNotExist) {
			// A non-empty directory means pre-existing or concurrently added data;
			// retaining it is safer than recursive cleanup.
			continue
		}
	}
	return nil
}

func syncRestoreDirectory(root *os.Root, directory string) {
	if directory == "" {
		directory = "."
	}
	file, err := root.Open(directory)
	if err == nil {
		_ = file.Sync()
		_ = file.Close()
	}
}
