package checkpoint

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/workspacehelper"
)

const (
	testWorkspaceID = "ws_aaaaaaaaaaaaaaaa"
	testProviderID  = "11111111-1111-4111-8111-111111111111"
)

type localRunner struct {
	helper     *workspacehelper.Helper
	providerID string
}

func (r localRunner) RunHelper(ctx context.Context, providerID string, request []byte) ([]byte, error) {
	if providerID != r.providerID {
		return nil, errors.New("unexpected provider workspace")
	}
	var output bytes.Buffer
	if err := r.helper.Serve(ctx, bytes.NewReader(request), &output); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func TestCreatePersistsOutsideRepositoryAndRestoresTrackedAndUntrackedFiles(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}
	base := t.TempDir()
	repository := filepath.Join(base, "repository")
	if err := os.Mkdir(repository, 0o700); err != nil {
		t.Fatal(err)
	}
	initializeGit(t, repository)
	write(t, filepath.Join(repository, "tracked.txt"), "dirty tracked\n")
	write(t, filepath.Join(repository, "untracked.txt"), "untracked recovery\n")
	write(t, filepath.Join(repository, ".env.local"), "TOKEN=excluded\n")

	helper, err := workspacehelper.New(repository)
	if err != nil {
		t.Fatal(err)
	}
	checkpointRoot := filepath.Join(base, "local-checkpoints")
	service, err := New(Config{Root: checkpointRoot}, localRunner{helper: helper, providerID: testProviderID})
	if err != nil {
		t.Fatal(err)
	}
	id, dirty, unpushed, err := service.Create(context.Background(), testWorkspaceID, testProviderID, "before-delete")
	if err != nil {
		t.Fatal(err)
	}
	if id == "" || !dirty {
		t.Fatalf("checkpoint = %q dirty=%v unpushed=%v", id, dirty, unpushed)
	}
	relative, err := filepath.Rel(repository, checkpointRoot)
	if err != nil || relative == "." || !strings.HasPrefix(relative, "..") {
		t.Fatalf("checkpoint root %q is not outside repository %q", checkpointRoot, repository)
	}
	metadata, err := service.List(testWorkspaceID)
	if err != nil || len(metadata) != 1 {
		t.Fatalf("metadata = %#v, %v", metadata, err)
	}
	if metadata[0].ID != id || metadata[0].Reason != "before-delete" || metadata[0].OmittedSensitive != 1 || metadata[0].FileCount != 2 {
		t.Fatalf("unexpected metadata: %#v", metadata[0])
	}
	if _, err := os.Stat(filepath.Join(checkpointRoot, testWorkspaceID, id+".zip")); err != nil {
		t.Fatal(err)
	}

	write(t, filepath.Join(repository, "tracked.txt"), "lost\n")
	if err := os.Remove(filepath.Join(repository, "untracked.txt")); err != nil {
		t.Fatal(err)
	}
	if err := service.RestoreFile(context.Background(), testWorkspaceID, testProviderID, id, "tracked.txt"); err != nil {
		t.Fatal(err)
	}
	if err := service.RestoreFile(context.Background(), testWorkspaceID, testProviderID, id, "untracked.txt"); err != nil {
		t.Fatal(err)
	}
	if got := read(t, filepath.Join(repository, "tracked.txt")); got != "dirty tracked\n" {
		t.Fatalf("restored tracked content = %q", got)
	}
	if got := read(t, filepath.Join(repository, "untracked.txt")); got != "untracked recovery\n" {
		t.Fatalf("restored untracked content = %q", got)
	}
	if err := service.RestoreFile(context.Background(), testWorkspaceID, testProviderID, id, ".env.local"); !errors.Is(err, core.ErrForbidden) {
		t.Fatalf("sensitive restore error = %v", err)
	}
}

func TestCreateCleanPushedRepositoryDoesNotWriteArchive(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}
	base := t.TempDir()
	repository := filepath.Join(base, "repository")
	remote := filepath.Join(base, "remote.git")
	if err := os.Mkdir(repository, 0o700); err != nil {
		t.Fatal(err)
	}
	initializeGit(t, repository)
	runGit(t, base, "init", "--bare", remote)
	runGit(t, repository, "remote", "add", "origin", remote)
	runGit(t, repository, "push", "--set-upstream", "origin", "HEAD")
	helper, _ := workspacehelper.New(repository)
	service, err := New(Config{Root: filepath.Join(base, "checkpoints")}, localRunner{helper: helper, providerID: testProviderID})
	if err != nil {
		t.Fatal(err)
	}
	id, dirty, unpushed, err := service.Create(context.Background(), testWorkspaceID, testProviderID, "periodic")
	if err != nil || id != "" || dirty || unpushed {
		t.Fatalf("clean checkpoint = %q dirty=%v unpushed=%v err=%v", id, dirty, unpushed, err)
	}
	items, err := service.List(testWorkspaceID)
	if err != nil || len(items) != 0 {
		t.Fatalf("clean workspace persisted checkpoint: %#v, %v", items, err)
	}
}

func TestRestoreWorkspaceCreatesPreRestoreCheckpointAndRestoresDeletedDelta(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}
	base := t.TempDir()
	repository := filepath.Join(base, "repository")
	if err := os.Mkdir(repository, 0o700); err != nil {
		t.Fatal(err)
	}
	initializeGit(t, repository)
	write(t, filepath.Join(repository, "deleted.txt"), "base deleted\n")
	runGit(t, repository, "add", "deleted.txt")
	runGit(t, repository, "commit", "-m", "add deleted fixture")
	write(t, filepath.Join(repository, "tracked.txt"), "checkpoint value\n")
	if err := os.Remove(filepath.Join(repository, "deleted.txt")); err != nil {
		t.Fatal(err)
	}
	helper, err := workspacehelper.New(repository)
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(Config{Root: filepath.Join(base, "checkpoints")}, localRunner{helper: helper, providerID: testProviderID})
	if err != nil {
		t.Fatal(err)
	}
	targetID, _, _, err := service.Create(context.Background(), testWorkspaceID, testProviderID, "manual")
	if err != nil || targetID == "" {
		t.Fatalf("target checkpoint = %q, %v", targetID, err)
	}
	write(t, filepath.Join(repository, "tracked.txt"), "current value\n")
	write(t, filepath.Join(repository, "deleted.txt"), "current recreated\n")
	write(t, filepath.Join(repository, "unrelated.txt"), "unrelated current\n")

	result, err := service.RestoreWorkspace(context.Background(), testWorkspaceID, testProviderID, targetID, true)
	if err != nil {
		t.Fatal(err)
	}
	if result.RestoredCheckpointID != targetID || result.PreRestoreCheckpointID == "" || !result.GitStatus.Dirty {
		t.Fatalf("restore result = %#v", result)
	}
	if got := read(t, filepath.Join(repository, "tracked.txt")); got != "checkpoint value\n" {
		t.Fatalf("restored tracked content = %q", got)
	}
	if _, err := os.Lstat(filepath.Join(repository, "deleted.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recorded deletion was not restored: %v", err)
	}
	if got := read(t, filepath.Join(repository, "unrelated.txt")); got != "unrelated current\n" {
		t.Fatalf("delta restore changed unrelated path = %q", got)
	}
	if _, err := service.RestoreWorkspace(context.Background(), testWorkspaceID, testProviderID, result.PreRestoreCheckpointID, true); err != nil {
		t.Fatalf("pre-restore checkpoint could not undo restore: %v", err)
	}
	if got := read(t, filepath.Join(repository, "tracked.txt")); got != "current value\n" {
		t.Fatalf("pre-restore checkpoint did not recover current tracked value = %q", got)
	}
	if got := read(t, filepath.Join(repository, "deleted.txt")); got != "current recreated\n" {
		t.Fatalf("pre-restore checkpoint did not recover recreated file = %q", got)
	}
	if _, err := service.RestoreWorkspace(context.Background(), testWorkspaceID, testProviderID, targetID, true); err != nil {
		t.Fatalf("idempotent restore failed: %v", err)
	}
	if _, err := service.RestoreWorkspace(context.Background(), testWorkspaceID, testProviderID, targetID, true); err != nil {
		t.Fatalf("second idempotent restore failed: %v", err)
	}
	items, err := service.List(testWorkspaceID)
	if err != nil || len(items) < 5 {
		t.Fatalf("pre-restore checkpoints were not persisted: %#v, %v", items, err)
	}
}

func TestRestoreWorkspaceRejectsCrossWorkspaceAndTamperedArchiveBeforePreCheckpoint(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}
	base := t.TempDir()
	repository := filepath.Join(base, "repository")
	if err := os.Mkdir(repository, 0o700); err != nil {
		t.Fatal(err)
	}
	initializeGit(t, repository)
	write(t, filepath.Join(repository, "tracked.txt"), "checkpoint value\n")
	helper, _ := workspacehelper.New(repository)
	service, err := New(Config{Root: filepath.Join(base, "checkpoints")}, localRunner{helper: helper, providerID: testProviderID})
	if err != nil {
		t.Fatal(err)
	}
	id, _, _, err := service.Create(context.Background(), testWorkspaceID, testProviderID, "manual")
	if err != nil {
		t.Fatal(err)
	}
	otherWorkspace := "ws_bbbbbbbbbbbbbbbb"
	if _, err := service.RestoreWorkspace(context.Background(), otherWorkspace, testProviderID, id, true); err == nil {
		t.Fatal("cross-workspace checkpoint restore succeeded")
	}
	archivePath := filepath.Join(service.root, testWorkspaceID, id+".zip")
	archive, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	archive[len(archive)/2] ^= 0xff
	if err := os.WriteFile(archivePath, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := service.List(testWorkspaceID)
	if _, err := service.RestoreWorkspace(context.Background(), testWorkspaceID, testProviderID, id, true); err == nil {
		t.Fatal("tampered checkpoint restore succeeded")
	}
	after, _ := service.List(testWorkspaceID)
	if len(after) != len(before) {
		t.Fatalf("tampered restore created a pre-checkpoint: before=%d after=%d", len(before), len(after))
	}
}

func TestCheckpointCountQuotaPrunesOldest(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}
	base := t.TempDir()
	repository := filepath.Join(base, "repository")
	if err := os.Mkdir(repository, 0o700); err != nil {
		t.Fatal(err)
	}
	initializeGit(t, repository)
	helper, _ := workspacehelper.New(repository)
	service, err := New(Config{Root: filepath.Join(base, "checkpoints"), MaxCheckpoints: 1}, localRunner{helper: helper, providerID: testProviderID})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { now = now.Add(time.Second); return now }
	write(t, filepath.Join(repository, "tracked.txt"), "first\n")
	first, _, _, err := service.Create(context.Background(), testWorkspaceID, testProviderID, "periodic")
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(repository, "tracked.txt"), "second\n")
	second, _, _, err := service.Create(context.Background(), testWorkspaceID, testProviderID, "periodic")
	if err != nil {
		t.Fatal(err)
	}
	items, err := service.List(testWorkspaceID)
	if err != nil || len(items) != 1 || items[0].ID != second || first == second {
		t.Fatalf("pruned items = %#v, %v", items, err)
	}
	if _, err := os.Stat(filepath.Join(service.root, testWorkspaceID, first+".zip")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("oldest checkpoint archive was not pruned")
	}
}

func TestValidateArchiveRejectsTraversal(t *testing.T) {
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	content := []byte("escape")
	digest := sha256.Sum256(content)
	manifest := workspacehelper.CheckpointManifest{
		Version: 1,
		Entries: []workspacehelper.CheckpointEntry{{Path: "../escape", Size: int64(len(content)), SHA256: hex.EncodeToString(digest[:]), Mode: 0o600}},
	}
	manifestBytes, _ := json.Marshal(manifest)
	entry, _ := writer.Create(workspacehelper.CheckpointManifestName)
	_, _ = entry.Write(manifestBytes)
	entry, _ = writer.Create("files/../escape")
	_, _ = entry.Write(content)
	_ = writer.Close()
	if _, _, err := validateArchive(archive.Bytes()); err == nil {
		t.Fatal("archive traversal was accepted")
	}
}

func TestLegacyV1CheckpointRemainsFileRestorableButFullRestoreIsExplicitlyUnsupported(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}
	base := t.TempDir()
	repository := filepath.Join(base, "repository")
	if err := os.Mkdir(repository, 0o700); err != nil {
		t.Fatal(err)
	}
	initializeGit(t, repository)
	helper, _ := workspacehelper.New(repository)
	service, err := New(Config{Root: filepath.Join(base, "checkpoints")}, localRunner{helper: helper, providerID: testProviderID})
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("legacy recovered\n")
	digest := sha256.Sum256(content)
	manifest := workspacehelper.CheckpointManifest{
		Version: 1,
		Entries: []workspacehelper.CheckpointEntry{{
			Path: "tracked.txt", SHA256: hex.EncodeToString(digest[:]), Size: int64(len(content)), Mode: 0o600,
		}, {Path: "legacy-deleted.txt", Deleted: true}},
	}
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	header := &zip.FileHeader{Name: "files/tracked.txt", Method: zip.Deflate}
	header.SetMode(0o600)
	file, _ := writer.CreateHeader(header)
	_, _ = file.Write(content)
	manifestBytes, _ := json.Marshal(manifest)
	header = &zip.FileHeader{Name: workspacehelper.CheckpointManifestName, Method: zip.Deflate}
	header.SetMode(0o600)
	file, _ = writer.CreateHeader(header)
	_, _ = file.Write(manifestBytes)
	_ = writer.Close()
	archiveDigest := sha256.Sum256(archive.Bytes())
	const checkpointID = "cp_20260716T010203.000000000Z_aaaaaaaaaaaaaaaaaaaaaaaa"
	metadata := Metadata{
		Version: metadataVersion, ID: checkpointID, WorkspaceID: testWorkspaceID, Reason: "legacy",
		CreatedAt: time.Date(2026, 7, 16, 1, 2, 3, 0, time.UTC), ArchiveSHA256: hex.EncodeToString(archiveDigest[:]),
		CompressedBytes: int64(archive.Len()), ExpandedBytes: int64(len(content)), FileCount: 1,
	}
	if err := service.persist(metadata, archive.Bytes()); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(repository, "tracked.txt"), "current\n")
	if err := service.RestoreFile(context.Background(), testWorkspaceID, testProviderID, checkpointID, "tracked.txt"); err != nil {
		t.Fatalf("legacy file restore failed: %v", err)
	}
	if got := read(t, filepath.Join(repository, "tracked.txt")); got != string(content) {
		t.Fatalf("legacy file restore = %q", got)
	}
	if _, err := service.RestoreWorkspace(context.Background(), testWorkspaceID, testProviderID, checkpointID, true); !errors.Is(err, core.ErrPrecondition) || !strings.Contains(err.Error(), "file restore only") {
		t.Fatalf("legacy workspace restore error = %v", err)
	}
	items, err := service.ListVerified(context.Background(), testWorkspaceID)
	if err != nil || len(items) != 1 || !items[0].HashVerified || items[0].WorkspaceRestoreSupported || items[0].ArchiveVersion != 1 {
		t.Fatalf("legacy checkpoint listing = %#v, %v", items, err)
	}
}

type canceledRunner struct{}

func (canceledRunner) RunHelper(context.Context, string, []byte) ([]byte, error) {
	return nil, context.Canceled
}

func TestCreatePropagatesCancellationAndWritesNothing(t *testing.T) {
	root := t.TempDir()
	service, err := New(Config{Root: root}, canceledRunner{})
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = service.Create(context.Background(), testWorkspaceID, testProviderID, "before-suspend")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
	entries, readErr := os.ReadDir(root)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("canceled checkpoint wrote data: %v %#v", readErr, entries)
	}
}

func initializeGit(t *testing.T, root string) {
	t.Helper()
	runGit(t, root, "init")
	runGit(t, root, "config", "user.name", "Checkpoint Test")
	runGit(t, root, "config", "user.email", "checkpoint@example.test")
	write(t, filepath.Join(root, "tracked.txt"), "base\n")
	runGit(t, root, "add", "tracked.txt")
	runGit(t, root, "commit", "-m", "initial")
}

func runGit(t *testing.T, root string, args ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	command.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}
