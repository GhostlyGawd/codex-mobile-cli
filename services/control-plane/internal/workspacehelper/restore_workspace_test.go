package workspacehelper

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const restoreTestWorkspaceID = "ws_aaaaaaaaaaaaaaaa"

func TestWorkspaceRestoreAppliesFilesAndDeletionsIdempotentlyWithoutTouchingGitMetadata(t *testing.T) {
	root := restoreTestRepository(t)
	writeRestoreTestFile(t, root, "tracked.txt", "checkpoint tracked\n")
	if err := os.Remove(filepath.Join(root, "deleted.txt")); err != nil {
		t.Fatal(err)
	}
	writeRestoreTestFile(t, root, "untracked.txt", "checkpoint untracked\n")
	headBefore := readRestoreTestFile(t, root, ".git/HEAD")
	archiveBytes, manifest, err := buildCheckpointArchive(context.Background(), root, restoreTestWorkspaceID, restoreTestHead(t, root))
	if err != nil {
		t.Fatal(err)
	}
	if !manifestContainsDeleted(manifest, "deleted.txt") {
		t.Fatalf("checkpoint did not record deletion: %#v", manifest)
	}
	validated, err := validateWorkspaceRestoreArchive(archiveBytes, restoreTestWorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	defer validated.wipe()

	writeRestoreTestFile(t, root, "tracked.txt", "current tracked\n")
	writeRestoreTestFile(t, root, "deleted.txt", "recreated current file\n")
	if err := os.Remove(filepath.Join(root, "untracked.txt")); err != nil {
		t.Fatal(err)
	}
	writeRestoreTestFile(t, root, "unrelated.txt", "must remain\n")
	for iteration := 0; iteration < 2; iteration++ {
		if err := applyWorkspaceRestore(context.Background(), root, validated, restoreFaults{failApplyAfter: -1, failRollbackAfter: -1}); err != nil {
			t.Fatalf("restore iteration %d: %v", iteration, err)
		}
	}
	if got := readRestoreTestFile(t, root, "tracked.txt"); got != "checkpoint tracked\n" {
		t.Fatalf("tracked restore = %q", got)
	}
	if got := readRestoreTestFile(t, root, "untracked.txt"); got != "checkpoint untracked\n" {
		t.Fatalf("untracked restore = %q", got)
	}
	if _, err := os.Lstat(filepath.Join(root, "deleted.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recorded deletion was not restored: %v", err)
	}
	if got := readRestoreTestFile(t, root, "unrelated.txt"); got != "must remain\n" {
		t.Fatalf("delta restore changed unrelated path: %q", got)
	}
	if got := readRestoreTestFile(t, root, ".git/HEAD"); got != headBefore {
		t.Fatal("restore changed Git control metadata")
	}
}

func TestWorkspaceRestoreRollsBackMidApplyFailure(t *testing.T) {
	root := restoreTestRepository(t)
	archiveBytes := makeRestoreArchive(t, CheckpointManifest{
		Version: CheckpointArchiveVersion, WorkspaceID: restoreTestWorkspaceID,
		Entries: []CheckpointEntry{
			restoreTestEntry("a.txt", "checkpoint a\n"),
			restoreTestEntry("b.txt", "checkpoint b\n"),
		},
	}, map[string][]byte{"a.txt": []byte("checkpoint a\n"), "b.txt": []byte("checkpoint b\n")}, nil)
	validated, err := validateWorkspaceRestoreArchive(archiveBytes, restoreTestWorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	defer validated.wipe()
	writeRestoreTestFile(t, root, "a.txt", "current a\n")
	writeRestoreTestFile(t, root, "b.txt", "current b\n")
	err = applyWorkspaceRestore(context.Background(), root, validated, restoreFaults{failApplyAfter: 1, failRollbackAfter: -1})
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("mid-apply error = %v", err)
	}
	if got := readRestoreTestFile(t, root, "a.txt"); got != "current a\n" {
		t.Fatalf("first file was not rolled back: %q", got)
	}
	if got := readRestoreTestFile(t, root, "b.txt"); got != "current b\n" {
		t.Fatalf("second file changed: %q", got)
	}
	if journals, _ := filepath.Glob(filepath.Join(root, ".git", "codex-mobile-restore-*")); len(journals) != 0 {
		t.Fatalf("completed rollback retained journal: %#v", journals)
	}
}

func TestWorkspaceRestoreRetainsPrivateJournalAndFailsClosedWhenRollbackIsIncomplete(t *testing.T) {
	root := restoreTestRepository(t)
	entry := restoreTestEntry("a.txt", "checkpoint\n")
	second := restoreTestEntry("b.txt", "checkpoint b\n")
	archiveBytes := makeRestoreArchive(t, CheckpointManifest{
		Version: CheckpointArchiveVersion, WorkspaceID: restoreTestWorkspaceID, Entries: []CheckpointEntry{entry, second},
	}, map[string][]byte{"a.txt": []byte("checkpoint\n"), "b.txt": []byte("checkpoint b\n")}, nil)
	validated, err := validateWorkspaceRestoreArchive(archiveBytes, restoreTestWorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	defer validated.wipe()
	writeRestoreTestFile(t, root, "a.txt", "current\n")
	writeRestoreTestFile(t, root, "b.txt", "current b\n")
	err = applyWorkspaceRestore(context.Background(), root, validated, restoreFaults{failApplyAfter: 1, failRollbackAfter: 0})
	if err == nil || !strings.Contains(err.Error(), "rollback incomplete") {
		t.Fatalf("incomplete rollback error = %v", err)
	}
	journals, globErr := filepath.Glob(filepath.Join(root, ".git", "codex-mobile-restore-*"))
	if globErr != nil || len(journals) != 1 {
		t.Fatalf("private recovery journal was not retained: %#v, %v", journals, globErr)
	}
	info, statErr := os.Stat(journals[0])
	if statErr != nil || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		t.Fatalf("recovery journal was not private: %v %#o", statErr, info.Mode().Perm())
	}
}

func TestWorkspaceRestoreArchiveRejectsLegacyTamperedOversizedAndSpecialEntries(t *testing.T) {
	ordinary := []byte("ordinary\n")
	entry := restoreTestEntry("file.txt", string(ordinary))
	tests := []struct {
		name      string
		manifest  CheckpointManifest
		files     map[string][]byte
		fileModes map[string]fs.FileMode
		legacy    bool
	}{
		{name: "legacy", manifest: CheckpointManifest{Version: 1, Entries: []CheckpointEntry{entry}}, files: map[string][]byte{"file.txt": ordinary}, legacy: true},
		{name: "tampered digest", manifest: CheckpointManifest{Version: CheckpointArchiveVersion, WorkspaceID: restoreTestWorkspaceID, Entries: []CheckpointEntry{{Path: "file.txt", Size: int64(len(ordinary)), SHA256: strings.Repeat("0", 64), Mode: 0o600}}}, files: map[string][]byte{"file.txt": ordinary}},
		{name: "case conflict", manifest: CheckpointManifest{Version: CheckpointArchiveVersion, WorkspaceID: restoreTestWorkspaceID, Entries: []CheckpointEntry{entry, restoreTestEntry("FILE.txt", string(ordinary))}}, files: map[string][]byte{"file.txt": ordinary, "FILE.txt": ordinary}},
		{name: "hierarchy conflict", manifest: CheckpointManifest{Version: CheckpointArchiveVersion, WorkspaceID: restoreTestWorkspaceID, Entries: []CheckpointEntry{entry, restoreTestEntry("file.txt/child", string(ordinary))}}, files: map[string][]byte{"file.txt": ordinary, "file.txt/child": ordinary}},
		{name: "symlink entry", manifest: CheckpointManifest{Version: CheckpointArchiveVersion, WorkspaceID: restoreTestWorkspaceID, Entries: []CheckpointEntry{entry}}, files: map[string][]byte{"file.txt": ordinary}, fileModes: map[string]fs.FileMode{"file.txt": os.ModeSymlink | 0o777}},
		{name: "fifo entry", manifest: CheckpointManifest{Version: CheckpointArchiveVersion, WorkspaceID: restoreTestWorkspaceID, Entries: []CheckpointEntry{entry}}, files: map[string][]byte{"file.txt": ordinary}, fileModes: map[string]fs.FileMode{"file.txt": os.ModeNamedPipe | 0o600}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			archiveBytes := makeRestoreArchive(t, test.manifest, test.files, test.fileModes)
			_, err := validateWorkspaceRestoreArchive(archiveBytes, restoreTestWorkspaceID)
			if test.legacy {
				if !errors.Is(err, errLegacyWorkspaceRestore) {
					t.Fatalf("legacy error = %v", err)
				}
			} else if err == nil {
				t.Fatal("malicious archive was accepted")
			}
		})
	}

	oversized := bytes.Repeat([]byte{'x'}, MaxCheckpointFileBytes+1)
	oversizedEntry := restoreTestEntry("large.bin", string(oversized))
	archiveBytes := makeRestoreArchive(t, CheckpointManifest{
		Version: CheckpointArchiveVersion, WorkspaceID: restoreTestWorkspaceID, Entries: []CheckpointEntry{oversizedEntry},
	}, map[string][]byte{"large.bin": oversized}, nil)
	if _, err := validateWorkspaceRestoreArchive(archiveBytes, restoreTestWorkspaceID); err == nil {
		t.Fatal("oversized expanded entry was accepted")
	}
}

func makeRestoreArchive(t *testing.T, manifest CheckpointManifest, files map[string][]byte, modes map[string]fs.FileMode) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for path, content := range files {
		header := &zip.FileHeader{Name: "files/" + path, Method: zip.Deflate}
		mode := fs.FileMode(0o600)
		if configured, ok := modes[path]; ok {
			mode = configured
		}
		header.SetMode(mode)
		entry, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	header := &zip.FileHeader{Name: CheckpointManifestName, Method: zip.Deflate}
	header.SetMode(0o600)
	manifestEntry, err := writer.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manifestEntry.Write(manifestBytes); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func restoreTestEntry(path, content string) CheckpointEntry {
	digest := sha256.Sum256([]byte(content))
	return CheckpointEntry{Path: path, SHA256: hex.EncodeToString(digest[:]), Size: int64(len(content)), Mode: 0o600}
}

func restoreTestRepository(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}
	root := t.TempDir()
	restoreTestGit(t, root, "init")
	restoreTestGit(t, root, "config", "user.name", "Restore Test")
	restoreTestGit(t, root, "config", "user.email", "restore@example.test")
	writeRestoreTestFile(t, root, "tracked.txt", "base tracked\n")
	writeRestoreTestFile(t, root, "deleted.txt", "base deleted\n")
	restoreTestGit(t, root, "add", "tracked.txt", "deleted.txt")
	restoreTestGit(t, root, "commit", "-m", "initial")
	return root
}

func restoreTestHead(t *testing.T, root string) string {
	t.Helper()
	cmd := exec.Command("git", "-C", root, "rev-parse", "HEAD")
	output, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(output))
}

func restoreTestGit(t *testing.T, root string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
}

func writeRestoreTestFile(t *testing.T, root, path, content string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readRestoreTestFile(t *testing.T, root, path string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func manifestContainsDeleted(manifest CheckpointManifest, path string) bool {
	for _, entry := range manifest.Entries {
		if entry.Path == path && entry.Deleted {
			return true
		}
	}
	return false
}
