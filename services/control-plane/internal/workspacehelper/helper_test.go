package workspacehelper

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGitHubHelperOperationsRequireIndependentDeadline(t *testing.T) {
	for _, request := range []Request{
		{Version: Version, Operation: OpGitClone},
		{Version: Version, Operation: OpGitPull},
		{Version: Version, Operation: OpGitPush},
		{Version: Version, Operation: OpFileRead, GitHubToken: "sensitive"},
	} {
		if _, _, err := workspaceHelperRequestContext(context.Background(), &request); err == nil {
			t.Fatalf("operation %q accepted GitHub authority without deadline", request.Operation)
		}
	}
}

func TestWorkspaceHelperDeadlineIsValidatedAndCancelsRequest(t *testing.T) {
	for _, deadline := range []time.Time{time.Now().Add(-time.Second), time.Now().Add(maxRequestDeadlineFuture + time.Second)} {
		request := Request{Version: Version, Operation: OpGitPush, OperationDeadlineUnixMilli: deadline.UnixMilli()}
		if _, _, err := workspaceHelperRequestContext(context.Background(), &request); err == nil {
			t.Fatalf("invalid remote deadline %v was accepted", deadline)
		}
		if request.OperationDeadlineUnixMilli != 0 {
			t.Fatal("remote deadline was retained in the executable request")
		}
	}

	deadline := time.Now().Add(40 * time.Millisecond)
	request := Request{Version: Version, Operation: OpGitPush, OperationDeadlineUnixMilli: deadline.UnixMilli()}
	requestContext, cancel, err := workspaceHelperRequestContext(context.Background(), &request)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	if request.OperationDeadlineUnixMilli != 0 {
		t.Fatal("remote deadline was retained after deriving the bounded context")
	}
	select {
	case <-requestContext.Done():
		if !errors.Is(requestContext.Err(), context.DeadlineExceeded) {
			t.Fatalf("remote helper deadline = %v", requestContext.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("remote helper operation did not stop at its independent deadline")
	}
}

func TestFileRoundTripETagAndSensitiveDenial(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "hello.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("SECRET=value"), 0o600); err != nil {
		t.Fatal(err)
	}
	temporaryRoot := t.TempDir()
	if err := writeRuntimeSecrets(temporaryRoot, nil); err != nil {
		t.Fatal(err)
	}
	helper, _ := NewWithTemporaryRoot(root, temporaryRoot)
	read := call(t, helper, Request{Version: Version, Operation: OpFileRead, Path: "hello.txt"})
	if read.File == nil || read.File.Content != "hello" {
		t.Fatalf("unexpected read: %#v", read)
	}
	saved := call(t, helper, Request{Version: Version, Operation: OpFileSave, Path: "hello.txt", Content: "updated", ExpectedETag: read.File.ETag})
	if saved.File == nil || saved.File.Content != "updated" || saved.File.ETag == read.File.ETag {
		t.Fatalf("unexpected save: %#v", saved)
	}
	denied := callRaw(t, helper, Request{Version: Version, Operation: OpFileRead, Path: ".env"})
	if denied.OK || denied.ErrorCode != "forbidden" {
		t.Fatalf("sensitive path was exposed: %#v", denied)
	}
}

func TestGitStatusStageAndCommit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}
	root := t.TempDir()
	runGit(t, root, "init")
	runGit(t, root, "config", "user.name", "Test")
	runGit(t, root, "config", "user.email", "test@example.test")
	_ = os.WriteFile(filepath.Join(root, "file.txt"), []byte("one\n"), 0o600)
	runGit(t, root, "add", "file.txt")
	runGit(t, root, "commit", "-m", "initial")
	_ = os.WriteFile(filepath.Join(root, "file.txt"), []byte("two\n"), 0o600)
	temporaryRoot := t.TempDir()
	if err := writeRuntimeSecrets(temporaryRoot, nil); err != nil {
		t.Fatal(err)
	}
	helper, _ := NewWithTemporaryRoot(root, temporaryRoot)
	status := call(t, helper, Request{Version: Version, Operation: OpGitStatus})
	if status.GitStatus == nil || !status.GitStatus.Dirty {
		t.Fatalf("expected dirty status: %#v", status)
	}
	call(t, helper, Request{Version: Version, Operation: OpGitStage, Path: "file.txt", Staged: true})
	committed := call(t, helper, Request{Version: Version, Operation: OpGitCommit, CommitMessage: "mobile change", AuthorName: "Owner", AuthorEmail: "owner@example.test"})
	if committed.CommitSHA == "" || committed.GitStatus == nil || committed.GitStatus.Dirty {
		t.Fatalf("unexpected commit response: %#v", committed)
	}
}

func TestConfigureWorkspaceKeepsEnvironmentOutsideRepository(t *testing.T) {
	parent := t.TempDir()
	temporaryRoot := t.TempDir()
	root := filepath.Join(parent, "repository")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	legacyState := filepath.Join(parent, ".codex-mobile")
	if err := os.Mkdir(legacyState, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacyState, "environment.json"), []byte(`{"OLD_TOKEN":"legacy-secret"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	helper, _ := NewWithTemporaryRoot(root, temporaryRoot)
	configured := call(t, helper, Request{
		Version: Version, Operation: OpConfigure, SafetyMode: "balanced", Network: true,
		Environment:    map[string]string{"EXAMPLE_API_TOKEN": "sensitive-value"},
		GrantedSecrets: map[string][]byte{"GRANTED_TOKEN": []byte("granted-runtime-secret")},
		CodexAuthKey:   bytes.Repeat([]byte{0x42}, CodexAuthKeyBytes),
	})
	if !configured.OK {
		t.Fatalf("configuration failed: %#v", configured)
	}
	if _, err := os.Stat(filepath.Join(root, ".env")); !os.IsNotExist(err) {
		t.Fatal("environment was written into the repository")
	}
	data, err := os.ReadFile(filepath.Join(temporaryRoot, "codex-mobile-runtime", "environment.json"))
	if err != nil || !bytes.Contains(data, []byte("sensitive-value")) {
		t.Fatalf("tmpfs runtime environment state missing: %v", err)
	}
	secretData, err := os.ReadFile(filepath.Join(temporaryRoot, "codex-mobile-runtime", "secrets.json"))
	if err != nil || bytes.Contains(secretData, []byte("granted-runtime-secret")) {
		t.Fatalf("tmpfs granted secret file is missing or not safely encoded: %v", err)
	}
	if persisted, err := os.ReadFile(filepath.Join(parent, ".codex-mobile", "environment.json")); !os.IsNotExist(err) || bytes.Contains(persisted, []byte("sensitive-value")) {
		t.Fatalf("environment plaintext persisted in workspace state: %v", err)
	}
	t.Setenv("CODER_AGENT_TOKEN", "must-never-reach-terminal")
	t.Setenv("CODER_AGENT_URL", "https://coder-control.invalid")
	t.Setenv("DATABASE_URL", "postgres://must-not-reach-terminal")
	t.Setenv("BASH_ENV", filepath.Join(root, "hostile-bash-env"))
	t.Setenv("TERM", "xterm-256color")
	loadedEnvironment, err := loadTerminalEnvironment(root, temporaryRoot)
	if err != nil || !stringSliceContains(loadedEnvironment, "EXAMPLE_API_TOKEN=sensitive-value") || !stringSliceContains(loadedEnvironment, "GRANTED_TOKEN=granted-runtime-secret") {
		t.Fatalf("terminal did not receive tmpfs environment: %v", err)
	}
	joinedEnvironment := strings.Join(loadedEnvironment, "\n")
	for _, forbidden := range []string{"CODER_AGENT_TOKEN=", "CODER_AGENT_URL=", "DATABASE_URL=", "BASH_ENV="} {
		if strings.Contains(joinedEnvironment, forbidden) {
			t.Fatalf("terminal inherited privileged environment %q", forbidden)
		}
	}
	if !stringSliceContains(loadedEnvironment, "TERM=xterm-256color") {
		t.Fatal("terminal allowlist omitted the safe terminal type")
	}
	if persistentTreeContains(t, parent, []byte("granted-runtime-secret")) {
		t.Fatal("granted secret plaintext persisted outside tmpfs")
	}
	if _, err := loadTerminalEnvironment(root, t.TempDir()); err == nil {
		t.Fatal("terminal launch did not fail closed without configured tmpfs state")
	}
	config, err := os.ReadFile(filepath.Join(parent, ".codex-home", "config.toml"))
	if err != nil || bytes.Contains(config, []byte("sensitive-value")) || !bytes.Contains(config, []byte("sandbox_mode = \"workspace-write\"")) ||
		!bytes.Contains(config, []byte("cli_auth_credentials_store = \"file\"")) || !bytes.Contains(config, []byte("forced_login_method = \"chatgpt\"")) {
		t.Fatalf("managed Codex config invalid: %v: %s", err, config)
	}
	denied := callRaw(t, helper, Request{
		Version: Version, Operation: OpConfigure, SafetyMode: "balanced",
		Environment: map[string]string{"PATH": "/hostile"}, CodexAuthKey: bytes.Repeat([]byte{0x42}, CodexAuthKeyBytes),
	})
	if denied.OK || denied.ErrorCode != "invalid" {
		t.Fatalf("reserved environment override accepted: %#v", denied)
	}
}

func persistentTreeContains(t *testing.T, root string, value []byte) bool {
	t.Helper()
	found := false
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		found = found || bytes.Contains(content, value)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

func TestHelperGitScannerUsesOnlyTmpfsGrantedValuesAndSealDeletesThem(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}
	root := initializedRepository(t)
	temporaryRoot := t.TempDir()
	secret := []byte("runtime-grant-secret-123")
	if err := writeRuntimeSecrets(temporaryRoot, map[string][]byte{"GRANTED_TOKEN": secret}); err != nil {
		t.Fatal(err)
	}
	helper, err := NewWithTemporaryRoot(root, temporaryRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tracked.txt"), []byte("token="+string(secret)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	blocked := callRaw(t, helper, Request{Version: Version, Operation: OpGitStage, Path: "tracked.txt", Staged: true, GrantedSecrets: map[string][]byte{"GRANTED_TOKEN": secret}})
	if blocked.OK || strings.Contains(blocked.Error, string(secret)) {
		t.Fatalf("granted value was not generically blocked: %#v", blocked)
	}
	if err := os.WriteFile(filepath.Join(root, "tracked.txt"), []byte("ordinary work\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	call(t, helper, Request{Version: Version, Operation: OpGitStage, Path: "tracked.txt", Staged: true, GrantedSecrets: map[string][]byte{"GRANTED_TOKEN": secret}})
	_ = callRaw(t, helper, Request{Version: Version, Operation: OpCheckpointExport, CheckpointWorkspaceID: "ws_aaaaaaaaaaaaaaaa"})
	if _, err := os.Lstat(runtimeSecretsPath(temporaryRoot)); err != nil {
		t.Fatalf("ordinary checkpoint removed live runtime grants: %v", err)
	}
	_ = callRaw(t, helper, Request{Version: Version, Operation: OpCheckpointExport, CheckpointWorkspaceID: "ws_aaaaaaaaaaaaaaaa", CheckpointSeal: true})
	if _, err := os.Lstat(runtimeSecretsPath(temporaryRoot)); !os.IsNotExist(err) {
		t.Fatalf("checkpoint seal retained granted runtime secrets: %v", err)
	}
	sealed := callRaw(t, helper, Request{Version: Version, Operation: OpGitCommit, CommitMessage: "after seal", GrantedSecrets: map[string][]byte{"GRANTED_TOKEN": secret}})
	if sealed.OK || sealed.ErrorCode != "precondition" {
		t.Fatalf("Git mutation did not fail closed after runtime secret seal: %#v", sealed)
	}
}

func stringSliceContains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func TestCheckpointExportCapturesTrackedAndUntrackedButExcludesSensitivePaths(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}
	root := initializedRepository(t)
	if err := os.WriteFile(filepath.Join(root, "tracked.txt"), []byte("dirty tracked\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "untracked.txt"), []byte("untracked work\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env.local"), []byte("TOKEN=must-not-leave\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	helper, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	response := call(t, helper, Request{Version: Version, Operation: OpCheckpointExport, CheckpointWorkspaceID: "ws_aaaaaaaaaaaaaaaa"})
	if response.GitStatus == nil || !response.GitStatus.Dirty || response.Checkpoint == nil {
		t.Fatalf("checkpoint response = %#v", response)
	}
	if response.Checkpoint.CompressedBytes > MaxCheckpointArchiveBytes || response.Checkpoint.ExpandedBytes > MaxCheckpointExpandedBytes {
		t.Fatalf("checkpoint exceeded bounds: %#v", response.Checkpoint)
	}
	archive, err := base64.StdEncoding.DecodeString(response.Checkpoint.ArchiveBase64)
	if err != nil {
		t.Fatal(err)
	}
	files, manifest := inspectCheckpointArchive(t, archive)
	if string(files["tracked.txt"]) != "dirty tracked\n" || string(files["untracked.txt"]) != "untracked work\n" {
		t.Fatalf("checkpoint contents = %#v", files)
	}
	if _, present := files[".env.local"]; present || manifest.OmittedSensitive != 1 || bytes.Contains(archive, []byte("must-not-leave")) {
		t.Fatalf("sensitive file escaped checkpoint: manifest=%#v", manifest)
	}
	if _, err := os.Stat(filepath.Join(root, ".codex-mobile", "checkpoints")); !os.IsNotExist(err) {
		t.Fatal("checkpoint data was written inside the repository")
	}
}

func TestCheckpointExportFailsClosedForOversizedNonSensitiveWork(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}
	root := initializedRepository(t)
	large := bytes.Repeat([]byte("x"), MaxCheckpointFileBytes+1)
	if err := os.WriteFile(filepath.Join(root, "large.bin"), large, 0o600); err != nil {
		t.Fatal(err)
	}
	helper, _ := New(root)
	response := callRaw(t, helper, Request{Version: Version, Operation: OpCheckpointExport, CheckpointWorkspaceID: "ws_aaaaaaaaaaaaaaaa"})
	if response.OK || response.Checkpoint != nil {
		t.Fatalf("oversized checkpoint unexpectedly succeeded: %#v", response)
	}
}

func TestCheckpointRestoreRejectsTraversalAndSensitivePaths(t *testing.T) {
	root := t.TempDir()
	helper, _ := New(root)
	content := base64.StdEncoding.EncodeToString([]byte("restored"))
	for _, path := range []string{"../escape", ".env", "secrets/token.txt"} {
		response := callRaw(t, helper, Request{
			Version: Version, Operation: OpCheckpointRestoreFile, Path: path, Content: content,
			CheckpointContentSHA256: "f60c65b75f01d5a670c3b44c3dd10f6bc79a022e2ff8d5bb0de14e40e7a20f3b",
		})
		if response.OK {
			t.Fatalf("restore accepted unsafe path %q", path)
		}
	}
}

func initializedRepository(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	runGit(t, root, "init")
	runGit(t, root, "config", "user.name", "Test")
	runGit(t, root, "config", "user.email", "test@example.test")
	if err := os.WriteFile(filepath.Join(root, "tracked.txt"), []byte("base\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "add", "tracked.txt")
	runGit(t, root, "commit", "-m", "initial")
	return root
}

func inspectCheckpointArchive(t *testing.T, data []byte) (map[string][]byte, CheckpointManifest) {
	t.Helper()
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	files := make(map[string][]byte)
	var manifest CheckpointManifest
	for _, entry := range reader.File {
		opened, err := entry.Open()
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(opened)
		_ = opened.Close()
		if err != nil {
			t.Fatal(err)
		}
		if entry.Name == CheckpointManifestName {
			if err := json.Unmarshal(content, &manifest); err != nil {
				t.Fatal(err)
			}
			continue
		}
		files[strings.TrimPrefix(entry.Name, "files/")] = content
	}
	return files, manifest
}

func call(t *testing.T, helper *Helper, request Request) Response {
	t.Helper()
	response := callRaw(t, helper, request)
	if !response.OK {
		t.Fatalf("helper failed: %#v", response)
	}
	return response
}

func callRaw(t *testing.T, helper *Helper, request Request) Response {
	t.Helper()
	data, _ := json.Marshal(request)
	var output bytes.Buffer
	if err := helper.Serve(context.Background(), bytes.NewReader(data), &output); err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.Unmarshal(output.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func runGit(t *testing.T, root string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
}
