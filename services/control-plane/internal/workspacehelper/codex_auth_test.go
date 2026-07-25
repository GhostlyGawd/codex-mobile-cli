package workspacehelper

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var testChatGPTAuth = []byte(`{"auth_mode":"chatgpt","OPENAI_API_KEY":null,"tokens":{"access_token":"access-secret","refresh_token":"refresh-secret"}}`)

func TestCodexAuthEnvelopeAuthenticatesAndRejectsTamper(t *testing.T) {
	key := bytes.Repeat([]byte{0x31}, CodexAuthKeyBytes)
	encoded, err := sealCodexAuth(key, testChatGPTAuth, bytes.NewReader(bytes.Repeat([]byte{0x72}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("access-secret")) || bytes.Contains(encoded, []byte("refresh-secret")) {
		t.Fatal("credential plaintext appeared in the durable envelope")
	}
	opened, err := openCodexAuth(key, encoded)
	if err != nil || !bytes.Equal(opened, testChatGPTAuth) {
		t.Fatalf("open authenticated envelope: %v", err)
	}
	wipeBytes(opened)

	var envelope codexAuthEnvelope
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[len(ciphertext)-1] ^= 0x80
	envelope.Ciphertext = base64.RawURLEncoding.EncodeToString(ciphertext)
	tampered, _ := json.Marshal(envelope)
	if plaintext, err := openCodexAuth(key, tampered); err == nil {
		wipeBytes(plaintext)
		t.Fatal("tampered credential envelope authenticated")
	}
	wrongKey := bytes.Repeat([]byte{0x32}, CodexAuthKeyBytes)
	if plaintext, err := openCodexAuth(wrongKey, encoded); err == nil {
		wipeBytes(plaintext)
		t.Fatal("credential envelope opened with a different workspace key")
	}
}

func TestCodexAuthManagerLeavesNoPlaintextAtRest(t *testing.T) {
	parent, temporaryRoot := t.TempDir(), t.TempDir()
	root := filepath.Join(parent, "repository")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	manager, err := newCodexAuthManager(root, temporaryRoot, bytes.NewReader(bytes.Repeat([]byte{0x44}, 256)))
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x19}, CodexAuthKeyBytes)
	if err := manager.configure(key); err != nil {
		t.Fatal(err)
	}
	if err := atomicPrivateFile(manager.paths.runtimeAuth, testChatGPTAuth); err != nil {
		t.Fatal(err)
	}
	if plaintext, err := readPrivateFile(manager.paths.runtimeAuth, maxCodexAuthBytes); err != nil {
		t.Fatalf("read materialized auth before seal: %v", err)
	} else {
		if err := validateCodexAuth(plaintext); err != nil {
			t.Fatalf("validate materialized auth before seal: %v", err)
		}
		wipeBytes(plaintext)
	}
	if err := manager.seal(key); err != nil {
		t.Fatal(err)
	}
	if err := manager.purgeMaterialized(); err != nil {
		t.Fatal(err)
	}
	durable, err := os.ReadFile(manager.paths.encryptedAuth)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(durable, []byte("access-secret")) || bytes.Contains(durable, []byte("refresh-secret")) {
		t.Fatal("workspace volume contains Codex credential plaintext")
	}
	if err := filepath.WalkDir(parent, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(content, []byte("access-secret")) || bytes.Contains(content, []byte("refresh-secret")) {
			return errors.New("persistent workspace scan found credential plaintext")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{manager.paths.runtimeAuth, manager.paths.persistentAuth} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("materialized credential remained at %s: %v", path, err)
		}
	}
	if err := manager.materialize(key); err != nil {
		t.Fatal(err)
	}
	materialized, err := os.ReadFile(manager.paths.runtimeAuth)
	if err != nil || !bytes.Equal(materialized, testChatGPTAuth) {
		t.Fatalf("materialize sealed credential: %v", err)
	}
	wipeBytes(materialized)
	if err := manager.purgeMaterialized(); err != nil {
		t.Fatal(err)
	}
}

func TestCodexAuthConcurrentLeasesSealOnlyAfterLastExit(t *testing.T) {
	parent, temporaryRoot := t.TempDir(), t.TempDir()
	root := filepath.Join(parent, "repository")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	manager, err := newCodexAuthManager(root, temporaryRoot, nil)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x27}, CodexAuthKeyBytes)
	if err := manager.configure(key); err != nil {
		t.Fatal(err)
	}
	if err := atomicPrivateFile(manager.paths.runtimeAuth, testChatGPTAuth); err != nil {
		t.Fatal(err)
	}
	if err := manager.seal(key); err != nil {
		t.Fatal(err)
	}
	if err := manager.purgeMaterialized(); err != nil {
		t.Fatal(err)
	}
	first, err := manager.begin()
	if err != nil {
		if errors.Is(err, errCodexAuthUnavailable) && os.PathSeparator == '\\' {
			t.Skip("Windows development host does not permit an unprivileged auth symlink")
		}
		t.Fatal(err)
	}
	second, err := manager.begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicPrivateFile(manager.paths.runtimeAuth, testChatGPTAuth); err != nil {
		t.Fatal(err)
	}
	if err := first.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(manager.paths.runtimeAuth); err != nil {
		t.Fatal("one concurrent exit purged live auth state")
	}
	if err := second.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(manager.paths.runtimeAuth); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("last concurrent exit did not purge plaintext auth state")
	}
	if _, err := os.Stat(manager.paths.encryptedAuth); err != nil {
		t.Fatal("last concurrent exit did not persist encrypted auth state")
	}
}

func TestCodexLauncherRejectsAPIKeyAndScrubsEnvironment(t *testing.T) {
	if codexArgumentsAllowed([]string{"login", "--with-api-key"}) || codexArgumentsAllowed([]string{"--with-api-key=secret"}) ||
		codexArgumentsAllowed([]string{"-c", "forced_login_method=api"}) {
		t.Fatal("API-key login launcher arguments were accepted")
	}
	if !codexArgumentsAllowed([]string{"login", "--device-auth"}) {
		t.Fatal("ChatGPT device login launcher arguments were rejected")
	}
	if !isDeviceAuthLogin([]string{"login", "--device-auth"}) || isDeviceAuthLogin([]string{"login"}) || isDeviceAuthLogin([]string{"--strict-config"}) {
		t.Fatal("unauthenticated Codex exception was broader than exact device auth")
	}
	environment := sanitizedCodexEnvironment([]string{
		"PATH=/hostile/bin", "CODEX_HOME=/hostile/home", "OPENAI_API_KEY=secret", "CODEX_API_KEY=secret", "SAFE=value",
	}, "/workspaces/.codex-home")
	joined := strings.Join(environment, "\n")
	if strings.Contains(joined, "secret") || strings.Contains(joined, "/hostile/home") ||
		!strings.Contains(joined, "CODEX_HOME=/workspaces/.codex-home") ||
		!strings.Contains(joined, "PATH="+trustedCodexDirectory+string(os.PathListSeparator)) {
		t.Fatal("launcher environment retained a forbidden credential or path")
	}
	inherited := strings.Join(inheritedTerminalEnvironment([]string{
		"PATH=/usr/bin", "TERM=xterm-256color", "CODER_AGENT_TOKEN=agent-secret",
		"DATABASE_URL=postgres://private", "BASH_ENV=/workspaces/repository/hostile",
	}), "\n")
	if !strings.Contains(inherited, "PATH=/usr/bin") || !strings.Contains(inherited, "TERM=xterm-256color") {
		t.Fatal("direct Codex wrapper omitted its safe inherited environment")
	}
	for _, forbidden := range []string{"CODER_AGENT_TOKEN", "DATABASE_URL", "BASH_ENV"} {
		if strings.Contains(inherited, forbidden) {
			t.Fatalf("direct Codex wrapper inherited privileged environment %q", forbidden)
		}
	}
}

func TestCodexAuthManagerRequiresValidatedAuthExceptForExactDeviceLogin(t *testing.T) {
	parent, temporaryRoot := t.TempDir(), t.TempDir()
	root := filepath.Join(parent, "repository")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	manager, err := newCodexAuthManager(root, temporaryRoot, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.configure(bytes.Repeat([]byte{0x53}, CodexAuthKeyBytes)); err != nil {
		t.Fatal(err)
	}
	if session, err := manager.begin(); err == nil {
		_ = session.close()
		t.Fatal("normal Codex launch proceeded without validated ChatGPT auth")
	}
	session, err := manager.beginDeviceLogin()
	if err != nil {
		if errors.Is(err, errCodexAuthUnavailable) && os.PathSeparator == '\\' {
			t.Skip("Windows development host does not permit an unprivileged auth symlink")
		}
		t.Fatalf("exact device login was blocked: %v", err)
	}
	if err := session.close(); err != nil {
		t.Fatal(err)
	}
}

func TestSensitiveHelperRequestIsZeroed(t *testing.T) {
	key := bytes.Repeat([]byte{0x61}, CodexAuthKeyBytes)
	alias := key
	request := Request{
		GitHubToken: "github-secret", CodexAuthKey: key,
		Environment:    map[string]string{"TOKEN": "environment-secret"},
		GrantedSecrets: map[string][]byte{"GRANTED": []byte("granted-secret")},
	}
	grantedAlias := request.GrantedSecrets["GRANTED"]
	scrubSensitiveRequest(&request)
	if request.GitHubToken != "" || request.CodexAuthKey != nil || len(request.Environment) != 0 || request.GrantedSecrets != nil {
		t.Fatalf("helper request retained sensitive fields: %#v", request)
	}
	if !bytes.Equal(alias, make([]byte, CodexAuthKeyBytes)) {
		t.Fatal("decoded workspace auth key buffer was not zeroed")
	}
	if !bytes.Equal(grantedAlias, make([]byte, len(grantedAlias))) {
		t.Fatal("decoded granted secret buffer was not zeroed")
	}
}

func TestCodexAuthRejectsNonChatGPTState(t *testing.T) {
	for _, content := range [][]byte{
		[]byte(`{"auth_mode":"apikey","OPENAI_API_KEY":"sk-secret"}`),
		[]byte(`{"auth_mode":"personalAccessToken","personal_access_token":"secret"}`),
		[]byte(`{"auth_mode":"chatgpt","agent_identity":{"agent_private_key":"secret"}}`),
	} {
		if err := validateCodexAuth(content); err == nil {
			t.Fatal("non-ChatGPT credential state was accepted")
		}
	}
}
