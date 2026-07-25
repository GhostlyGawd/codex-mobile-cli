package workspacehelper

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/terminal"
)

const (
	CodexAuthKeyBytes     = 32
	maxCodexAuthBytes     = 1 << 20
	trustedCodexDirectory = "/opt/codex-mobile-helper"
	TrustedCodexPath      = trustedCodexDirectory + "/codex-real"
	authEnvelopeVersion   = 1
	tmuxCommandTimeout    = 5 * time.Second
	tmuxCommandWaitDelay  = time.Second
)

var (
	errCodexAuthUnavailable = errors.New("Codex authentication state is unavailable")
	errCodexAuthInUse       = errors.New("Codex authentication state is in use")
	authAAD                 = []byte("codex-mobile:codex-auth:v1")
)

type codexAuthEnvelope struct {
	Version    int    `json:"version"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type codexAuthPaths struct {
	key            string
	runtimeDir     string
	runtimeAuth    string
	leaseDir       string
	lock           string
	persistentHome string
	persistentAuth string
	encryptedAuth  string
}

type codexAuthManager struct {
	paths  codexAuthPaths
	random io.Reader
}

type codexAuthSession struct {
	manager *codexAuthManager
	lease   string
}

func newCodexAuthManager(root, temporaryRoot string, randomSource io.Reader) (*codexAuthManager, error) {
	if root == "" {
		root = DefaultRoot
	}
	if temporaryRoot == "" {
		temporaryRoot = os.TempDir()
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	temporaryRoot, err = filepath.Abs(temporaryRoot)
	if err != nil || !filepath.IsAbs(temporaryRoot) {
		return nil, errors.New("Codex authentication temporary root is invalid")
	}
	if randomSource == nil {
		randomSource = rand.Reader
	}
	workspaceParent := filepath.Dir(root)
	// Each isolated container owns one workspace and mounts /tmp as tmpfs in
	// both plain and approved-Dev-Container modes.
	runtimeDir := filepath.Join(temporaryRoot, "codex-mobile-runtime")
	stateDir := filepath.Join(workspaceParent, ".codex-mobile")
	home := filepath.Join(workspaceParent, ".codex-home")
	return &codexAuthManager{
		paths: codexAuthPaths{
			key:            filepath.Join(runtimeDir, "key"),
			runtimeDir:     runtimeDir,
			runtimeAuth:    filepath.Join(runtimeDir, "auth.json"),
			leaseDir:       filepath.Join(runtimeDir, "leases"),
			lock:           filepath.Join(runtimeDir, "state.lock"),
			persistentHome: home,
			persistentAuth: filepath.Join(home, "auth.json"),
			encryptedAuth:  filepath.Join(stateDir, "codex-auth.json.enc"),
		},
		random: randomSource,
	}, nil
}

// configure installs the envelope key only in the container's tmpfs. The
// control plane calls it after every provision/resume, and never persists the
// unwrapped key in the workspace volume.
func (m *codexAuthManager) configure(key []byte) error {
	if len(key) != CodexAuthKeyBytes {
		return errCodexAuthUnavailable
	}
	if err := ensurePrivateDirectory(m.paths.runtimeDir); err != nil {
		return errCodexAuthUnavailable
	}
	if err := ensurePrivateDirectory(m.paths.leaseDir); err != nil {
		return errCodexAuthUnavailable
	}
	if err := ensurePrivateDirectory(m.paths.persistentHome); err != nil {
		return errCodexAuthUnavailable
	}
	if err := ensurePrivateDirectory(filepath.Dir(m.paths.encryptedAuth)); err != nil {
		return errCodexAuthUnavailable
	}
	lock, err := acquireCodexAuthLock(m.paths.lock)
	if err != nil {
		return errCodexAuthUnavailable
	}
	defer lock.Close()

	if existing, readErr := readPrivateFile(m.paths.key, CodexAuthKeyBytes); readErr == nil {
		defer wipeBytes(existing)
		if len(existing) != CodexAuthKeyBytes || subtle.ConstantTimeCompare(existing, key) != 1 {
			return errCodexAuthUnavailable
		}
	} else if errors.Is(readErr, os.ErrNotExist) {
		if err := atomicPrivateFile(m.paths.key, key); err != nil {
			return errCodexAuthUnavailable
		}
	} else {
		return errCodexAuthUnavailable
	}

	// Authentication failure is detected during trusted configuration, before
	// an interactive process can consume a corrupted or key-swapped envelope.
	if encrypted, readErr := readPrivateFile(m.paths.encryptedAuth, 4*maxCodexAuthBytes); readErr == nil {
		plaintext, openErr := openCodexAuth(key, encrypted)
		wipeBytes(encrypted)
		if openErr != nil {
			return errCodexAuthUnavailable
		}
		defer wipeBytes(plaintext)
		if err := validateCodexAuth(plaintext); err != nil {
			return errCodexAuthUnavailable
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return errCodexAuthUnavailable
	}
	if err := m.validatePersistentAuthLink(); err != nil {
		return errCodexAuthUnavailable
	}
	return nil
}

func (m *codexAuthManager) begin() (*codexAuthSession, error) {
	return m.beginMode(false)
}

func (m *codexAuthManager) beginDeviceLogin() (*codexAuthSession, error) {
	return m.beginMode(true)
}

func (m *codexAuthManager) beginMode(allowUnauthenticated bool) (*codexAuthSession, error) {
	if err := ensurePrivateDirectory(m.paths.runtimeDir); err != nil {
		return nil, errCodexAuthUnavailable
	}
	if err := ensurePrivateDirectory(m.paths.leaseDir); err != nil {
		return nil, errCodexAuthUnavailable
	}
	lock, err := acquireCodexAuthLock(m.paths.lock)
	if err != nil {
		return nil, errCodexAuthUnavailable
	}
	defer lock.Close()
	key, err := m.loadKey()
	if err != nil {
		return nil, errCodexAuthUnavailable
	}
	defer wipeBytes(key)
	leases, err := m.activeLeases()
	if err != nil {
		return nil, errCodexAuthUnavailable
	}
	if leases == 0 {
		// A process that died before its normal sealing defer may have left a
		// tmpfs copy. The authenticated persistent envelope is authoritative.
		if err := secureRemove(m.paths.runtimeAuth); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, errCodexAuthUnavailable
		}
		if err := m.materialize(key); err != nil {
			return nil, errCodexAuthUnavailable
		}
	}
	if !allowUnauthenticated {
		materialized, err := readPrivateFile(m.paths.runtimeAuth, maxCodexAuthBytes)
		if err != nil {
			return nil, errCodexAuthUnavailable
		}
		validationErr := validateCodexAuth(materialized)
		wipeBytes(materialized)
		if validationErr != nil {
			return nil, errCodexAuthUnavailable
		}
	}
	if err := m.ensurePersistentAuthLink(); err != nil {
		return nil, errCodexAuthUnavailable
	}
	lease, err := m.createLease()
	if err != nil {
		return nil, errCodexAuthUnavailable
	}
	return &codexAuthSession{manager: m, lease: lease}, nil
}

func (s *codexAuthSession) close() error {
	if s == nil || s.manager == nil || s.lease == "" {
		return nil
	}
	m := s.manager
	lock, err := acquireCodexAuthLock(m.paths.lock)
	if err != nil {
		return errCodexAuthUnavailable
	}
	defer lock.Close()
	if err := os.Remove(s.lease); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errCodexAuthUnavailable
	}
	s.lease = ""
	remaining, err := m.activeLeases()
	if err != nil {
		return errCodexAuthUnavailable
	}
	if remaining != 0 {
		return nil
	}
	key, err := m.loadKey()
	if err != nil {
		return errCodexAuthUnavailable
	}
	defer wipeBytes(key)
	if err := m.seal(key); err != nil {
		return errCodexAuthUnavailable
	}
	return m.purgeMaterialized()
}

// sealBoundary snapshots auth state before checkpoint/suspend/delete. An
// active Codex process keeps its tmpfs file; a quiescent workspace is purged.
func (m *codexAuthManager) sealBoundary() error {
	if _, err := os.Lstat(m.paths.key); errors.Is(err, os.ErrNotExist) {
		if _, cipherErr := os.Lstat(m.paths.encryptedAuth); errors.Is(cipherErr, os.ErrNotExist) {
			if _, plainErr := os.Lstat(m.paths.runtimeAuth); errors.Is(plainErr, os.ErrNotExist) {
				return nil
			}
		}
		return errCodexAuthUnavailable
	}
	lock, err := acquireCodexAuthLock(m.paths.lock)
	if err != nil {
		return errCodexAuthUnavailable
	}
	defer lock.Close()
	key, err := m.loadKey()
	if err != nil {
		return errCodexAuthUnavailable
	}
	defer wipeBytes(key)
	leases, err := m.activeLeases()
	if err != nil {
		return errCodexAuthUnavailable
	}
	if _, statErr := os.Lstat(m.paths.runtimeAuth); statErr == nil {
		if err := m.seal(key); err != nil {
			return errCodexAuthUnavailable
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return errCodexAuthUnavailable
	}
	if leases == 0 {
		return m.purgeMaterialized()
	}
	return nil
}

func (m *codexAuthManager) materialize(key []byte) error {
	encrypted, err := readPrivateFile(m.paths.encryptedAuth, 4*maxCodexAuthBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errCodexAuthUnavailable
	}
	defer wipeBytes(encrypted)
	plaintext, err := openCodexAuth(key, encrypted)
	if err != nil {
		return errCodexAuthUnavailable
	}
	defer wipeBytes(plaintext)
	if err := validateCodexAuth(plaintext); err != nil {
		return errCodexAuthUnavailable
	}
	return atomicPrivateFile(m.paths.runtimeAuth, plaintext)
}

func (m *codexAuthManager) seal(key []byte) error {
	plaintext, err := readPrivateFile(m.paths.runtimeAuth, maxCodexAuthBytes)
	if errors.Is(err, os.ErrNotExist) {
		// Codex logout removes auth.json. Mirror that deletion into the durable
		// encrypted state only after all concurrent wrapper leases have exited.
		if removeErr := os.Remove(m.paths.encryptedAuth); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return errCodexAuthUnavailable
		}
		return nil
	}
	if err != nil {
		return errCodexAuthUnavailable
	}
	defer wipeBytes(plaintext)
	if err := validateCodexAuth(plaintext); err != nil {
		return errCodexAuthUnavailable
	}
	encoded, err := sealCodexAuth(key, plaintext, m.random)
	if err != nil {
		return errCodexAuthUnavailable
	}
	defer wipeBytes(encoded)
	if err := atomicPrivateFile(m.paths.encryptedAuth, encoded); err != nil {
		return errCodexAuthUnavailable
	}
	return nil
}

func (m *codexAuthManager) loadKey() ([]byte, error) {
	key, err := readPrivateFile(m.paths.key, CodexAuthKeyBytes)
	if err != nil || len(key) != CodexAuthKeyBytes {
		wipeBytes(key)
		return nil, errCodexAuthUnavailable
	}
	return key, nil
}

func (m *codexAuthManager) createLease() (string, error) {
	randomID := make([]byte, 16)
	defer wipeBytes(randomID)
	if _, err := io.ReadFull(m.random, randomID); err != nil {
		return "", err
	}
	name := strconv.Itoa(os.Getpid()) + "-" + hex.EncodeToString(randomID)
	path := filepath.Join(m.paths.leaseDir, name)
	if err := atomicPrivateFile(path, []byte(strconv.Itoa(os.Getpid()))); err != nil {
		return "", err
	}
	return path, nil
}

func (m *codexAuthManager) activeLeases() (int, error) {
	entries, err := os.ReadDir(m.paths.leaseDir)
	if err != nil {
		return 0, err
	}
	active := 0
	for _, entry := range entries {
		if entry.IsDir() || strings.ContainsAny(entry.Name(), "/\\\x00\r\n") {
			return 0, errCodexAuthUnavailable
		}
		path := filepath.Join(m.paths.leaseDir, entry.Name())
		content, err := readPrivateFile(path, 32)
		if err != nil {
			return 0, errCodexAuthUnavailable
		}
		pid, parseErr := strconv.Atoi(string(content))
		wipeBytes(content)
		if parseErr != nil || pid <= 0 {
			return 0, errCodexAuthUnavailable
		}
		if !codexProcessAlive(pid) {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return 0, errCodexAuthUnavailable
			}
			continue
		}
		active++
	}
	return active, nil
}

func (m *codexAuthManager) validatePersistentAuthLink() error {
	info, err := os.Lstat(m.paths.persistentAuth)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return errCodexAuthUnavailable
	}
	target, err := os.Readlink(m.paths.persistentAuth)
	if err != nil || filepath.Clean(target) != filepath.Clean(m.paths.runtimeAuth) {
		return errCodexAuthUnavailable
	}
	return nil
}

func (m *codexAuthManager) ensurePersistentAuthLink() error {
	if err := ensurePrivateDirectory(m.paths.persistentHome); err != nil {
		return err
	}
	if err := m.validatePersistentAuthLink(); err != nil {
		return err
	}
	if _, err := os.Lstat(m.paths.persistentAuth); errors.Is(err, os.ErrNotExist) {
		return os.Symlink(m.paths.runtimeAuth, m.paths.persistentAuth)
	} else {
		return err
	}
}

func (m *codexAuthManager) purgeMaterialized() error {
	if info, err := os.Lstat(m.paths.persistentAuth); err == nil {
		if info.Mode()&os.ModeSymlink == 0 {
			return errCodexAuthUnavailable
		}
		if err := os.Remove(m.paths.persistentAuth); err != nil {
			return errCodexAuthUnavailable
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errCodexAuthUnavailable
	}
	if err := secureRemove(m.paths.runtimeAuth); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errCodexAuthUnavailable
	}
	return nil
}

// status authenticates every credential representation that exists. A
// missing credential is a valid disconnected state; malformed, unreadable, or
// keyless state is unavailable rather than being mislabeled as disconnected.
func (m *codexAuthManager) status() (string, error) {
	lock, err := acquireCodexAuthLock(m.paths.lock)
	if err != nil {
		return "", errCodexAuthUnavailable
	}
	defer lock.Close()

	leases, err := m.activeLeases()
	if err != nil {
		return "", errCodexAuthUnavailable
	}
	connected := false
	if runtimeAuth, readErr := readPrivateFile(m.paths.runtimeAuth, maxCodexAuthBytes); readErr == nil {
		validationErr := validateCodexAuth(runtimeAuth)
		wipeBytes(runtimeAuth)
		if validationErr != nil {
			return "", errCodexAuthUnavailable
		}
		connected = true
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return "", errCodexAuthUnavailable
	}
	if encrypted, readErr := readPrivateFile(m.paths.encryptedAuth, 4*maxCodexAuthBytes); readErr == nil {
		key, keyErr := m.loadKey()
		if keyErr != nil {
			wipeBytes(encrypted)
			return "", errCodexAuthUnavailable
		}
		plaintext, openErr := openCodexAuth(key, encrypted)
		wipeBytes(key)
		wipeBytes(encrypted)
		if openErr != nil {
			return "", errCodexAuthUnavailable
		}
		validationErr := validateCodexAuth(plaintext)
		wipeBytes(plaintext)
		if validationErr != nil {
			return "", errCodexAuthUnavailable
		}
		connected = true
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return "", errCodexAuthUnavailable
	}
	if connected {
		return "connected", nil
	}
	if leases != 0 {
		return "authenticating", nil
	}
	return "disconnected", nil
}

func (m *codexAuthManager) revoke() error {
	lock, err := acquireCodexAuthLock(m.paths.lock)
	if err != nil {
		return errCodexAuthUnavailable
	}
	defer lock.Close()
	leases, err := m.activeLeases()
	if err != nil {
		return errCodexAuthUnavailable
	}
	if leases != 0 {
		return errCodexAuthInUse
	}
	if err := m.purgeMaterialized(); err != nil {
		return errCodexAuthUnavailable
	}
	for _, path := range []string{m.paths.encryptedAuth, m.paths.key} {
		if err := secureRemove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errCodexAuthUnavailable
		}
	}
	return nil
}

func (h *Helper) codexAuthStatus(request *Request) Response {
	if !codexAuthRequestOnly(request, false) {
		return failure("invalid", "The Codex connection status request was invalid.")
	}
	manager, err := newCodexAuthManager(h.root, h.temporaryRoot, nil)
	if err != nil {
		return failure("precondition", "Codex authentication state could not be inspected.")
	}
	state, err := manager.status()
	if err != nil {
		return failure("precondition", "Codex authentication state could not be inspected.")
	}
	return Response{Version: Version, OK: true, CodexAuthState: state}
}

func (h *Helper) codexAuthRevoke(ctx context.Context, request *Request) Response {
	if !codexAuthRequestOnly(request, true) || h.killCodexTmux == nil {
		return failure("invalid", "The Codex disconnect request was invalid.")
	}
	seen := make(map[string]struct{}, len(request.CodexTerminalTabIDs))
	tabIDs := make([]string, 0, len(request.CodexTerminalTabIDs))
	for _, tabID := range request.CodexTerminalTabIDs {
		parsed, err := terminal.ParseTabID(tabID)
		if err != nil {
			return failure("invalid", "The Codex disconnect request was invalid.")
		}
		canonical := strings.ToLower(parsed.String())
		if _, duplicate := seen[canonical]; duplicate {
			return failure("invalid", "The Codex disconnect request was invalid.")
		}
		seen[canonical] = struct{}{}
		tabIDs = append(tabIDs, canonical)
	}
	for _, tabID := range tabIDs {
		if err := h.killCodexTmux(ctx, tabID); err != nil {
			return failure("precondition", "An app-owned Codex terminal could not be stopped.")
		}
	}
	manager, err := newCodexAuthManager(h.root, h.temporaryRoot, nil)
	if err != nil {
		return failure("precondition", "Codex authentication state could not be revoked.")
	}
	for attempt := 0; ; attempt++ {
		err = manager.revoke()
		if !errors.Is(err, errCodexAuthInUse) {
			break
		}
		if attempt >= 39 {
			return failure("conflict", "A Codex process is still using the authentication state.")
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return failure("conflict", "A Codex process is still using the authentication state.")
		case <-timer.C:
		}
	}
	if err != nil {
		return failure("precondition", "Codex authentication state could not be revoked.")
	}
	return Response{Version: Version, OK: true, CodexAuthState: "disconnected"}
}

func codexAuthRequestOnly(request *Request, revoke bool) bool {
	if request == nil || request.Path != "" || request.Content != "" || request.ExpectedETag != "" || request.Query != "" ||
		request.Staged || request.CommitMessage != "" || request.AuthorName != "" || request.AuthorEmail != "" ||
		request.GitHubToken != "" || request.Repository != "" || request.BaseBranch != "" || request.Branch != "" ||
		len(request.Environment) != 0 || len(request.GrantedSecrets) != 0 || request.SafetyMode != "" || request.Network ||
		request.EventMode != "" || len(request.CodexAuthKey) != 0 || request.CheckpointContentSHA256 != "" ||
		request.CheckpointMode != 0 || request.CheckpointWorkspaceID != "" || request.CheckpointArchiveSHA256 != "" ||
		request.CheckpointID != "" || request.CheckpointForce || request.CheckpointSeal || len(request.Paths) != 0 ||
		request.TerminalTabID != "" || len(request.Attachments) != 0 {
		return false
	}
	if revoke {
		return request.Confirmed && len(request.CodexTerminalTabIDs) <= 64
	}
	return !request.Confirmed && len(request.CodexTerminalTabIDs) == 0
}

func killCodexTmuxSession(ctx context.Context, temporaryRoot, tabID string) error {
	if _, err := terminal.ParseTabID(tabID); err != nil || !filepath.IsAbs(temporaryRoot) {
		return errors.New("invalid Codex tmux session")
	}
	temporaryRoot = filepath.Clean(temporaryRoot)
	session := "cm-" + strings.ToLower(tabID)
	hasSession, cancel, err := newTmuxCommand(ctx, temporaryRoot, "has-session", "-t", session)
	if err != nil {
		return err
	}
	err = hasSession.Run()
	cancel()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 1 {
			return nil
		}
		return err
	}
	kill, cancel, err := newTmuxCommand(ctx, temporaryRoot, "kill-session", "-t", session)
	if err != nil {
		return err
	}
	defer cancel()
	return kill.Run()
}

func boundedTmuxCommandContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, tmuxCommandTimeout)
}

func newTmuxCommand(parent context.Context, temporaryRoot string, args ...string) (*exec.Cmd, context.CancelFunc, error) {
	if parent == nil || !filepath.IsAbs(temporaryRoot) {
		return nil, nil, errors.New("invalid tmux subprocess boundary")
	}
	temporaryRoot = filepath.Clean(temporaryRoot)
	commandContext, cancel := boundedTmuxCommandContext(parent)
	command := exec.CommandContext(commandContext, "/usr/bin/tmux", args...)
	command.Dir = temporaryRoot
	command.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "LANG=C", "TMPDIR=" + temporaryRoot}
	command.Stdin = strings.NewReader("")
	command.Stdout, command.Stderr = io.Discard, io.Discard
	command.WaitDelay = tmuxCommandWaitDelay
	return command, cancel, nil
}

func sealCodexAuth(key, plaintext []byte, randomSource io.Reader) ([]byte, error) {
	if len(key) != CodexAuthKeyBytes || len(plaintext) == 0 || len(plaintext) > maxCodexAuthBytes || randomSource == nil {
		return nil, errCodexAuthUnavailable
	}
	aead, err := codexAuthAEAD(key)
	if err != nil {
		return nil, errCodexAuthUnavailable
	}
	nonce := make([]byte, aead.NonceSize())
	defer wipeBytes(nonce)
	if _, err := io.ReadFull(randomSource, nonce); err != nil {
		return nil, errCodexAuthUnavailable
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, authAAD)
	envelope := codexAuthEnvelope{
		Version: authEnvelopeVersion, Nonce: base64.RawURLEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawURLEncoding.EncodeToString(ciphertext),
	}
	defer wipeBytes(ciphertext)
	return json.Marshal(envelope)
}

func openCodexAuth(key, encoded []byte) ([]byte, error) {
	if len(key) != CodexAuthKeyBytes || len(encoded) == 0 || len(encoded) > 4*maxCodexAuthBytes {
		return nil, errCodexAuthUnavailable
	}
	var envelope codexAuthEnvelope
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil || envelope.Version != authEnvelopeVersion {
		return nil, errCodexAuthUnavailable
	}
	if err := ensureEOF(decoder); err != nil {
		return nil, errCodexAuthUnavailable
	}
	nonce, err := base64.RawURLEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		return nil, errCodexAuthUnavailable
	}
	defer wipeBytes(nonce)
	ciphertext, err := base64.RawURLEncoding.DecodeString(envelope.Ciphertext)
	if err != nil || len(ciphertext) > maxCodexAuthBytes+64 {
		wipeBytes(ciphertext)
		return nil, errCodexAuthUnavailable
	}
	defer wipeBytes(ciphertext)
	aead, err := codexAuthAEAD(key)
	if err != nil || len(nonce) != aead.NonceSize() {
		return nil, errCodexAuthUnavailable
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, authAAD)
	if err != nil || len(plaintext) == 0 || len(plaintext) > maxCodexAuthBytes {
		wipeBytes(plaintext)
		return nil, errCodexAuthUnavailable
	}
	return plaintext, nil
}

func codexAuthAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func validateCodexAuth(content []byte) error {
	if len(content) == 0 || len(content) > maxCodexAuthBytes || !json.Valid(content) {
		return errCodexAuthUnavailable
	}
	var document map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(content))
	if err := decoder.Decode(&document); err != nil || len(document) == 0 {
		return errCodexAuthUnavailable
	}
	defer func() {
		for name, value := range document {
			wipeBytes(value)
			delete(document, name)
		}
	}()
	if err := ensureEOF(decoder); err != nil {
		return errCodexAuthUnavailable
	}
	if mode, ok := document["auth_mode"]; ok && !bytes.Equal(bytes.TrimSpace(mode), []byte("null")) {
		var value string
		if json.Unmarshal(mode, &value) != nil || value != "chatgpt" {
			return errCodexAuthUnavailable
		}
	}
	for _, name := range []string{"OPENAI_API_KEY", "personal_access_token", "bedrock_api_key", "agent_identity"} {
		value, ok := document[name]
		trimmed := bytes.TrimSpace(value)
		if !ok || bytes.Equal(trimmed, []byte("null")) || bytes.Equal(trimmed, []byte(`""`)) {
			continue
		}
		return errCodexAuthUnavailable
	}
	return nil
}

func ensurePrivateDirectory(path string) error {
	return ensurePrivateDirectoryPlatform(path)
}

func readPrivateFile(path string, maximum int64) ([]byte, error) {
	return readPrivateFilePlatform(path, maximum)
}

func secureRemove(path string) error {
	return removePrivateFilePlatform(path)
}

func wipeBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func codexArgumentsAllowed(args []string) bool {
	for _, arg := range args {
		lower := strings.ToLower(arg)
		if strings.ContainsRune(arg, '\x00') || lower == "--with-api-key" || strings.HasPrefix(lower, "--with-api-key=") ||
			lower == "-c" || lower == "--config" || strings.HasPrefix(lower, "-c=") || strings.HasPrefix(lower, "--config=") {
			return false
		}
	}
	return true
}

func sanitizedCodexEnvironment(source []string, codexHome string) []string {
	result := make([]string, 0, len(source)+2)
	havePath := false
	for _, entry := range source {
		name, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		switch strings.ToUpper(name) {
		case "OPENAI_API_KEY", "CODEX_API_KEY", "CODEX_MOBILE_GIT_TOKEN_FILE":
			continue
		case "CODEX_HOME":
			continue
		case "PATH":
			havePath = true
			result = append(result, name+"="+trustedCodexDirectory+string(os.PathListSeparator)+value)
		default:
			result = append(result, entry)
		}
	}
	result = append(result, "CODEX_HOME="+codexHome)
	if !havePath {
		result = append(result, "PATH="+trustedCodexDirectory)
	}
	return result
}

func runCodex(args []string, root, temporaryRoot, executable string, environment []string, terminalTabID string) error {
	if !codexArgumentsAllowed(args) || executable == "" || !filepath.IsAbs(executable) || filepath.Clean(executable) != executable {
		return errors.New("invalid Codex launcher request")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return errors.New("invalid Codex launcher request")
	}
	manager, err := newCodexAuthManager(root, temporaryRoot, nil)
	if err != nil {
		return errCodexAuthUnavailable
	}
	var session *codexAuthSession
	if isDeviceAuthLogin(args) {
		session, err = manager.beginDeviceLogin()
	} else {
		session, err = manager.begin()
	}
	if err != nil {
		return errCodexAuthUnavailable
	}
	codexHome := manager.paths.persistentHome
	if terminalTabID != "" {
		codexHome, err = prepareTerminalCodexHome(root, terminalTabID)
		if err != nil {
			_ = session.close()
			return errCodexAuthUnavailable
		}
	}
	command := newInteractiveCodexCommand(executable, args, root, sanitizedCodexEnvironment(environment, codexHome))
	runErr := runCodexCommand(command)
	sealErr := session.close()
	if sealErr != nil {
		return errCodexAuthUnavailable
	}
	return runErr
}

// newInteractiveCodexCommand is the sole deliberately long-lived subprocess
// boundary in the helper. The real Codex TUI owns the terminal streams and may
// run for the lifetime of its tmux tab, so imposing a helper timeout or output
// buffer would corrupt the authoritative CLI experience. The terminal manager
// bounds its lifecycle by owning and revoking the tab/session instead.
func newInteractiveCodexCommand(executable string, args []string, root string, environment []string) *exec.Cmd {
	command := exec.Command(executable, args...)
	command.Dir = root
	command.Env = append([]string(nil), environment...)
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	return command
}

func isDeviceAuthLogin(args []string) bool {
	return len(args) == 2 && args[0] == "login" && args[1] == "--device-auth"
}

func runCodexCommand(command *exec.Cmd) error {
	if err := command.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	for {
		select {
		case err := <-done:
			return err
		case received := <-signals:
			// The child normally shares the terminal's foreground process group
			// and receives the signal directly. Forwarding is idempotent and also
			// covers non-interactive launches where only the wrapper was targeted.
			_ = command.Process.Signal(received)
		}
	}
}

// RunCodex invokes only the immutable, pinned binary in the helper volume.
// It deliberately does not resolve PATH, which may be repository controlled.
func RunCodex(args []string, root string, environment []string) error {
	return runCodex(args, root, os.TempDir(), TrustedCodexPath, inheritedTerminalEnvironment(environment), "")
}

func (h *Helper) configureCodexAuth(key []byte) error {
	manager, err := newCodexAuthManager(h.root, h.temporaryRoot, nil)
	if err != nil {
		return err
	}
	return manager.configure(key)
}

func (h *Helper) sealCodexAuth() error {
	manager, err := newCodexAuthManager(h.root, h.temporaryRoot, nil)
	if err != nil {
		return err
	}
	return manager.sealBoundary()
}

func scrubSensitiveRequest(request *Request) {
	if request == nil {
		return
	}
	request.GitHubToken = ""
	request.OperationDeadlineUnixMilli = 0
	wipeBytes(request.CodexAuthKey)
	request.CodexAuthKey = nil
	for name := range request.Environment {
		request.Environment[name] = ""
		delete(request.Environment, name)
	}
	wipeRuntimeSecrets(request.GrantedSecrets)
	request.GrantedSecrets = nil
	for index := range request.Attachments {
		wipeBytes(request.Attachments[index].Content)
		request.Attachments[index].Content = nil
	}
	request.Attachments = nil
}
