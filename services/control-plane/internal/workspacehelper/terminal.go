package workspacehelper

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/codex"
)

// RunTerminalIfRequested turns the root-owned helper into a small fixed
// terminal launcher. Environment values are loaded from the private workspace
// state directory and never interpolated into a shell command.
func RunTerminalIfRequested(args []string, root string) (bool, error) {
	if len(args) == 0 || args[0] != "terminal" {
		return false, nil
	}
	if len(args) < 2 || len(args) > 4 {
		return true, errors.New("invalid terminal launcher arguments")
	}
	kind := args[1]
	if kind != "codex" && kind != "shell" && kind != "server" && kind != "test" && kind != "log" {
		return true, errors.New("invalid terminal kind")
	}
	if root == "" {
		root = DefaultRoot
	}
	environment, err := loadTerminalEnvironment(root, os.TempDir())
	if err != nil {
		return true, err
	}
	defer clearEnvironmentEntries(environment)
	var executable string
	var commandArgs []string
	if kind == "codex" {
		if len(args) < 3 || len(args) > 4 || !validCodexTabID(args[2]) {
			return true, errors.New("invalid Codex terminal mapping")
		}
		tabID := args[2]
		threadID := ""
		if len(args) == 4 {
			threadID = args[3]
		} else {
			home, homeErr := terminalCodexHome(root, tabID)
			if homeErr != nil {
				return true, homeErr
			}
			threadID, err = latestCodexThreadID(home)
			if err != nil {
				return true, errors.New("Codex terminal session index is unavailable")
			}
		}
		commandArgs, err = codex.LaunchArgs(threadID)
		if err != nil {
			return true, err
		}
		// loadTerminalEnvironment already combines only an inherited allowlist
		// with the owner's explicitly configured values and active grants. Do
		// not pass it through the raw-wrapper allowlist a second time.
		return true, runCodex(commandArgs, root, os.TempDir(), TrustedCodexPath, environment, tabID)
	} else {
		if len(args) != 2 {
			return true, errors.New("thread ID is only valid for Codex terminals")
		}
		// The workspace image owns this fixed executable. Never resolve a shell
		// through repository-influenced PATH state.
		executable = "/bin/bash"
		commandArgs = []string{"-l"}
	}
	return true, execTerminal(executable, commandArgs, environment)
}

var inheritedTerminalEnvironmentNames = map[string]struct{}{
	"COLORTERM": {}, "HOME": {}, "LANG": {}, "LC_ALL": {}, "LC_CTYPE": {},
	"LOGNAME": {}, "PATH": {}, "SHELL": {}, "SSL_CERT_DIR": {}, "SSL_CERT_FILE": {},
	"TEMP": {}, "TERM": {}, "TMP": {}, "TMPDIR": {}, "TZ": {}, "USER": {},
	// Windows development and test hosts need these to execute system tools.
	"SYSTEMROOT": {}, "USERPROFILE": {}, "WINDIR": {},
}

// inheritedTerminalEnvironment is the only process-environment inheritance
// boundary for a workspace shell or direct Codex wrapper. Coder agent tokens,
// control-plane/database credentials, GitHub/APNs material, BASH_ENV/ENV, and
// every unrecognized variable are excluded even if the helper itself received
// them from Coder or a caller-controlled parent process.
func inheritedTerminalEnvironment(source []string) []string {
	values := inheritedTerminalEnvironmentMap(source)
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]string, 0, len(names))
	for _, name := range names {
		result = append(result, name+"="+values[name])
	}
	return result
}

func inheritedTerminalEnvironmentMap(source []string) map[string]string {
	result := make(map[string]string)
	for _, entry := range source {
		name, value, ok := strings.Cut(entry, "=")
		canonical := strings.ToUpper(name)
		if !ok || name == "" || len(value) > 8192 || strings.ContainsRune(value, '\x00') {
			continue
		}
		if _, allowed := inheritedTerminalEnvironmentNames[canonical]; !allowed {
			continue
		}
		// Canonical names prevent case-variant duplicates from producing
		// platform-dependent subprocess behavior.
		result[canonical] = value
	}
	return result
}

func loadTerminalEnvironment(root, temporaryRoot string) ([]string, error) {
	if root == "" {
		root = DefaultRoot
	}
	if temporaryRoot == "" {
		return nil, errors.New("workspace runtime environment is unavailable")
	}
	path := filepath.Join(temporaryRoot, "codex-mobile-runtime", "environment.json")
	content, err := readPrivateFile(path, 300*1024)
	if err != nil {
		return nil, errors.New("workspace runtime environment is unavailable")
	}
	defer wipeBytes(content)
	decoder := json.NewDecoder(bytes.NewReader(content))
	var custom map[string]string
	if err := decoder.Decode(&custom); err != nil {
		return nil, errors.New("workspace environment is invalid")
	}
	defer func() {
		for name := range custom {
			custom[name] = ""
			delete(custom, name)
		}
	}()
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("workspace environment is invalid")
	}
	merged := inheritedTerminalEnvironmentMap(os.Environ())
	for name, value := range custom {
		if !validEnvironmentName(name) || reservedEnvironmentName(name) || len(value) > 8192 || strings.ContainsRune(value, '\x00') {
			return nil, errors.New("workspace environment is invalid")
		}
		merged[name] = value
	}
	granted, err := loadRuntimeSecrets(temporaryRoot)
	if err != nil {
		return nil, errors.New("workspace runtime environment is unavailable")
	}
	defer wipeRuntimeSecrets(granted)
	for name, value := range granted {
		merged[name] = string(value)
	}
	names := make([]string, 0, len(merged))
	for name := range merged {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]string, 0, len(names))
	for _, name := range names {
		result = append(result, name+"="+merged[name])
	}
	return result, nil
}

func clearEnvironmentEntries(values []string) {
	for index := range values {
		values[index] = ""
	}
}
