package workspacehelper

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	maximumCodexSessionEntries = 4096
	maximumCodexSessionBytes   = 1 << 30
)

var (
	codexTabIDPattern  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	rolloutNamePattern = regexp.MustCompile(`^rollout-[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}-[0-9]{2}-[0-9]{2}-([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\.jsonl$`)
)

func validCodexTabID(value string) bool {
	return codexTabIDPattern.MatchString(value) && strings.Trim(value, "0-") != ""
}

func terminalCodexHome(root, tabID string) (string, error) {
	if !validCodexTabID(tabID) {
		return "", errors.New("invalid Codex terminal tab ID")
	}
	root, err := filepath.Abs(root)
	if err != nil || !filepath.IsAbs(root) {
		return "", errors.New("invalid Codex workspace root")
	}
	return filepath.Join(filepath.Dir(root), ".codex-home", "terminal-tabs", strings.ToLower(tabID)), nil
}

// prepareTerminalCodexHome gives every persistent terminal tab its own Codex
// session index while sharing only the managed config and materialized ChatGPT
// credential. This makes an exact tab-to-thread mapping possible even when a
// workspace has several concurrent Codex TUIs.
func prepareTerminalCodexHome(root, tabID string) (string, error) {
	home, err := terminalCodexHome(root, tabID)
	if err != nil {
		return "", err
	}
	if err := ensurePrivateDirectory(home); err != nil {
		return "", errCodexAuthUnavailable
	}
	for name, target := range map[string]string{
		"config.toml": filepath.Join("..", "..", "config.toml"),
		"auth.json":   filepath.Join("..", "..", "auth.json"),
	} {
		if err := ensureManagedCodexLink(filepath.Join(home, name), target); err != nil {
			return "", errCodexAuthUnavailable
		}
	}
	return home, nil
}

func ensureManagedCodexLink(path, target string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Symlink(target, path); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return errCodexAuthUnavailable
	}
	actual, err := os.Readlink(path)
	if err != nil || filepath.Clean(actual) != filepath.Clean(target) {
		return errCodexAuthUnavailable
	}
	return nil
}

func (h *Helper) codexThreadLookup(request *Request) Response {
	if !codexThreadLookupRequestOnly(request) || !validCodexTabID(request.TerminalTabID) {
		return failure("invalid", "The Codex terminal mapping request was invalid.")
	}
	home, err := terminalCodexHome(h.root, request.TerminalTabID)
	if err != nil {
		return failure("invalid", "The Codex terminal mapping request was invalid.")
	}
	threadID, err := latestCodexThreadID(home)
	if err != nil {
		return failure("precondition", "The Codex terminal session index was unsafe or unavailable.")
	}
	return Response{Version: Version, OK: true, CodexThreadID: threadID}
}

func codexThreadLookupRequestOnly(request *Request) bool {
	return request.Path == "" && request.Content == "" && request.ExpectedETag == "" && request.Query == "" &&
		!request.Staged && request.CommitMessage == "" && request.AuthorName == "" && request.AuthorEmail == "" &&
		request.GitHubToken == "" && request.Repository == "" && request.BaseBranch == "" && request.Branch == "" &&
		len(request.Environment) == 0 && len(request.GrantedSecrets) == 0 && request.SafetyMode == "" && !request.Network &&
		request.EventMode == "" && len(request.CodexAuthKey) == 0 && request.CheckpointContentSHA256 == "" &&
		request.CheckpointMode == 0 && request.CheckpointWorkspaceID == "" && request.CheckpointArchiveSHA256 == "" &&
		request.CheckpointID == "" && !request.CheckpointForce && !request.CheckpointSeal && len(request.Paths) == 0 &&
		!request.Confirmed && len(request.CodexTerminalTabIDs) == 0 && len(request.Attachments) == 0
}

// latestCodexThreadID treats the session tree as hostile metadata. It follows
// no symlinks, reads no conversation content, bounds traversal, and derives the
// UUID only from the pinned Codex rollout filename contract.
func latestCodexThreadID(home string) (string, error) {
	info, err := os.Lstat(home)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errCodexAuthUnavailable
	}
	sessions := filepath.Join(home, "sessions")
	info, err = os.Lstat(sessions)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errCodexAuthUnavailable
	}
	entries := 0
	latestID := ""
	latestTime := time.Time{}
	err = filepath.WalkDir(sessions, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		entries++
		if entries > maximumCodexSessionEntries {
			return errCodexAuthUnavailable
		}
		relative, err := filepath.Rel(sessions, path)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return errCodexAuthUnavailable
		}
		if relative != "." && strings.Count(filepath.ToSlash(relative), "/") > 3 {
			return errCodexAuthUnavailable
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errCodexAuthUnavailable
		}
		if entry.IsDir() {
			return nil
		}
		match := rolloutNamePattern.FindStringSubmatch(entry.Name())
		if len(match) != 2 {
			return nil
		}
		fileInfo, err := entry.Info()
		if err != nil || !fileInfo.Mode().IsRegular() || fileInfo.Size() <= 0 || fileInfo.Size() > maximumCodexSessionBytes {
			return errCodexAuthUnavailable
		}
		candidate := strings.ToLower(match[1])
		if fileInfo.ModTime().After(latestTime) || (fileInfo.ModTime().Equal(latestTime) && candidate > latestID) {
			latestID, latestTime = candidate, fileInfo.ModTime()
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return latestID, nil
}
