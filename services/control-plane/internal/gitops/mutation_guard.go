package gitops

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	workspacefiles "github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/files"
)

const maximumRemoteRefs = 10000

var githubRepositoryPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$`)

func validGitHubRepository(value string) bool { return githubRepositoryPattern.MatchString(value) }

func (s *Service) validateStagedPaths(ctx context.Context, environment []string) error {
	listing, err := s.run(ctx, nil, environment, "diff", "--cached", "--name-only", "--no-renames", "-z", "--")
	if err != nil {
		return err
	}
	defer clear(listing)
	count := 0
	for _, path := range bytes.Split(listing, []byte{0}) {
		if len(path) == 0 {
			continue
		}
		count++
		if count > maximumScannerFiles || workspacefiles.Sensitive(string(path)) {
			return fmt.Errorf("%w: sensitive or oversized tree cannot be changed through native Git", core.ErrForbidden)
		}
	}
	return nil
}

func (s *Service) resolvePushHead(ctx context.Context) (string, string, error) {
	refBytes, err := s.run(ctx, nil, nil, "symbolic-ref", "-q", "HEAD")
	if err != nil {
		return "", "", fmt.Errorf("%w: detached HEAD requires the terminal", core.ErrPrecondition)
	}
	ref := strings.TrimSpace(string(refBytes))
	clear(refBytes)
	if !validLocalBranchRef(ref) {
		return "", "", errors.New("Git branch ref is invalid")
	}
	tipBytes, err := s.run(ctx, nil, nil, "rev-parse", "--verify", ref)
	if err != nil {
		return "", "", err
	}
	tip := strings.TrimSpace(string(tipBytes))
	clear(tipBytes)
	if !validGitObjectID([]byte(tip)) {
		return "", "", errors.New("Git branch tip is invalid")
	}
	return ref, tip, nil
}

func validLocalBranchRef(ref string) bool {
	return strings.HasPrefix(ref, "refs/heads/") && len(ref) > len("refs/heads/") && len(ref) <= 1024 &&
		!strings.ContainsAny(ref, "\x00\r\n") && !strings.Contains(ref, "..") && !strings.HasSuffix(ref, "/")
}

func (s *Service) remoteObjectIDs(ctx context.Context, environment []string, remote string) ([]string, error) {
	if remote == "" || strings.ContainsAny(remote, "\x00\r\n") {
		return nil, ErrSecretScan
	}
	listing, err := s.run(ctx, nil, environment, "ls-remote", "--heads", "--quiet", remote)
	if err != nil {
		return nil, err
	}
	defer clear(listing)
	result := make([]string, 0)
	seen := make(map[string]struct{})
	for _, line := range bytes.Split(listing, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		fields := bytes.Fields(line)
		if len(fields) != 2 || !validGitObjectID(fields[0]) || !bytes.HasPrefix(fields[1], []byte("refs/heads/")) || bytes.IndexByte(fields[1], 0) >= 0 {
			return nil, ErrSecretScan
		}
		objectID := string(fields[0])
		if _, duplicate := seen[objectID]; duplicate {
			continue
		}
		seen[objectID] = struct{}{}
		result = append(result, objectID)
		if len(result) > maximumRemoteRefs {
			return nil, ErrSecretScan
		}
	}
	return result, nil
}
