package gitops

import (
	"context"
	"io"
	"strings"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// ScanRepositoryReachable performs the authenticated-push scan without
// executing workspace Git. A devcontainer may replace every executable and
// Git config file, so the process that holds a GitHub token must derive the
// exact object graph through the in-process object store.
func (s *ValueSecretScanner) ScanRepositoryReachable(ctx context.Context, repository *gogit.Repository, tip plumbing.Hash, remoteHashes []plumbing.Hash) error {
	if s == nil || repository == nil || tip.IsZero() || len(remoteHashes) > maximumScannerObjects {
		return ErrSecretScan
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrSecretScan
	}
	remote := make(map[plumbing.Hash]struct{}, len(remoteHashes))
	for _, hash := range remoteHashes {
		if !hash.IsZero() {
			remote[hash] = struct{}{}
		}
	}
	queue := []plumbing.Hash{tip}
	seen := make(map[plumbing.Hash]struct{})
	totalBytes := int64(0)
	for len(queue) != 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		hash := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if _, exists := remote[hash]; exists {
			continue
		}
		if _, exists := seen[hash]; exists {
			continue
		}
		seen[hash] = struct{}{}
		if len(seen) > maximumScannerObjects {
			return ErrSecretScan
		}
		encoded, err := repository.Storer.EncodedObject(plumbing.AnyObject, hash)
		if err != nil || encoded.Size() < 0 || encoded.Size() > maximumScannerFileBytes {
			return ErrSecretScan
		}
		reader, err := encoded.Reader()
		if err != nil {
			return ErrSecretScan
		}
		content, readErr := io.ReadAll(io.LimitReader(reader, maximumScannerFileBytes+1))
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil || len(content) > maximumScannerFileBytes || int64(len(content)) != encoded.Size() {
			clear(content)
			return ErrSecretScan
		}
		totalBytes += int64(len(content))
		if totalBytes > maximumScannerTotalBytes {
			clear(content)
			return ErrSecretScan
		}
		matchErr := s.match(content)
		clear(content)
		if matchErr != nil {
			return matchErr
		}
		switch encoded.Type() {
		case plumbing.CommitObject:
			commit, err := object.GetCommit(repository.Storer, hash)
			if err != nil {
				return ErrSecretScan
			}
			queue = append(queue, commit.TreeHash)
			queue = append(queue, commit.ParentHashes...)
		case plumbing.TreeObject:
			tree, err := object.GetTree(repository.Storer, hash)
			if err != nil {
				return ErrSecretScan
			}
			for _, entry := range tree.Entries {
				if entry.Name == "" || strings.ContainsAny(entry.Name, "/\\\x00") || sensitiveScannerPath(entry.Name) || !safeRepositoryMode(entry.Mode) {
					return ErrSecretScan
				}
				if err := s.match([]byte(entry.Name)); err != nil {
					return err
				}
				queue = append(queue, entry.Hash)
			}
		case plumbing.TagObject:
			tag, err := object.GetTag(repository.Storer, hash)
			if err != nil {
				return ErrSecretScan
			}
			queue = append(queue, tag.Target)
		case plumbing.BlobObject:
		default:
			return ErrSecretScan
		}
	}
	return nil
}

func safeRepositoryMode(mode filemode.FileMode) bool {
	switch mode {
	case filemode.Dir, filemode.Regular, filemode.Executable, filemode.Symlink, filemode.Submodule:
		return true
	default:
		return false
	}
}
