package workspace

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/admission"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
)

type MemoryStore struct {
	mu          sync.Mutex
	workspaces  map[string]core.Workspace
	diskFreeGiB int64
}

func NewMemoryStore(diskFreeGiB int64) *MemoryStore {
	return &MemoryStore{workspaces: make(map[string]core.Workspace), diskFreeGiB: diskFreeGiB}
}

func (s *MemoryStore) Create(_ context.Context, ws core.Workspace) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.workspaces[ws.ID]; exists {
		return errors.New("workspace already exists")
	}
	s.workspaces[ws.ID] = workspaceWithoutPrivateInputs(ws)
	return nil
}

func (s *MemoryStore) Get(_ context.Context, ownerID, id string) (core.Workspace, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ws, ok := s.workspaces[id]
	if !ok || ws.OwnerID != ownerID {
		return core.Workspace{}, core.ErrNotFound
	}
	return ws, nil
}

func (s *MemoryStore) Save(_ context.Context, ws core.Workspace) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prior, ok := s.workspaces[ws.ID]
	if !ok || prior.OwnerID != ws.OwnerID {
		return core.ErrNotFound
	}
	s.workspaces[ws.ID] = workspaceWithoutPrivateInputs(ws)
	return nil
}

func workspaceWithoutPrivateInputs(value core.Workspace) core.Workspace {
	value.EnvironmentVariables = nil
	value.InitialPrompt = ""
	return value
}

func (s *MemoryStore) FinalizeDelete(_ context.Context, ownerID, workspaceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ws, ok := s.workspaces[workspaceID]
	if !ok || ws.OwnerID != ownerID {
		return core.ErrNotFound
	}
	if ws.State != core.WorkspaceDeleting {
		return core.ErrConflict
	}
	delete(s.workspaces, workspaceID)
	return nil
}

func (s *MemoryStore) List(_ context.Context, ownerID string) ([]core.Workspace, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]core.Workspace, 0)
	for _, ws := range s.workspaces {
		if ws.OwnerID == ownerID {
			out = append(out, ws)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

func (s *MemoryStore) ListAll(_ context.Context) ([]core.Workspace, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]core.Workspace, 0, len(s.workspaces))
	for _, ws := range s.workspaces {
		out = append(out, ws)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].OwnerID != out[j].OwnerID {
			return out[i].OwnerID < out[j].OwnerID
		}
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

func (s *MemoryStore) TouchActivity(_ context.Context, ownerID, workspaceID string, observedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ws, ok := s.workspaces[workspaceID]
	if !ok || ws.OwnerID != ownerID {
		return core.ErrNotFound
	}
	switch ws.State {
	case core.WorkspaceReady, core.WorkspaceRunning, core.WorkspaceNeedsAttention, core.WorkspaceIdle:
	default:
		return core.ErrConflict
	}
	if observedAt.After(ws.LastActivityAt) {
		ws.LastActivityAt = observedAt.UTC()
	}
	if observedAt.After(ws.UpdatedAt) {
		ws.UpdatedAt = observedAt.UTC()
	}
	if ws.State == core.WorkspaceIdle {
		ws.State = core.WorkspaceRunning
	}
	s.workspaces[workspaceID] = ws
	return nil
}

func (s *MemoryStore) TransitionIfInactive(_ context.Context, ownerID, workspaceID string, from, to core.WorkspaceState, expectedLastActivity, at time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ws, ok := s.workspaces[workspaceID]
	if !ok || ws.OwnerID != ownerID {
		return false, core.ErrNotFound
	}
	if ws.State != from || !ws.LastActivityAt.Equal(expectedLastActivity) {
		return false, nil
	}
	if !from.CanTransition(to) {
		return false, core.ErrInvalid
	}
	ws.State = to
	if at.After(ws.UpdatedAt) {
		ws.UpdatedAt = at.UTC()
	}
	s.workspaces[workspaceID] = ws
	return true, nil
}

func (s *MemoryStore) UpdateQuota(_ context.Context, ownerID, workspaceID string, quota core.Quota, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ws, ok := s.workspaces[workspaceID]
	if !ok || ws.OwnerID != ownerID {
		return core.ErrNotFound
	}
	ws.Quota = quota
	if at.After(ws.UpdatedAt) {
		ws.UpdatedAt = at.UTC()
	}
	s.workspaces[workspaceID] = ws
	return nil
}

func (s *MemoryStore) UpdatePolicy(_ context.Context, ownerID, workspaceID string, retention core.RetentionPolicy, idleTimeoutMinutes int, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ws, ok := s.workspaces[workspaceID]
	if !ok || ws.OwnerID != ownerID {
		return core.ErrNotFound
	}
	ws.Retention, ws.IdleTimeoutMinutes = retention, idleTimeoutMinutes
	if at.After(ws.UpdatedAt) {
		ws.UpdatedAt = at.UTC()
	}
	s.workspaces[workspaceID] = ws
	return nil
}

func (s *MemoryStore) UpdateSafetyMode(_ context.Context, ownerID, workspaceID string, mode core.SafetyMode, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ws, ok := s.workspaces[workspaceID]
	if !ok || ws.OwnerID != ownerID {
		return core.ErrNotFound
	}
	if !mode.Valid() {
		return core.ErrInvalid
	}
	if ws.State != core.WorkspaceSuspended {
		return core.ErrConflict
	}
	ws.SafetyMode = mode
	if at.After(ws.UpdatedAt) {
		ws.UpdatedAt = at.UTC()
	}
	s.workspaces[workspaceID] = ws
	return nil
}

func (s *MemoryStore) Snapshot(_ context.Context, ownerID string) (admission.Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	snapshot := admission.Snapshot{DiskFreeGiB: s.diskFreeGiB}
	for _, ws := range s.workspaces {
		if ws.OwnerID != ownerID {
			continue
		}
		if ws.State.CountsAsRunning() {
			snapshot.Running++
		}
		if ws.State == core.WorkspaceProvisioning && ws.ProviderResourceID == "" {
			snapshot.PendingDiskGiB += ws.Quota.DiskGiB
		}
		if ws.State == core.WorkspaceQueued {
			snapshot.Queued++
		}
	}
	return snapshot, nil
}
