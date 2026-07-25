package terminal

import (
	"errors"
	"fmt"
	"testing"
)

func TestRegisteredTabCapacityEveryScopeAndUnregisterRecovery(t *testing.T) {
	t.Run("workspace", func(t *testing.T) {
		manager := newTabCapacityManager(t)
		ids := registerCapacityTabs(t, manager, "owner", "workspace", maxRegisteredTabsPerWorkspace)
		if err := registerCapacityTab(t, manager, "owner", "workspace", "workspace-overflow"); !errors.Is(err, ErrTerminalCapacity) {
			t.Fatalf("workspace registered-tab cap error = %v", err)
		}
		if err := manager.Unregister(ids[0], "capacity_recovery"); err != nil {
			t.Fatal(err)
		}
		if err := registerCapacityTab(t, manager, "owner", "workspace", "workspace-recovered"); err != nil {
			t.Fatalf("workspace cap did not recover after unregister: %v", err)
		}
	})

	t.Run("owner", func(t *testing.T) {
		manager := newTabCapacityManager(t)
		for index := 0; index < maxRegisteredTabsPerOwner; index++ {
			workspaceID := fmt.Sprintf("workspace-%d", index/maxRegisteredTabsPerWorkspace)
			if err := registerCapacityTab(t, manager, "owner", workspaceID, fmt.Sprintf("owner-%d", index)); err != nil {
				t.Fatal(err)
			}
		}
		if err := registerCapacityTab(t, manager, "owner", "owner-overflow-workspace", "owner-overflow"); !errors.Is(err, ErrTerminalCapacity) {
			t.Fatalf("owner registered-tab cap error = %v", err)
		}
	})

	t.Run("global", func(t *testing.T) {
		manager := newTabCapacityManager(t)
		for index := 0; index < maxRegisteredTabsGlobal; index++ {
			ownerID := fmt.Sprintf("owner-%d", index/maxRegisteredTabsPerOwner)
			workspaceID := fmt.Sprintf("workspace-%d-%d", index/maxRegisteredTabsPerOwner, index/maxRegisteredTabsPerWorkspace)
			if err := registerCapacityTab(t, manager, ownerID, workspaceID, fmt.Sprintf("global-%d", index)); err != nil {
				t.Fatal(err)
			}
		}
		if err := registerCapacityTab(t, manager, "new-owner", "new-workspace", "global-overflow"); !errors.Is(err, ErrTerminalCapacity) {
			t.Fatalf("global registered-tab cap error = %v", err)
		}
	})
}

func TestTerminalHeapPoolsStayWithinDocumentedBudget(t *testing.T) {
	// Worst-case retained payload bytes across the four dominant pools:
	// registered replay rings, one upstream read plus queue/pending chunk per
	// registered PTY, per-subscriber replay snapshots, and outbound queues.
	rings := int64(maxRegisteredTabsGlobal * terminalReplayMaxBytes)
	ptyQueues := int64(maxRegisteredTabsGlobal * (MaxPayload + (RuntimeOutputQueueChunks+1)*RuntimeOutputChunkBytes))
	replaySnapshots := int64(maxSubscribersGlobal * terminalReplayMaxBytes)
	outboundQueues := int64(maxSubscribersGlobal * terminalSubscriberQueueFrames * RuntimeOutputChunkBytes)
	total := rings + ptyQueues + replaySnapshots + outboundQueues
	const documentedMaximum = int64(1100 << 20)
	if total > documentedMaximum {
		t.Fatalf("terminal heap payload budget grew to %d bytes (limit %d)", total, documentedMaximum)
	}
	t.Logf("terminal retained-payload ceiling: rings=%d PTY=%d replay-copies=%d outbound=%d total=%d", rings, ptyQueues, replaySnapshots, outboundQueues, total)
}

func newTabCapacityManager(t *testing.T) *Manager {
	t.Helper()
	manager, err := NewManager([]byte("0123456789abcdef0123456789abcdef"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	return manager
}

func registerCapacityTabs(t *testing.T, manager *Manager, ownerID, workspaceID string, count int) []TabID {
	t.Helper()
	ids := make([]TabID, 0, count)
	for index := 0; index < count; index++ {
		seed := fmt.Sprintf("%s-%s-%d", ownerID, workspaceID, index)
		id := seededTabID(seed)
		if err := registerCapacityTabID(t, manager, ownerID, workspaceID, id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	return ids
}

func registerCapacityTab(t *testing.T, manager *Manager, ownerID, workspaceID, seed string) error {
	t.Helper()
	return registerCapacityTabID(t, manager, ownerID, workspaceID, seededTabID(seed))
}

func registerCapacityTabID(t *testing.T, manager *Manager, ownerID, workspaceID string, id TabID) error {
	t.Helper()
	redactor := testOutputRedactor(t)
	err := manager.Register(ownerID, workspaceID, id, newFakeRuntime(), redactor, false)
	if err != nil {
		redactor.Close()
	}
	return err
}
