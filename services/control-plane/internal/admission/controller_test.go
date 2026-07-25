package admission

import (
	"testing"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
)

func TestReferenceCapacityAdmitsTenEqualShares(t *testing.T) {
	t.Parallel()
	c, err := New(ReferenceCapacity())
	if err != nil {
		t.Fatal(err)
	}
	decision := c.PlanStart(Snapshot{Running: 9, DiskFreeGiB: 200})
	if !decision.Admitted {
		t.Fatalf("tenth workspace was not admitted: %#v", decision)
	}
	minimum := ReferenceCapacity().Minimum
	if decision.Quota.CPUMilli < minimum.CPUMilli || decision.Quota.MemoryMiB < minimum.MemoryMiB || decision.Quota.DiskGiB < minimum.DiskGiB {
		t.Fatalf("unsafe tenth share: %#v", decision.Quota)
	}
	shares, err := c.Shares(10)
	if err != nil || len(shares) != 10 {
		t.Fatalf("shares: %v, %v", shares, err)
	}
	for i, share := range shares {
		if share != shares[0] {
			t.Fatalf("share %d differs: %#v vs %#v", i, share, shares[0])
		}
	}
}

func TestEleventhWorkspaceQueuesWithoutScaling(t *testing.T) {
	t.Parallel()
	c, _ := New(ReferenceCapacity())
	decision := c.PlanStart(Snapshot{Running: 10, Queued: 2, DiskFreeGiB: 200})
	if decision.Admitted || decision.QueuePosition != 3 || decision.Reason == "" {
		t.Fatalf("unexpected decision: %#v", decision)
	}
}

func TestDiskReserveQueuesStart(t *testing.T) {
	t.Parallel()
	c, _ := New(ReferenceCapacity())
	decision := c.PlanStart(Snapshot{Running: 9, DiskFreeGiB: 55})
	if decision.Admitted || decision.Reason != "disk reserve would be violated" {
		t.Fatalf("unexpected disk decision: %#v", decision)
	}
	decision = c.PlanStart(Snapshot{Running: 9, DiskFreeGiB: 56})
	if !decision.Admitted {
		t.Fatalf("safe tenth workspace was refused at the exact reserve boundary: %#v", decision)
	}
}

func TestDiskReserveIncludesDurableProvisioningReservations(t *testing.T) {
	t.Parallel()
	c, _ := New(ReferenceCapacity())
	decision := c.PlanStart(Snapshot{Running: 1, DiskFreeGiB: 71, PendingDiskGiB: 16})
	if decision.Admitted || decision.Reason != "disk reserve would be violated" {
		t.Fatalf("pending disk reservation was ignored: %#v", decision)
	}
	decision = c.PlanStart(Snapshot{Running: 1, DiskFreeGiB: 72, PendingDiskGiB: 16})
	if !decision.Admitted {
		t.Fatalf("exact pending-reservation boundary was refused: %#v", decision)
	}
}

func TestInvalidCapacityRejected(t *testing.T) {
	t.Parallel()
	_, err := New(Capacity{Total: core.Quota{CPUMilli: 1, MemoryMiB: 1, DiskGiB: 1}, Minimum: core.Quota{CPUMilli: 1, MemoryMiB: 1, DiskGiB: 1}, MaxRunning: 11})
	if err == nil {
		t.Fatal("expected invalid capacity")
	}
}

func TestMaintenanceDrainQueuesWithoutChangingCapacity(t *testing.T) {
	t.Parallel()
	c, err := New(ReferenceCapacity())
	if err != nil {
		t.Fatal(err)
	}
	c.SetMaintenanceDrain(true)
	decision := c.PlanStart(Snapshot{Running: 0, Queued: 2, DiskFreeGiB: 200})
	if decision.Admitted || decision.QueuePosition != 3 || decision.Reason != "server maintenance admission drain is active" {
		t.Fatalf("unexpected maintenance decision: %#v", decision)
	}
	c.SetMaintenanceDrain(false)
	if decision := c.PlanStart(Snapshot{DiskFreeGiB: 200}); !decision.Admitted {
		t.Fatalf("admission did not reopen: %#v", decision)
	}
}
