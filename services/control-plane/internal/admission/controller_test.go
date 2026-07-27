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

func TestOwnerPCBetaCapacityAdmitsExactlyOneBoundedWorkspace(t *testing.T) {
	t.Parallel()
	capacity := OwnerPCBetaCapacity()
	if capacity.MaxRunning != 1 {
		t.Fatalf("unexpected owner-PC maximum: %d", capacity.MaxRunning)
	}
	c, err := New(capacity)
	if err != nil {
		t.Fatal(err)
	}
	decision := c.PlanStart(Snapshot{DiskFreeGiB: 40})
	if !decision.Admitted {
		t.Fatalf("owner-PC workspace was not admitted at the exact boundary: %#v", decision)
	}
	want := core.Quota{CPUMilli: 2000, MemoryMiB: 2048, DiskGiB: 40}
	if decision.Quota != want {
		t.Fatalf("owner-PC quota = %#v, want %#v", decision.Quota, want)
	}
	second := c.PlanStart(Snapshot{Running: 1, DiskFreeGiB: 64})
	if second.Admitted || second.Reason != "running workspace limit reached" {
		t.Fatalf("second owner-PC workspace was not queued: %#v", second)
	}
}

func TestOwnerPCBetaDiskReserveFailsClosedBelowBoundary(t *testing.T) {
	t.Parallel()
	c, err := New(OwnerPCBetaCapacity())
	if err != nil {
		t.Fatal(err)
	}
	decision := c.PlanStart(Snapshot{DiskFreeGiB: 39})
	if decision.Admitted || decision.Reason != "disk reserve would be violated" {
		t.Fatalf("unexpected owner-PC disk decision: %#v", decision)
	}
}

func TestCapacityForProfileRejectsDeferredAndUnknownProfiles(t *testing.T) {
	t.Parallel()
	for _, profile := range []string{"", "fixed_price_vps", "unknown"} {
		if _, err := CapacityForProfile(profile); err == nil {
			t.Fatalf("profile %q was accepted", profile)
		}
	}
	if got, err := CapacityForProfile("owner_pc_beta"); err != nil || got != OwnerPCBetaCapacity() {
		t.Fatalf("owner profile capacity: %#v, %v", got, err)
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
	for _, capacity := range []Capacity{
		{
			Total:       core.Quota{CPUMilli: 2, MemoryMiB: 2, DiskGiB: 2},
			Reserve:     core.Quota{CPUMilli: 3, MemoryMiB: 1, DiskGiB: 1},
			Minimum:     core.Quota{CPUMilli: 1, MemoryMiB: 1, DiskGiB: 1},
			MaxRunning:  1,
			DiskReserve: 1,
		},
		{
			Total:       core.Quota{CPUMilli: 2, MemoryMiB: 2, DiskGiB: 2},
			Reserve:     core.Quota{CPUMilli: 0, MemoryMiB: -1, DiskGiB: 0},
			Minimum:     core.Quota{CPUMilli: 1, MemoryMiB: 1, DiskGiB: 1},
			MaxRunning:  1,
			DiskReserve: 0,
		},
	} {
		if _, err := New(capacity); err == nil {
			t.Fatalf("accepted invalid capacity: %#v", capacity)
		}
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
