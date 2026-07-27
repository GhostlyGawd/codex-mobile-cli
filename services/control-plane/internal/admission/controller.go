package admission

import (
	"fmt"
	"sync/atomic"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
)

type Capacity struct {
	Total       core.Quota
	Reserve     core.Quota
	Minimum     core.Quota
	MaxRunning  int
	DiskReserve int64
}

type Snapshot struct {
	Running        int
	Queued         int
	DiskFreeGiB    int64
	PendingDiskGiB int64
}

type Decision struct {
	Admitted      bool       `json:"admitted"`
	Reason        string     `json:"reason,omitempty"`
	QueuePosition int        `json:"queue_position,omitempty"`
	Quota         core.Quota `json:"quota"`
	Pressure      float64    `json:"pressure"`
}

func ReferenceCapacity() Capacity {
	return Capacity{
		Total:       core.Quota{CPUMilli: 8000, MemoryMiB: 24 * 1024, DiskGiB: 200},
		Reserve:     core.Quota{CPUMilli: 2000, MemoryMiB: 6 * 1024, DiskGiB: 40},
		Minimum:     core.Quota{CPUMilli: 500, MemoryMiB: 1536, DiskGiB: 8},
		MaxRunning:  10,
		DiskReserve: 40,
	}
}

// OwnerPCBetaCapacity is intentionally smaller than the measured WSL VM.
// Trusted host/control services retain 2 CPU and 3 GiB while the sole
// untrusted workspace receives exactly 2 CPU and 2 GiB. The 24 GiB disk
// reserve plus the maximum 16 GiB immutable workspace keeps admission closed
// below 40 GiB free on the dedicated 64 GiB XFS filesystem.
func OwnerPCBetaCapacity() Capacity {
	return Capacity{
		Total:       core.Quota{CPUMilli: 4000, MemoryMiB: 5 * 1024, DiskGiB: 64},
		Reserve:     core.Quota{CPUMilli: 2000, MemoryMiB: 3 * 1024, DiskGiB: 24},
		Minimum:     core.Quota{CPUMilli: 2000, MemoryMiB: 2 * 1024, DiskGiB: 8},
		MaxRunning:  1,
		DiskReserve: 24,
	}
}

func CapacityForProfile(profile string) (Capacity, error) {
	switch profile {
	case "development":
		return ReferenceCapacity(), nil
	case "owner_pc_beta":
		return OwnerPCBetaCapacity(), nil
	default:
		return Capacity{}, fmt.Errorf("deployment profile %q is not supported", profile)
	}
}

type Controller struct {
	capacity         Capacity
	maintenanceDrain atomic.Bool
}

func New(capacity Capacity) (*Controller, error) {
	if capacity.MaxRunning < 1 || capacity.MaxRunning > 10 {
		return nil, fmt.Errorf("max running must be between 1 and 10")
	}
	if !positive(capacity.Total) || !positive(capacity.Minimum) ||
		negative(capacity.Reserve) || !notGreater(capacity.Reserve, capacity.Total) ||
		capacity.DiskReserve < capacity.Reserve.DiskGiB ||
		capacity.DiskReserve > capacity.Total.DiskGiB {
		return nil, fmt.Errorf("capacity totals, minimums, and disk reserve are invalid")
	}
	pool := subtract(capacity.Total, capacity.Reserve)
	if pool.CPUMilli < capacity.Minimum.CPUMilli || pool.MemoryMiB < capacity.Minimum.MemoryMiB || pool.DiskGiB < capacity.Minimum.DiskGiB {
		return nil, fmt.Errorf("control-plane reserve leaves less than one safe workspace")
	}
	return &Controller{capacity: capacity}, nil
}

func (c *Controller) PlanStart(snapshot Snapshot) Decision {
	if c.maintenanceDrain.Load() {
		return Decision{Reason: "server maintenance admission drain is active", QueuePosition: snapshot.Queued + 1}
	}
	count := snapshot.Running + 1
	if snapshot.Running < 0 || snapshot.Queued < 0 || snapshot.DiskFreeGiB < 0 || snapshot.PendingDiskGiB < 0 {
		return Decision{Reason: "invalid capacity snapshot"}
	}
	if count > c.capacity.MaxRunning {
		return Decision{Reason: "running workspace limit reached", QueuePosition: snapshot.Queued + 1, Pressure: 1}
	}
	quota := c.share(count)
	if below(quota, c.capacity.Minimum) {
		return Decision{Reason: "equal share would fall below the minimum safe allocation", QueuePosition: snapshot.Queued + 1, Quota: quota, Pressure: pressure(count, c.capacity.MaxRunning)}
	}
	// DiskFreeGiB already reflects all existing persistent volumes. Require
	// room for one worst-case immutable volume plus the full host reserve;
	// multiplying by the running count would double-count existing usage.
	neededFree := c.capacity.DiskReserve + core.MaximumWorkspaceDiskGiB + snapshot.PendingDiskGiB
	if snapshot.DiskFreeGiB < neededFree {
		return Decision{Reason: "disk reserve would be violated", QueuePosition: snapshot.Queued + 1, Quota: quota, Pressure: pressure(count, c.capacity.MaxRunning)}
	}
	return Decision{Admitted: true, Quota: quota, Pressure: pressure(count, c.capacity.MaxRunning)}
}

// SetMaintenanceDrain closes only new workspace admission. Existing runtime
// teardown is coordinated separately so a warning/checkpoint can complete.
func (c *Controller) SetMaintenanceDrain(enabled bool) {
	c.maintenanceDrain.Store(enabled)
}

func (c *Controller) Shares(running int) ([]core.Quota, error) {
	if running < 0 || running > c.capacity.MaxRunning {
		return nil, fmt.Errorf("running count outside policy")
	}
	if running == 0 {
		return []core.Quota{}, nil
	}
	q := c.share(running)
	if below(q, c.capacity.Minimum) {
		return nil, core.ErrCapacity
	}
	out := make([]core.Quota, running)
	for i := range out {
		out[i] = q
	}
	return out, nil
}

func (c *Controller) share(count int) core.Quota {
	pool := subtract(c.capacity.Total, c.capacity.Reserve)
	return core.Quota{
		CPUMilli:  pool.CPUMilli / int64(count),
		MemoryMiB: pool.MemoryMiB / int64(count),
		DiskGiB:   pool.DiskGiB / int64(count),
	}
}

func positive(q core.Quota) bool { return q.CPUMilli > 0 && q.MemoryMiB > 0 && q.DiskGiB > 0 }

func negative(q core.Quota) bool { return q.CPUMilli < 0 || q.MemoryMiB < 0 || q.DiskGiB < 0 }

func notGreater(a, b core.Quota) bool {
	return a.CPUMilli <= b.CPUMilli && a.MemoryMiB <= b.MemoryMiB && a.DiskGiB <= b.DiskGiB
}

func subtract(a, b core.Quota) core.Quota {
	return core.Quota{CPUMilli: a.CPUMilli - b.CPUMilli, MemoryMiB: a.MemoryMiB - b.MemoryMiB, DiskGiB: a.DiskGiB - b.DiskGiB}
}

func below(a, minimum core.Quota) bool {
	return a.CPUMilli < minimum.CPUMilli || a.MemoryMiB < minimum.MemoryMiB || a.DiskGiB < minimum.DiskGiB
}

func pressure(running, maximum int) float64 { return float64(running) / float64(maximum) }
