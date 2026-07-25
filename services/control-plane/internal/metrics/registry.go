// Package metrics exposes a deliberately small, local-only Prometheus text
// surface. Callers provide bounded operation names, never repository names,
// workspace IDs, paths, commands, prompts, terminal output, or secret values.
package metrics

import (
	"fmt"
	"net/http"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const maxOperationLength = 80

type httpKey struct {
	operation   string
	statusClass string
}

// Registry is safe for concurrent use. It intentionally avoids a third-party
// monitoring service and cardinality-bearing resource labels.
type Registry struct {
	startedAt time.Time

	mu               sync.Mutex
	httpRequests     map[httpKey]uint64
	httpDurationMS   map[string]uint64
	httpObservations map[string]uint64

	checkpointSuccess  atomic.Uint64
	checkpointFailure  atomic.Uint64
	notificationSent   atomic.Uint64
	notificationFailed atomic.Uint64
	maintenanceRuns    atomic.Uint64
	maintenanceFailed  atomic.Uint64
	runningWorkspaces  atomic.Int64
	queuedWorkspaces   atomic.Int64
	terminalSessions   atomic.Int64
}

func New() *Registry {
	return &Registry{
		startedAt:        time.Now().UTC(),
		httpRequests:     make(map[httpKey]uint64),
		httpDurationMS:   make(map[string]uint64),
		httpObservations: make(map[string]uint64),
	}
}

func (r *Registry) RecordHTTP(operation string, status int, duration time.Duration) {
	operation = safeOperation(operation)
	class := "other"
	if status >= 100 && status <= 599 {
		class = strconv.Itoa(status/100) + "xx"
	}
	if duration < 0 {
		duration = 0
	}
	r.mu.Lock()
	r.httpRequests[httpKey{operation: operation, statusClass: class}]++
	r.httpDurationMS[operation] += uint64(duration / time.Millisecond)
	r.httpObservations[operation]++
	r.mu.Unlock()
}

func (r *Registry) RecordCheckpoint(success bool) {
	if success {
		r.checkpointSuccess.Add(1)
	} else {
		r.checkpointFailure.Add(1)
	}
}

func (r *Registry) RecordNotification(success bool) {
	if success {
		r.notificationSent.Add(1)
	} else {
		r.notificationFailed.Add(1)
	}
}

func (r *Registry) RecordMaintenance(success bool) {
	if success {
		r.maintenanceRuns.Add(1)
	} else {
		r.maintenanceFailed.Add(1)
	}
}

func (r *Registry) SetWorkspaceCounts(running, queued int) {
	if running < 0 {
		running = 0
	}
	if queued < 0 {
		queued = 0
	}
	r.runningWorkspaces.Store(int64(running))
	r.queuedWorkspaces.Store(int64(queued))
}

func (r *Registry) SetTerminalSessions(value int) {
	if value < 0 {
		value = 0
	}
	r.terminalSessions.Store(int64(value))
}

func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/metrics" {
			http.NotFound(w, request)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write([]byte(r.Render()))
	})
}

func (r *Registry) Render() string {
	r.mu.Lock()
	requests := make(map[httpKey]uint64, len(r.httpRequests))
	for key, value := range r.httpRequests {
		requests[key] = value
	}
	durations := make(map[string]uint64, len(r.httpDurationMS))
	for key, value := range r.httpDurationMS {
		durations[key] = value
	}
	observations := make(map[string]uint64, len(r.httpObservations))
	for key, value := range r.httpObservations {
		observations[key] = value
	}
	r.mu.Unlock()

	keys := make([]httpKey, 0, len(requests))
	for key := range requests {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].operation == keys[j].operation {
			return keys[i].statusClass < keys[j].statusClass
		}
		return keys[i].operation < keys[j].operation
	})
	operations := make([]string, 0, len(durations))
	for operation := range durations {
		operations = append(operations, operation)
	}
	sort.Strings(operations)

	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	var output strings.Builder
	output.WriteString("# HELP codex_mobile_uptime_seconds Control-plane process uptime.\n")
	output.WriteString("# TYPE codex_mobile_uptime_seconds gauge\n")
	fmt.Fprintf(&output, "codex_mobile_uptime_seconds %.0f\n", time.Since(r.startedAt).Seconds())
	output.WriteString("# HELP codex_mobile_http_requests_total Bounded REST requests by operation and status class.\n")
	output.WriteString("# TYPE codex_mobile_http_requests_total counter\n")
	for _, key := range keys {
		fmt.Fprintf(&output, "codex_mobile_http_requests_total{operation=%q,status_class=%q} %d\n", key.operation, key.statusClass, requests[key])
	}
	output.WriteString("# HELP codex_mobile_http_request_duration_milliseconds_total Cumulative REST handler time.\n")
	output.WriteString("# TYPE codex_mobile_http_request_duration_milliseconds_total counter\n")
	for _, operation := range operations {
		fmt.Fprintf(&output, "codex_mobile_http_request_duration_milliseconds_total{operation=%q} %d\n", operation, durations[operation])
		fmt.Fprintf(&output, "codex_mobile_http_request_duration_observations_total{operation=%q} %d\n", operation, observations[operation])
	}
	writeCounter(&output, "checkpoint_success_total", r.checkpointSuccess.Load())
	writeCounter(&output, "checkpoint_failure_total", r.checkpointFailure.Load())
	writeCounter(&output, "notification_sent_total", r.notificationSent.Load())
	writeCounter(&output, "notification_failure_total", r.notificationFailed.Load())
	writeCounter(&output, "maintenance_success_total", r.maintenanceRuns.Load())
	writeCounter(&output, "maintenance_failure_total", r.maintenanceFailed.Load())
	writeGauge(&output, "running_workspaces", r.runningWorkspaces.Load())
	writeGauge(&output, "queued_workspaces", r.queuedWorkspaces.Load())
	writeGauge(&output, "terminal_sessions", r.terminalSessions.Load())
	writeGauge(&output, "go_goroutines", int64(runtime.NumGoroutine()))
	writeGauge(&output, "go_heap_bytes", int64(memory.HeapAlloc))
	return output.String()
}

func safeOperation(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxOperationLength {
		return "unknown"
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '_' || character == '-' || character == '.' {
			continue
		}
		return "unknown"
	}
	return value
}

func writeCounter(output *strings.Builder, name string, value uint64) {
	fmt.Fprintf(output, "# TYPE codex_mobile_%s counter\ncodex_mobile_%s %d\n", name, name, value)
}

func writeGauge(output *strings.Builder, name string, value int64) {
	fmt.Fprintf(output, "# TYPE codex_mobile_%s gauge\ncodex_mobile_%s %d\n", name, name, value)
}
