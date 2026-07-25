package coder

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/terminal"
	"github.com/coder/websocket"
)

func TestTmuxCommandIsFixedAndPersistent(t *testing.T) {
	command, err := tmuxCommand(PTYConfig{
		SessionName: "cm-primary-123", Kind: TerminalCodex,
		CodexTabID: "11111111-1111-4111-8111-111111111111", CodexThreadID: "thread-123",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"tmux new-session -A", "-s cm-primary-123", "-c /workspaces/repository", "exec /opt/codex-mobile-helper/codex-mobile-workspace-helper terminal codex 11111111-1111-4111-8111-111111111111 thread-123"} {
		if !strings.Contains(command, want) {
			t.Fatalf("command missing %q: %s", want, command)
		}
	}
	if _, err := tmuxCommand(PTYConfig{SessionName: "cm-bad;touch", Kind: TerminalShell}); err == nil {
		t.Fatal("expected unsafe session name rejection through OpenPTY validation")
	}
}

func TestOpenPTYValidation(t *testing.T) {
	client := &Client{}
	if _, err := client.OpenPTY(PTYConfig{AgentID: "agent", ReconnectID: "bad", SessionName: "cm-test", Kind: TerminalShell, InitialSize: terminal.Size{Rows: 24, Columns: 80}}); err == nil {
		t.Fatal("expected invalid reconnect UUID")
	}
}

func TestInitialPromptIsNotInterpolatedIntoShellCommand(t *testing.T) {
	t.Parallel()
	command, err := tmuxCommand(PTYConfig{
		SessionName: "cm-prompt-safe", Kind: TerminalCodex,
		CodexTabID:    "11111111-1111-4111-8111-111111111111",
		InitialPrompt: `fix it"; touch /tmp/escaped; #`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(command, "touch /tmp/escaped") || strings.Contains(command, "fix it") {
		t.Fatalf("initial prompt was interpolated into shell command: %q", command)
	}
}

func TestInitialPromptRequiresObservedTUIOutput(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	connection := &websocket.Conn{}
	runtime := &PTYRuntime{
		config: PTYConfig{Kind: TerminalCodex, InitialPrompt: "start here"},
		ctx:    ctx,
		conn:   connection,
	}
	runtime.scheduleInitialPrompt(connection, nil)
	if runtime.initialPromptConnection != nil {
		t.Fatal("an empty PTY frame armed initial-prompt delivery")
	}
	runtime.scheduleInitialPrompt(connection, []byte("first trusted child output"))
	runtime.mu.RLock()
	armed := runtime.initialPromptConnection == connection
	runtime.mu.RUnlock()
	if !armed {
		t.Fatal("real PTY output did not arm the stable-connection readiness barrier")
	}
	cancel()
}

func TestSerializedPTYWriteBoundsStalledTransport(t *testing.T) {
	runtimeCtx, cancelRuntime := context.WithCancel(context.Background())
	defer cancelRuntime()
	writeGate := make(chan struct{}, 1)
	writeGate <- struct{}{}
	started := time.Now()
	err := serializedPTYWrite(context.Background(), runtimeCtx, writeGate, 20*time.Millisecond, func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stalled PTY write error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("stalled PTY write exceeded its hard bound: %s", elapsed)
	}
}

func TestSerializedPTYWriteTimesOutWhileQueued(t *testing.T) {
	runtimeCtx, cancelRuntime := context.WithCancel(context.Background())
	defer cancelRuntime()
	writeGate := make(chan struct{}, 1)
	var called atomic.Bool
	started := time.Now()
	err := serializedPTYWrite(context.Background(), runtimeCtx, writeGate, 20*time.Millisecond, func(context.Context) error {
		called.Store(true)
		return nil
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("queued PTY write error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("queued PTY write exceeded its total bound: %s", elapsed)
	}
	if called.Load() {
		t.Fatal("timed-out queued PTY write reached the transport callback")
	}
}

func TestSerializedPTYWriteRejectsCanceledWaiterAfterLockAcquisition(t *testing.T) {
	runtimeCtx, cancelRuntime := context.WithCancel(context.Background())
	defer cancelRuntime()
	requestCtx, cancelRequest := context.WithCancel(context.Background())
	writeGate := make(chan struct{}, 1)
	var called atomic.Bool
	cancelRequest()
	if err := serializedPTYWrite(requestCtx, runtimeCtx, writeGate, time.Second, func(context.Context) error {
		called.Store(true)
		return nil
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled queued PTY write error = %v", err)
	}
	if called.Load() {
		t.Fatal("canceled queued PTY write reached the transport callback")
	}
}

func TestSerializedPTYWriteRejectsRuntimeCancellation(t *testing.T) {
	runtimeCtx, cancelRuntime := context.WithCancel(context.Background())
	cancelRuntime()
	writeGate := make(chan struct{}, 1)
	writeGate <- struct{}{}
	var called atomic.Bool
	err := serializedPTYWrite(context.Background(), runtimeCtx, writeGate, time.Second, func(context.Context) error {
		called.Store(true)
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("closed runtime PTY write error = %v", err)
	}
	if called.Load() {
		t.Fatal("closed runtime reached the PTY transport callback")
	}
}

func TestPTYOutputFloodIsChunkedAndBackpressuredByByteBudget(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	output := make(chan []byte, ptyOutputQueueChunks)
	done := make(chan error, 1)
	go func() {
		done <- enqueuePTYOutput(ctx, output, bytes.Repeat([]byte("x"), terminal.MaxPayload))
	}()
	deadline := time.Now().Add(2 * time.Second)
	for len(output) != ptyOutputQueueChunks && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(output) != ptyOutputQueueChunks {
		t.Fatalf("output queue did not reach its bounded backpressure point: %d", len(output))
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("backpressured PTY output error = %v", err)
	}
	queuedBytes := 0
	for index := 0; index < ptyOutputQueueChunks; index++ {
		chunk := <-output
		if len(chunk) == 0 || len(chunk) > ptyOutputChunkBytes {
			t.Fatalf("hostile PTY chunk size = %d", len(chunk))
		}
		queuedBytes += len(chunk)
	}
	if queuedBytes != ptyOutputQueueChunks*ptyOutputChunkBytes {
		t.Fatalf("PTY output queue bytes = %d", queuedBytes)
	}
}
