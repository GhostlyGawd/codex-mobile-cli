package terminal

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

type controlledTerminalFrameWriter struct {
	mu      sync.Mutex
	calls   int
	frames  []Frame
	started chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func newControlledTerminalFrameWriter(release <-chan struct{}) *controlledTerminalFrameWriter {
	return &controlledTerminalFrameWriter{started: make(chan struct{}), release: release}
}

func (w *controlledTerminalFrameWriter) Write(ctx context.Context, messageType websocket.MessageType, payload []byte) error {
	if messageType != websocket.MessageBinary {
		return errors.New("terminal test writer received a non-binary frame")
	}
	frame, err := ParseFrame(payload)
	if err != nil {
		return err
	}
	w.mu.Lock()
	w.calls++
	w.mu.Unlock()
	w.once.Do(func() { close(w.started) })
	if w.release != nil {
		select {
		case <-w.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	w.mu.Lock()
	w.frames = append(w.frames, frame)
	w.mu.Unlock()
	return nil
}

func (w *controlledTerminalFrameWriter) counts() (int, int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.calls, len(w.frames)
}

type blockingMutationRuntime struct {
	output        chan []byte
	writeStarted  chan struct{}
	writeRelease  chan struct{}
	resizeStarted chan struct{}
	resizeRelease chan struct{}
	writeOnce     sync.Once
	resizeOnce    sync.Once
	releaseWrite  sync.Once
	releaseResize sync.Once
	mu            sync.Mutex
	inputs        [][]byte
	sizes         []Size
	closed        bool
}

func newBlockingMutationRuntime() *blockingMutationRuntime {
	return &blockingMutationRuntime{
		output:        make(chan []byte),
		writeStarted:  make(chan struct{}),
		writeRelease:  make(chan struct{}),
		resizeStarted: make(chan struct{}),
		resizeRelease: make(chan struct{}),
	}
}

func (r *blockingMutationRuntime) Output() <-chan []byte { return r.output }

func (r *blockingMutationRuntime) WriteInput(_ context.Context, payload []byte) error {
	r.writeOnce.Do(func() { close(r.writeStarted) })
	<-r.writeRelease
	r.mu.Lock()
	r.inputs = append(r.inputs, append([]byte(nil), payload...))
	r.mu.Unlock()
	return nil
}

func (r *blockingMutationRuntime) Resize(_ context.Context, size Size) error {
	r.resizeOnce.Do(func() { close(r.resizeStarted) })
	<-r.resizeRelease
	r.mu.Lock()
	r.sizes = append(r.sizes, size)
	r.mu.Unlock()
	return nil
}

func (r *blockingMutationRuntime) Close() error {
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	return nil
}

func (r *blockingMutationRuntime) allowWrite() {
	r.releaseWrite.Do(func() { close(r.writeRelease) })
}

func (r *blockingMutationRuntime) allowResize() {
	r.releaseResize.Do(func() { close(r.resizeRelease) })
}

func openBlockingAdmission(t *testing.T) (*Manager, *Gateway, *tabState, admittedConnection, *blockingMutationRuntime) {
	t.Helper()
	manager, err := NewManager([]byte("0123456789abcdef0123456789abcdef"), nil)
	if err != nil {
		t.Fatal(err)
	}
	tabID, err := NewTabID()
	if err != nil {
		t.Fatal(err)
	}
	runtime := newBlockingMutationRuntime()
	if err := manager.Register("owner", "workspace", tabID, runtime, testOutputRedactor(t), false); err != nil {
		t.Fatal(err)
	}
	connection, err := manager.Issue("owner", "device-a", "workspace", tabID, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	admission, err := manager.admit(connection.Ticket)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admission.tab.lease.Request("device-a", false, manager.now()); err != nil {
		t.Fatal(err)
	}
	gateway := &Gateway{manager: manager}
	t.Cleanup(func() {
		runtime.allowWrite()
		runtime.allowResize()
		manager.unsubscribe(admission)
		_ = manager.Close()
	})
	return manager, gateway, admission.tab, admission, runtime
}

func TestRevokeDeviceDeniesBufferedOutputWrite(t *testing.T) {
	manager, _, tab, admission, _ := openBlockingAdmission(t)
	tab.broadcast(Frame{Kind: KindOutput, Sequence: 1, TabID: tab.id, Payload: []byte("buffered secret output")})
	selected := <-admission.outbound
	if disconnected := manager.RevokeDevice("owner", "device-a"); disconnected != 1 {
		t.Fatalf("revocation disconnected %d connections", disconnected)
	}
	writer := newControlledTerminalFrameWriter(nil)
	err := writeFrame(context.Background(), writer, admission.deliveries, selected)
	if !errors.Is(err, errTerminalAccessRevoked) {
		t.Fatalf("buffered output writer returned %v", err)
	}
	if calls, frames := writer.counts(); calls != 0 || frames != 0 {
		t.Fatalf("buffered output began after revocation: calls=%d frames=%d", calls, frames)
	}
}

func TestRevokeDeviceDeniesInitialReplayWrite(t *testing.T) {
	manager, _, tab, admission, _ := openBlockingAdmission(t)
	if disconnected := manager.RevokeDevice("owner", "device-a"); disconnected != 1 {
		t.Fatalf("revocation disconnected %d connections", disconnected)
	}
	writer := newControlledTerminalFrameWriter(nil)
	initial := Frame{Kind: KindOutput, Sequence: 1, TabID: tab.id, Payload: []byte("replayed secret output")}
	err := writeFrame(context.Background(), writer, admission.deliveries, initial)
	if !errors.Is(err, errTerminalAccessRevoked) {
		t.Fatalf("initial replay writer returned %v", err)
	}
	if calls, frames := writer.counts(); calls != 0 || frames != 0 {
		t.Fatalf("initial replay began after revocation: calls=%d frames=%d", calls, frames)
	}
}

func TestRevokeDeviceDeniesBufferedAttentionWrite(t *testing.T) {
	manager, _, tab, admission, _ := openBlockingAdmission(t)
	manager.Notify(tab.id, "question")
	selected := <-admission.outbound
	if selected.Kind != KindAttention {
		t.Fatalf("selected frame kind = %v, want attention", selected.Kind)
	}
	if disconnected := manager.RevokeDevice("owner", "device-a"); disconnected != 1 {
		t.Fatalf("revocation disconnected %d connections", disconnected)
	}
	writer := newControlledTerminalFrameWriter(nil)
	err := writeFrame(context.Background(), writer, admission.deliveries, selected)
	if !errors.Is(err, errTerminalAccessRevoked) {
		t.Fatalf("attention writer returned %v", err)
	}
	if calls, frames := writer.counts(); calls != 0 || frames != 0 {
		t.Fatalf("attention write began after revocation: calls=%d frames=%d", calls, frames)
	}
}

func TestRevokeDeviceDrainsAlreadyStartedWebSocketWrite(t *testing.T) {
	manager, _, tab, admission, _ := openBlockingAdmission(t)
	writeRelease := make(chan struct{})
	writer := newControlledTerminalFrameWriter(writeRelease)
	writeDone := make(chan error, 1)
	initial := []Frame{{Kind: KindOutput, Sequence: 1, TabID: tab.id, Payload: []byte("already-started secret output")}}
	go func() {
		writeDone <- writeFrames(context.Background(), writer, initial, make(chan connectionResponse), admission.outbound, admission.revoked, admission.deliveries)
	}()
	<-writer.started

	revokeDone := make(chan int, 1)
	go func() {
		revokeDone <- manager.RevokeDevice("owner", "device-a")
	}()
	waitFor(t, func() bool { return deliveryGateIsRevoked(admission.deliveries) })
	assertStillBlocked(t, revokeDone, "device revocation returned while a WebSocket write was in flight")

	// RevokeDevice must wait without manager/tab locks. Attention publication
	// traverses both locks and must remain non-blocking while the write drains.
	attentionDone := make(chan struct{})
	go func() {
		manager.Notify(tab.id, "question")
		close(attentionDone)
	}()
	_ = receiveWithin(t, attentionDone)

	close(writeRelease)
	if disconnected := receiveWithin(t, revokeDone); disconnected != 1 {
		t.Fatalf("revocation disconnected %d connections", disconnected)
	}
	_ = receiveWithin(t, writeDone)
	if err := writeFrame(context.Background(), writer, admission.deliveries, Frame{
		Kind: KindAttention, TabID: tab.id, Payload: []byte("after revoke"),
	}); !errors.Is(err, errTerminalAccessRevoked) {
		t.Fatalf("post-revocation write returned %v", err)
	}
	if calls, frames := writer.counts(); calls != 1 || frames != 1 {
		t.Fatalf("WebSocket writes after drain: calls=%d frames=%d", calls, frames)
	}
}

func TestRevokeDeviceDrainsBlockedInputAndRejectsEveryLaterMutation(t *testing.T) {
	manager, gateway, tab, admission, runtime := openBlockingAdmission(t)
	inputDone := make(chan error, 1)
	go func() {
		inputDone <- gateway.handleFrame(context.Background(), tab, admission.record, admission.mutations, Frame{
			Kind: KindInput, TabID: tab.id, Payload: []byte("before revoke\n"),
		}, nil)
	}()
	<-runtime.writeStarted

	revokeDone := make(chan int, 1)
	revokeStarted := make(chan struct{})
	go func() {
		close(revokeStarted)
		revokeDone <- manager.RevokeDevice("owner", "device-a")
	}()
	<-revokeStarted
	assertStillBlocked(t, revokeDone, "device revocation returned while PTY input was in flight")
	runtime.allowWrite()
	if err := receiveWithin(t, inputDone); err != nil {
		t.Fatal(err)
	}
	if disconnected := receiveWithin(t, revokeDone); disconnected != 1 {
		t.Fatalf("revocation disconnected %d connections", disconnected)
	}

	postRevokeFrames := []Frame{
		{Kind: KindInput, TabID: tab.id, Payload: []byte("after revoke\n")},
		{Kind: KindResize, TabID: tab.id, Payload: mustMarshalSize(t, Size{Rows: 40, Columns: 120})},
		{Kind: KindLeaseRequest, TabID: tab.id, Payload: []byte("device-a")},
		{Kind: KindAck, Flags: FlagInputReceiptConfirmed, Sequence: 7, TabID: tab.id},
	}
	for _, frame := range postRevokeFrames {
		if err := gateway.handleFrame(context.Background(), tab, admission.record, admission.mutations, frame, nil); !errors.Is(err, errTerminalAccessRevoked) {
			t.Fatalf("post-revocation mutation %v error = %v", frame.Kind, err)
		}
	}
	runtime.mu.Lock()
	inputs, sizes, closed := len(runtime.inputs), len(runtime.sizes), runtime.closed
	runtime.mu.Unlock()
	if inputs != 1 || sizes != 0 || closed {
		t.Fatalf("post-revocation PTY state inputs=%d sizes=%d closed=%v", inputs, sizes, closed)
	}
	if holder := tab.lease.Holder(manager.now()); holder.DeviceID != "" {
		t.Fatalf("revoked device reacquired the lease: %#v", holder)
	}
}

func TestRevokeDeviceDrainsBlockedResizeBeforeReturning(t *testing.T) {
	manager, gateway, tab, admission, runtime := openBlockingAdmission(t)
	resizeDone := make(chan error, 1)
	go func() {
		resizeDone <- gateway.handleFrame(context.Background(), tab, admission.record, admission.mutations, Frame{
			Kind: KindResize, TabID: tab.id, Payload: mustMarshalSize(t, Size{Rows: 30, Columns: 100}),
		}, nil)
	}()
	<-runtime.resizeStarted
	revokeDone := make(chan int, 1)
	revokeStarted := make(chan struct{})
	go func() {
		close(revokeStarted)
		revokeDone <- manager.RevokeDevice("owner", "device-a")
	}()
	<-revokeStarted
	assertStillBlocked(t, revokeDone, "device revocation returned while PTY resize was in flight")
	runtime.allowResize()
	if err := receiveWithin(t, resizeDone); err != nil {
		t.Fatal(err)
	}
	if disconnected := receiveWithin(t, revokeDone); disconnected != 1 {
		t.Fatalf("revocation disconnected %d connections", disconnected)
	}
	if err := gateway.handleFrame(context.Background(), tab, admission.record, admission.mutations, Frame{
		Kind: KindResize, TabID: tab.id, Payload: mustMarshalSize(t, Size{Rows: 50, Columns: 160}),
	}, nil); !errors.Is(err, errTerminalAccessRevoked) {
		t.Fatalf("post-revocation resize error = %v", err)
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if len(runtime.sizes) != 1 {
		t.Fatalf("post-revocation resize reached PTY: %#v", runtime.sizes)
	}
}

func TestUnregisterDrainsBlockedInputBeforeClosingRuntime(t *testing.T) {
	manager, gateway, tab, admission, runtime := openBlockingAdmission(t)
	inputDone := make(chan error, 1)
	go func() {
		inputDone <- gateway.handleFrame(context.Background(), tab, admission.record, admission.mutations, Frame{
			Kind: KindInput, TabID: tab.id, Payload: []byte("finish first\n"),
		}, nil)
	}()
	<-runtime.writeStarted
	unregisterDone := make(chan error, 1)
	unregisterStarted := make(chan struct{})
	go func() {
		close(unregisterStarted)
		unregisterDone <- manager.Unregister(tab.id, "owner_closed")
	}()
	<-unregisterStarted
	waitFor(t, tab.isClosed)
	assertStillBlocked(t, unregisterDone, "tab unregister returned while PTY input was in flight")
	revokeDone := make(chan int, 1)
	revokeStarted := make(chan struct{})
	go func() {
		close(revokeStarted)
		revokeDone <- manager.RevokeDevice("owner", "device-a")
	}()
	<-revokeStarted
	assertStillBlocked(t, revokeDone, "device revocation missed an already-closing tab")
	runtime.mu.Lock()
	closedBeforeDrain := runtime.closed
	runtime.mu.Unlock()
	if closedBeforeDrain {
		t.Fatal("runtime closed before its admitted input drained")
	}
	runtime.allowWrite()
	if err := receiveWithin(t, inputDone); err != nil {
		t.Fatal(err)
	}
	if err := receiveWithin(t, unregisterDone); err != nil {
		t.Fatal(err)
	}
	_ = receiveWithin(t, revokeDone)
	runtime.mu.Lock()
	closedAfterDrain := runtime.closed
	runtime.mu.Unlock()
	if !closedAfterDrain {
		t.Fatal("unregister did not close runtime after draining input")
	}
}

func TestManagerCloseDrainsWithoutHoldingActivityLock(t *testing.T) {
	manager, gateway, tab, admission, runtime := openBlockingAdmission(t)
	if err := manager.ConfigureActivityObserver(func(ActivityEvent) {}); err == nil {
		// openBlockingAdmission registers first, so install the observer directly
		// under the manager lock for this lock-order regression test.
		t.Fatal("activity observer unexpectedly configured after registration")
	}
	manager.mu.Lock()
	manager.activity = func(ActivityEvent) {}
	manager.mu.Unlock()
	inputDone := make(chan error, 1)
	go func() {
		inputDone <- gateway.handleFrame(context.Background(), tab, admission.record, admission.mutations, Frame{
			Kind: KindInput, TabID: tab.id, Payload: []byte("activity after write\n"),
		}, nil)
	}()
	<-runtime.writeStarted
	closeDone := make(chan error, 1)
	closeStarted := make(chan struct{})
	go func() {
		close(closeStarted)
		closeDone <- manager.Close()
	}()
	<-closeStarted
	waitFor(t, tab.isClosed)
	assertStillBlocked(t, closeDone, "manager close returned while PTY input was in flight")
	revokeDone := make(chan int, 1)
	revokeStarted := make(chan struct{})
	go func() {
		close(revokeStarted)
		revokeDone <- manager.RevokeDevice("owner", "device-a")
	}()
	<-revokeStarted
	assertStillBlocked(t, revokeDone, "device revocation missed a tab during manager close")
	runtime.allowWrite()
	if err := receiveWithin(t, inputDone); err != nil {
		t.Fatal(err)
	}
	if err := receiveWithin(t, closeDone); err != nil {
		t.Fatal(err)
	}
	_ = receiveWithin(t, revokeDone)
}

func TestUnregisterJoinsDeviceRevocationDrainWhenRevokeStartsFirst(t *testing.T) {
	manager, gateway, tab, admission, runtime := openBlockingAdmission(t)
	inputDone := make(chan error, 1)
	go func() {
		inputDone <- gateway.handleFrame(context.Background(), tab, admission.record, admission.mutations, Frame{
			Kind: KindInput, TabID: tab.id, Payload: []byte("revoke first\n"),
		}, nil)
	}()
	<-runtime.writeStarted
	revokeDone := make(chan int, 1)
	revokeStarted := make(chan struct{})
	go func() {
		close(revokeStarted)
		revokeDone <- manager.RevokeDevice("owner", "device-a")
	}()
	<-revokeStarted
	waitFor(t, func() bool { return mutationGateIsRevoked(admission.mutations) })
	unregisterDone := make(chan error, 1)
	unregisterStarted := make(chan struct{})
	go func() {
		close(unregisterStarted)
		unregisterDone <- manager.Unregister(tab.id, "owner_closed")
	}()
	<-unregisterStarted
	assertStillBlocked(t, revokeDone, "device revocation returned before its earlier input drained")
	assertStillBlocked(t, unregisterDone, "unregister failed to join an existing device drain")
	runtime.allowWrite()
	if err := receiveWithin(t, inputDone); err != nil {
		t.Fatal(err)
	}
	_ = receiveWithin(t, revokeDone)
	if err := receiveWithin(t, unregisterDone); err != nil {
		t.Fatal(err)
	}
}

func TestManagerCloseJoinsDeviceRevocationDrainWhenRevokeStartsFirst(t *testing.T) {
	manager, gateway, tab, admission, runtime := openBlockingAdmission(t)
	inputDone := make(chan error, 1)
	go func() {
		inputDone <- gateway.handleFrame(context.Background(), tab, admission.record, admission.mutations, Frame{
			Kind: KindInput, TabID: tab.id, Payload: []byte("revoke before shutdown\n"),
		}, nil)
	}()
	<-runtime.writeStarted
	revokeDone := make(chan int, 1)
	revokeStarted := make(chan struct{})
	go func() {
		close(revokeStarted)
		revokeDone <- manager.RevokeDevice("owner", "device-a")
	}()
	<-revokeStarted
	waitFor(t, func() bool { return mutationGateIsRevoked(admission.mutations) })
	closeDone := make(chan error, 1)
	closeStarted := make(chan struct{})
	go func() {
		close(closeStarted)
		closeDone <- manager.Close()
	}()
	<-closeStarted
	assertStillBlocked(t, revokeDone, "device revocation returned before its earlier input drained")
	assertStillBlocked(t, closeDone, "manager close failed to join an existing device drain")
	runtime.allowWrite()
	if err := receiveWithin(t, inputDone); err != nil {
		t.Fatal(err)
	}
	_ = receiveWithin(t, revokeDone)
	if err := receiveWithin(t, closeDone); err != nil {
		t.Fatal(err)
	}
}

func assertStillBlocked[T any](t *testing.T, done <-chan T, failure string) {
	t.Helper()
	select {
	case <-done:
		t.Fatal(failure)
	case <-time.After(25 * time.Millisecond):
	}
}

func receiveWithin[T any](t *testing.T, values <-chan T) T {
	t.Helper()
	select {
	case value := <-values:
		return value
	case <-time.After(2 * time.Second):
		var zero T
		t.Fatal("timed out waiting for terminal concurrency result")
		return zero
	}
}

func mustMarshalSize(t *testing.T, size Size) []byte {
	t.Helper()
	payload, err := size.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func mutationGateIsRevoked(gate *connectionMutationGate) bool {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	return gate.revoked
}

func deliveryGateIsRevoked(gate *connectionDeliveryGate) bool {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	return gate.revoked
}
