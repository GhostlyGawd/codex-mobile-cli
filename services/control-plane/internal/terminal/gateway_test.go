package terminal

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/codex"
	"github.com/coder/websocket"
)

type fakeRuntime struct {
	output chan []byte
	mu     sync.Mutex
	inputs [][]byte
	sizes  []Size
	closed bool
}

func newFakeRuntime() *fakeRuntime           { return &fakeRuntime{output: make(chan []byte, 16)} }
func (f *fakeRuntime) Output() <-chan []byte { return f.output }
func (f *fakeRuntime) WriteInput(_ context.Context, value []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inputs = append(f.inputs, append([]byte(nil), value...))
	return nil
}
func (f *fakeRuntime) Resize(_ context.Context, value Size) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sizes = append(f.sizes, value)
	return nil
}
func (f *fakeRuntime) Close() error { f.mu.Lock(); defer f.mu.Unlock(); f.closed = true; return nil }

func TestGatewayReplayLeaseInputAndOneUseTicket(t *testing.T) {
	manager, _ := NewManager([]byte("0123456789abcdef0123456789abcdef"), nil)
	defer manager.Close()
	tabID, _ := ParseTabID("52e782d5-6e80-4944-a42f-a21201900c74")
	runtime := newFakeRuntime()
	if err := manager.Register("owner", "workspace", tabID, runtime, testOutputRedactor(t), false); err != nil {
		t.Fatal(err)
	}
	runtime.output <- []byte("before")
	waitFor(t, func() bool { return manager.tabs[tabID].ring.After(0).LatestSequence == 1 })
	connection, err := manager.Issue("owner", "device-a", "workspace", tabID, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	gateway, _ := NewGateway(manager, "https://api.example.test")
	server := httptest.NewServer(gateway)
	defer server.Close()
	options := &websocket.DialOptions{Subprotocols: []string{Subprotocol}, HTTPHeader: http.Header{"Authorization": {"Bearer " + connection.Ticket}}}
	socket, _, err := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(server.URL, "http"), options)
	if err != nil {
		t.Fatal(err)
	}
	defer socket.CloseNow()
	_, data, err := socket.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	replay, err := ParseFrame(data)
	if err != nil || replay.Kind != KindOutput || string(replay.Payload) != "before" {
		t.Fatalf("unexpected replay: %#v %v", replay, err)
	}
	lease := Frame{Kind: KindLeaseRequest, TabID: tabID, Payload: []byte("device-a")}
	writeTestFrame(t, socket, lease)
	_, data, _ = socket.Read(context.Background())
	granted, _ := ParseFrame(data)
	if granted.Kind != KindLeaseGranted {
		t.Fatalf("expected lease grant, got %#v", granted)
	}
	writeTestFrame(t, socket, Frame{Kind: KindInput, TabID: tabID, Payload: []byte("ls\n")})
	waitFor(t, func() bool { runtime.mu.Lock(); defer runtime.mu.Unlock(); return len(runtime.inputs) == 1 })
	if _, _, err := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(server.URL, "http"), options); err == nil {
		t.Fatal("one-use ticket was accepted twice")
	}
	if runtime.closed {
		t.Fatal("WebSocket disconnect must not close persistent runtime")
	}
}

func TestDeviceRevocationClosesActiveSocketAndInvalidatesCredentials(t *testing.T) {
	manager, _ := NewManager([]byte("0123456789abcdef0123456789abcdef"), nil)
	defer manager.Close()
	tabID, _ := ParseTabID("52e782d5-6e80-4944-a42f-a21201900c74")
	runtime := newFakeRuntime()
	if err := manager.Register("owner", "workspace", tabID, runtime, testOutputRedactor(t), false); err != nil {
		t.Fatal(err)
	}
	active, err := manager.Issue("owner", "device-a", "workspace", tabID, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	unused, err := manager.Issue("owner", "device-a", "workspace", tabID, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	gateway, _ := NewGateway(manager, "https://api.example.test")
	server := httptest.NewServer(gateway)
	defer server.Close()
	socket, _, err := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(server.URL, "http"), &websocket.DialOptions{
		Subprotocols: []string{Subprotocol},
		HTTPHeader:   http.Header{"Authorization": {"Bearer " + active.Ticket}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.CloseNow()
	waitFor(t, func() bool {
		manager.tabs[tabID].mu.Lock()
		defer manager.tabs[tabID].mu.Unlock()
		return len(manager.tabs[tabID].subscribers) == 1
	})
	if decision, err := manager.tabs[tabID].lease.Request("device-a", false, time.Now()); err != nil || decision.Lease.DeviceID != "device-a" {
		t.Fatalf("lease before revoke = %#v, %v", decision, err)
	}
	if disconnected := manager.RevokeDevice("owner", "device-a"); disconnected != 1 {
		t.Fatalf("disconnected sockets = %d", disconnected)
	}
	readContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, _, err := socket.Read(readContext); err == nil {
		t.Fatal("revoked terminal WebSocket remained readable")
	}
	if _, err := manager.admit(unused.Ticket); err == nil {
		t.Fatal("unused ticket survived device revocation")
	}
	if _, err := manager.Issue("owner", "device-a", "workspace", tabID, 0, active.ReconnectToken); err == nil {
		t.Fatal("reconnect token survived device revocation")
	}
	if holder := manager.tabs[tabID].lease.Holder(time.Now()); holder.DeviceID != "" {
		t.Fatalf("revoked device retained lease: %#v", holder)
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.closed {
		t.Fatal("device revocation stopped the shared terminal runtime")
	}
}

func TestAdmissionCannotFallBehindDeviceRevocationSweep(t *testing.T) {
	manager, err := NewManager([]byte("0123456789abcdef0123456789abcdef"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	tabID, err := ParseTabID("52e782d5-6e80-4944-a42f-a21201900c74")
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Register("owner", "workspace", tabID, newFakeRuntime(), testOutputRedactor(t), false); err != nil {
		t.Fatal(err)
	}
	connection, err := manager.Issue("owner", "device-a", "workspace", tabID, 0, "")
	if err != nil {
		t.Fatal(err)
	}

	// Hold the tab boundary so admit has consumed the ticket while retaining
	// the manager lock, but cannot install the subscriber yet.
	tab := manager.tabs[tabID]
	tab.mu.Lock()
	admitted := make(chan admittedConnection, 1)
	admitErrors := make(chan error, 1)
	go func() {
		value, err := manager.admit(connection.Ticket)
		if err != nil {
			admitErrors <- err
			return
		}
		admitted <- value
	}()
	waitForManagerLock(t, manager)
	revokeStarted := make(chan struct{})
	disconnected := make(chan int, 1)
	go func() {
		close(revokeStarted)
		disconnected <- manager.RevokeDevice("owner", "device-a")
	}()
	<-revokeStarted
	tab.mu.Unlock()

	var admission admittedConnection
	select {
	case err := <-admitErrors:
		t.Fatal(err)
	case admission = <-admitted:
	}
	if got := <-disconnected; got != 1 {
		t.Fatalf("revocation missed admitted subscriber: %d", got)
	}
	select {
	case <-admission.revoked:
	default:
		t.Fatal("admission remained usable after the overlapping revocation")
	}
	if _, err := manager.admit(connection.Ticket); err == nil {
		t.Fatal("one-use admission ticket survived the overlap")
	}
}

func waitForManagerLock(t *testing.T, manager *Manager) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if manager.mu.TryLock() {
			manager.mu.Unlock()
		} else {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("terminal admission did not reach the manager boundary")
		}
		runtime.Gosched()
	}
}

func TestGatewayReceiptsIdempotentInputWithoutDuplicatePTYWrite(t *testing.T) {
	manager, _ := NewManager([]byte("0123456789abcdef0123456789abcdef"), nil)
	defer manager.Close()
	tabID, _ := ParseTabID("52e782d5-6e80-4944-a42f-a21201900c74")
	runtime := newFakeRuntime()
	if err := manager.Register("owner", "workspace", tabID, runtime, testOutputRedactor(t), false); err != nil {
		t.Fatal(err)
	}
	connection, err := manager.Issue("owner", "device-a", "workspace", tabID, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	gateway, _ := NewGateway(manager, "https://api.example.test")
	server := httptest.NewServer(gateway)
	defer server.Close()
	options := &websocket.DialOptions{
		Subprotocols: []string{Subprotocol},
		HTTPHeader:   http.Header{"Authorization": {"Bearer " + connection.Ticket}},
	}
	socket, _, err := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(server.URL, "http"), options)
	if err != nil {
		t.Fatal(err)
	}
	defer socket.CloseNow()
	writeTestFrame(t, socket, Frame{Kind: KindLeaseRequest, TabID: tabID, Payload: []byte("device-a")})
	_, data, err := socket.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	granted, err := ParseFrame(data)
	if err != nil || granted.Kind != KindLeaseGranted {
		t.Fatalf("expected lease grant, got %#v: %v", granted, err)
	}

	input := Frame{
		Kind: KindInput, Flags: FlagIdempotentInput, Sequence: 0x7f01,
		TabID: tabID, Payload: []byte("codex command\n"),
	}
	for attempt := 0; attempt < 2; attempt++ {
		writeTestFrame(t, socket, input)
		_, data, err = socket.Read(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		receipt, parseErr := ParseFrame(data)
		if parseErr != nil || receipt.Kind != KindAck || receipt.Flags != FlagInputReceipt || receipt.Sequence != input.Sequence || len(receipt.Payload) != 0 {
			t.Fatalf("unexpected input receipt: %#v %v", receipt, parseErr)
		}
	}
	writeTestFrame(t, socket, Frame{
		Kind: KindAck, Flags: FlagInputReceiptConfirmed, Sequence: input.Sequence, TabID: tabID,
	})
	writeTestFrame(t, socket, Frame{Kind: KindPing, TabID: tabID, Payload: []byte("confirmed")})
	_, data, err = socket.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	pong, err := ParseFrame(data)
	if err != nil || pong.Kind != KindPong || string(pong.Payload) != "confirmed" {
		t.Fatalf("receipt confirmation was not processed in-order: %#v %v", pong, err)
	}
	key := inputReceiptKey{deviceID: "device-a", sequence: input.Sequence}
	manager.tabs[tabID].inputMu.Lock()
	_, active := manager.tabs[tabID].inputReceipts[key]
	_, tombstoned := manager.tabs[tabID].confirmedInputKeys[key]
	manager.tabs[tabID].inputMu.Unlock()
	if active || !tombstoned {
		t.Fatalf("receipt confirmation cleanup active=%v tombstoned=%v", active, tombstoned)
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if len(runtime.inputs) != 1 || string(runtime.inputs[0]) != "codex command\n" {
		t.Fatalf("idempotent retry wrote PTY input %#v", runtime.inputs)
	}
}

func TestGatewayRejectsIdempotencyKeyReuseWithDifferentInput(t *testing.T) {
	manager, _ := NewManager([]byte("0123456789abcdef0123456789abcdef"), nil)
	defer manager.Close()
	tabID, _ := NewTabID()
	runtime := newFakeRuntime()
	if err := manager.Register("owner", "workspace", tabID, runtime, testOutputRedactor(t), false); err != nil {
		t.Fatal(err)
	}
	tab := manager.tabs[tabID]
	if _, err := tab.lease.Request("device-a", false, manager.now()); err != nil {
		t.Fatal(err)
	}
	gateway := &Gateway{manager: manager}
	record := ticketRecord{ownerID: "owner", deviceID: "device-a", workspaceID: "workspace", tabID: tabID}
	mutations := newConnectionMutationGate()
	responses := make(chan connectionResponse)
	go func() {
		response := <-responses
		response.written <- nil
	}()
	first := Frame{Kind: KindInput, Flags: FlagIdempotentInput, Sequence: 77, TabID: tabID, Payload: []byte("first\n")}
	if err := gateway.handleFrame(context.Background(), tab, record, mutations, first, responses); err != nil {
		t.Fatal(err)
	}
	second := first
	second.Payload = []byte("different\n")
	if err := gateway.handleFrame(context.Background(), tab, record, mutations, second, responses); err == nil {
		t.Fatal("reused idempotency key with different input was accepted")
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if len(runtime.inputs) != 1 || string(runtime.inputs[0]) != "first\n" {
		t.Fatalf("mismatched retry changed PTY input: %#v", runtime.inputs)
	}
}

func TestGatewayReceiptConfirmationCleansActiveStateAndKeepsBoundedDedupTombstone(t *testing.T) {
	manager, _ := NewManager([]byte("0123456789abcdef0123456789abcdef"), nil)
	defer manager.Close()
	tabID, _ := NewTabID()
	runtime := newFakeRuntime()
	if err := manager.Register("owner", "workspace", tabID, runtime, testOutputRedactor(t), false); err != nil {
		t.Fatal(err)
	}
	tab := manager.tabs[tabID]
	if _, err := tab.lease.Request("device-a", false, manager.now()); err != nil {
		t.Fatal(err)
	}
	gateway := &Gateway{manager: manager}
	recordA := ticketRecord{ownerID: "owner", deviceID: "device-a", workspaceID: "workspace", tabID: tabID}
	recordB := ticketRecord{ownerID: "owner", deviceID: "device-b", workspaceID: "workspace", tabID: tabID}
	mutationsA := newConnectionMutationGate()
	mutationsB := newConnectionMutationGate()
	input := Frame{
		Kind: KindInput, Flags: FlagIdempotentInput, Sequence: 4242,
		TabID: tabID, Payload: []byte("confirmed once\n"),
	}
	writtenResponse := func() chan connectionResponse {
		responses := make(chan connectionResponse)
		go func() {
			response := <-responses
			response.written <- nil
		}()
		return responses
	}
	if err := gateway.handleFrame(context.Background(), tab, recordA, mutationsA, input, writtenResponse()); err != nil {
		t.Fatal(err)
	}
	keyA := inputReceiptKey{deviceID: "device-a", sequence: input.Sequence}
	tab.inputMu.Lock()
	active := tab.inputReceipts[keyA]
	tab.inputMu.Unlock()
	if !active.receiptWritten {
		t.Fatal("input became confirmable before its targeted receipt write completed")
	}

	confirmation := Frame{
		Kind: KindAck, Flags: FlagInputReceiptConfirmed, Sequence: input.Sequence, TabID: tabID,
	}
	if err := gateway.handleFrame(context.Background(), tab, recordB, mutationsB, confirmation, nil); err != nil {
		t.Fatal(err)
	}
	tab.inputMu.Lock()
	_, activeAfterOtherDevice := tab.inputReceipts[keyA]
	tab.inputMu.Unlock()
	if !activeAfterOtherDevice {
		t.Fatal("another device deleted the originating device's receipt record")
	}
	if err := gateway.handleFrame(context.Background(), tab, recordA, mutationsA, confirmation, nil); err != nil {
		t.Fatal(err)
	}
	tab.inputMu.Lock()
	_, stillActive := tab.inputReceipts[keyA]
	_, tombstoned := tab.confirmedInputKeys[keyA]
	count := tab.inputReceiptCounts["device-a"]
	tab.inputMu.Unlock()
	if stillActive || !tombstoned || count != 0 {
		t.Fatalf("confirmation lifecycle active=%v tombstoned=%v count=%d", stillActive, tombstoned, count)
	}

	if err := gateway.handleFrame(context.Background(), tab, recordA, mutationsA, input, writtenResponse()); err != nil {
		t.Fatal(err)
	}
	runtime.mu.Lock()
	inputCount := len(runtime.inputs)
	runtime.mu.Unlock()
	if inputCount != 1 {
		t.Fatalf("confirmed-key retry duplicated PTY input: %d writes", inputCount)
	}
	mismatched := input
	mismatched.Payload = []byte("different after confirmation\n")
	if err := gateway.handleFrame(context.Background(), tab, recordA, mutationsA, mismatched, nil); err == nil {
		t.Fatal("mismatched reuse of a confirmed idempotency key was accepted")
	}
}

func TestGatewayRejectsNewIdempotentInputBeforeWriteWhenReceiptCapacityIsFull(t *testing.T) {
	manager, _ := NewManager([]byte("0123456789abcdef0123456789abcdef"), nil)
	defer manager.Close()
	tabID, _ := NewTabID()
	runtime := newFakeRuntime()
	if err := manager.Register("owner", "workspace", tabID, runtime, testOutputRedactor(t), false); err != nil {
		t.Fatal(err)
	}
	tab := manager.tabs[tabID]
	if _, err := tab.lease.Request("device-a", false, manager.now()); err != nil {
		t.Fatal(err)
	}
	tab.inputMu.Lock()
	for sequence := uint64(1); sequence <= maxInputReceiptsPerTab; sequence++ {
		tab.inputReceipts[inputReceiptKey{deviceID: "older-device", sequence: sequence}] = inputReceiptRecord{
			payloadHash: sha256.Sum256([]byte{byte(sequence)}), receiptWritten: true,
		}
	}
	tab.inputMu.Unlock()

	gateway := &Gateway{manager: manager}
	record := ticketRecord{ownerID: "owner", deviceID: "device-a", workspaceID: "workspace", tabID: tabID}
	responses := make(chan connectionResponse, 1)
	err := gateway.handleFrame(context.Background(), tab, record, newConnectionMutationGate(), Frame{
		Kind: KindInput, Flags: FlagIdempotentInput, Sequence: 99_999,
		TabID: tabID, Payload: []byte("must not write\n"),
	}, responses)
	if err == nil {
		t.Fatal("new idempotent input was accepted after receipt capacity filled")
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if len(runtime.inputs) != 0 {
		t.Fatalf("capacity failure wrote PTY input: %#v", runtime.inputs)
	}
}

func TestConfirmedReceiptsDoNotPermanentlyConsumePerDeviceCapacity(t *testing.T) {
	manager, _ := NewManager([]byte("0123456789abcdef0123456789abcdef"), nil)
	defer manager.Close()
	tabID, _ := NewTabID()
	runtime := newFakeRuntime()
	if err := manager.Register("owner", "workspace", tabID, runtime, testOutputRedactor(t), false); err != nil {
		t.Fatal(err)
	}
	tab := manager.tabs[tabID]
	for sequence := uint64(1); sequence <= maxInputReceiptsPerDevice+1; sequence++ {
		key := inputReceiptKey{deviceID: "device-a", sequence: sequence}
		payload := []byte("x")
		payloadHash := sha256.Sum256(payload)
		wrote, err := tab.writeInput(context.Background(), payload, &key, payloadHash)
		if err != nil || !wrote {
			t.Fatalf("write %d failed after confirmed cleanup: wrote=%v err=%v", sequence, wrote, err)
		}
		if err := tab.markInputReceiptWritten(key, payloadHash); err != nil {
			t.Fatal(err)
		}
		if err := tab.confirmInputReceipt(key); err != nil {
			t.Fatal(err)
		}
	}
	tab.inputMu.Lock()
	active := len(tab.inputReceipts)
	deviceCount := tab.inputReceiptCounts["device-a"]
	tab.inputMu.Unlock()
	if active != 0 || deviceCount != 0 {
		t.Fatalf("confirmed receipts leaked active capacity: active=%d device_count=%d", active, deviceCount)
	}
}

func TestGatewayInputReceiptBackpressuresUntilConnectionWriterAcceptsIt(t *testing.T) {
	manager, _ := NewManager([]byte("0123456789abcdef0123456789abcdef"), nil)
	defer manager.Close()
	tabID, _ := NewTabID()
	runtime := newFakeRuntime()
	if err := manager.Register("owner", "workspace", tabID, runtime, testOutputRedactor(t), false); err != nil {
		t.Fatal(err)
	}
	tab := manager.tabs[tabID]
	if _, err := tab.lease.Request("device-a", false, manager.now()); err != nil {
		t.Fatal(err)
	}
	gateway := &Gateway{manager: manager}
	record := ticketRecord{ownerID: "owner", deviceID: "device-a", workspaceID: "workspace", tabID: tabID}
	responses := make(chan connectionResponse)
	done := make(chan error, 1)
	mutations := newConnectionMutationGate()
	go func() {
		done <- gateway.handleFrame(context.Background(), tab, record, mutations, Frame{
			Kind: KindInput, Flags: FlagIdempotentInput, Sequence: 88,
			TabID: tabID, Payload: []byte("reliable\n"),
		}, responses)
	}()
	waitFor(t, func() bool {
		runtime.mu.Lock()
		defer runtime.mu.Unlock()
		return len(runtime.inputs) == 1
	})
	select {
	case err := <-done:
		t.Fatalf("handler completed before its receipt was accepted: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	response := <-responses
	if response.frame.Kind != KindAck || response.frame.Flags != FlagInputReceipt || response.frame.Sequence != 88 {
		t.Fatalf("unexpected reliable receipt: %#v", response.frame)
	}
	select {
	case err := <-done:
		t.Fatalf("handler completed before the WebSocket write result: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if err := tab.confirmInputReceipt(inputReceiptKey{deviceID: "device-a", sequence: 88}); err == nil {
		t.Fatal("receipt confirmation succeeded before the targeted WebSocket write")
	}
	response.written <- nil
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestGatewayTargetsInputReceiptOnlyToOriginatingDeviceConnection(t *testing.T) {
	manager, _ := NewManager([]byte("0123456789abcdef0123456789abcdef"), nil)
	defer manager.Close()
	tabID, _ := NewTabID()
	runtime := newFakeRuntime()
	if err := manager.Register("owner", "workspace", tabID, runtime, testOutputRedactor(t), false); err != nil {
		t.Fatal(err)
	}
	connectionA, err := manager.Issue("owner", "device-a", "workspace", tabID, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	connectionB, err := manager.Issue("owner", "device-b", "workspace", tabID, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	gateway, _ := NewGateway(manager, "https://api.example.test")
	server := httptest.NewServer(gateway)
	defer server.Close()
	dial := func(ticket string) *websocket.Conn {
		t.Helper()
		options := &websocket.DialOptions{
			Subprotocols: []string{Subprotocol},
			HTTPHeader:   http.Header{"Authorization": {"Bearer " + ticket}},
		}
		socket, _, dialErr := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(server.URL, "http"), options)
		if dialErr != nil {
			t.Fatal(dialErr)
		}
		return socket
	}
	socketA := dial(connectionA.Ticket)
	defer socketA.CloseNow()
	socketB := dial(connectionB.Ticket)
	defer socketB.CloseNow()
	for _, socket := range []*websocket.Conn{socketA, socketB} {
		writeTestFrame(t, socket, Frame{Kind: KindPing, TabID: tabID, Payload: []byte("ready")})
		_, data, readErr := socket.Read(context.Background())
		if readErr != nil {
			t.Fatal(readErr)
		}
		frame, parseErr := ParseFrame(data)
		if parseErr != nil || frame.Kind != KindPong || string(frame.Payload) != "ready" {
			t.Fatalf("connection did not become ready: %#v, %v", frame, parseErr)
		}
	}

	writeTestFrame(t, socketA, Frame{Kind: KindLeaseRequest, TabID: tabID, Payload: []byte("device-a")})
	for _, socket := range []*websocket.Conn{socketA, socketB} {
		_, data, readErr := socket.Read(context.Background())
		if readErr != nil {
			t.Fatal(readErr)
		}
		frame, parseErr := ParseFrame(data)
		if parseErr != nil || frame.Kind != KindLeaseGranted || string(frame.Payload) != "device-a" {
			t.Fatalf("unexpected lease broadcast: %#v, %v", frame, parseErr)
		}
	}

	writeTestFrame(t, socketA, Frame{
		Kind: KindInput, Flags: FlagIdempotentInput, Sequence: 0xabcdef,
		TabID: tabID, Payload: []byte("origin only\n"),
	})
	_, data, err := socketA.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := ParseFrame(data)
	if err != nil || receipt.Kind != KindAck || receipt.Flags != FlagInputReceipt || receipt.Sequence != 0xabcdef {
		t.Fatalf("origin did not receive its receipt: %#v, %v", receipt, err)
	}
	readContext, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, _, err := socketB.Read(readContext); err == nil {
		t.Fatal("non-originating device received another device's input receipt")
	}
}

func TestGatewayReplayGapIsFollowedByCompleteRetainedWindow(t *testing.T) {
	manager, _ := NewManager([]byte("0123456789abcdef0123456789abcdef"), nil)
	defer manager.Close()
	tabID, _ := NewTabID()
	runtime := newFakeRuntime()
	if err := manager.Register("owner", "workspace", tabID, runtime, testOutputRedactor(t), false); err != nil {
		t.Fatal(err)
	}
	ring, err := NewRing(tabID, 2, 1024)
	if err != nil {
		t.Fatal(err)
	}
	tab := manager.tabs[tabID]
	tab.mu.Lock()
	tab.ring = ring
	tab.mu.Unlock()
	for _, output := range []string{"one", "two", "three"} {
		tab.appendOutput([]byte(output))
	}

	connection, err := manager.Issue("owner", "device-a", "workspace", tabID, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	gateway, _ := NewGateway(manager, "https://api.example.test")
	server := httptest.NewServer(gateway)
	defer server.Close()
	options := &websocket.DialOptions{
		Subprotocols: []string{Subprotocol},
		HTTPHeader:   http.Header{"Authorization": {"Bearer " + connection.Ticket}},
	}
	socket, _, err := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(server.URL, "http"), options)
	if err != nil {
		t.Fatal(err)
	}
	defer socket.CloseNow()

	wantKinds := []Kind{KindReplayGap, KindOutput, KindOutput}
	wantSequences := []uint64{2, 2, 3}
	wantPayloads := []string{"scrollback_truncated", "two", "three"}
	for index := range wantKinds {
		_, data, readErr := socket.Read(context.Background())
		if readErr != nil {
			t.Fatal(readErr)
		}
		frame, parseErr := ParseFrame(data)
		if parseErr != nil || frame.Kind != wantKinds[index] || frame.Sequence != wantSequences[index] || string(frame.Payload) != wantPayloads[index] {
			t.Fatalf("replay frame %d = %#v, %v", index, frame, parseErr)
		}
	}
}

func TestReconnectTokenBindingAndOSC52Filtering(t *testing.T) {
	manager, _ := NewManager([]byte("0123456789abcdef0123456789abcdef"), nil)
	defer manager.Close()
	tabID, _ := NewTabID()
	runtime := newFakeRuntime()
	_ = manager.Register("owner", "workspace", tabID, runtime, testOutputRedactor(t), false)
	first, _ := manager.Issue("owner", "device-a", "workspace", tabID, 0, "")
	if _, err := manager.Issue("owner", "device-b", "workspace", tabID, 0, first.ReconnectToken); err == nil {
		t.Fatal("reconnect token crossed device boundary")
	}
	if _, err := manager.Issue("owner", "device-a", "workspace", tabID, 0, first.ReconnectToken); err != nil {
		t.Fatal(err)
	}
	runtime.output <- []byte("ok\x1b]52;c;c2VjcmV0\x07done")
	waitFor(t, func() bool { return manager.tabs[tabID].ring.After(0).LatestSequence == 1 })
	frames := manager.tabs[tabID].ring.After(0).Frames
	if len(frames) != 1 || string(frames[0].Payload) != "okdone" {
		t.Fatalf("remote clipboard was not filtered: %#v", frames)
	}
}

func TestUnregisterClosesRuntimeRevokesCredentialsAndIsIdempotent(t *testing.T) {
	manager, _ := NewManager([]byte("0123456789abcdef0123456789abcdef"), nil)
	defer manager.Close()
	tabID, _ := NewTabID()
	runtime := newFakeRuntime()
	if err := manager.Register("owner", "workspace", tabID, runtime, testOutputRedactor(t), false); err != nil {
		t.Fatal(err)
	}
	connection, err := manager.Issue("owner", "device", "workspace", tabID, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(manager.tickets) != 1 || len(manager.reconnects) != 1 {
		t.Fatalf("terminal credentials were not issued: tickets=%d reconnects=%d", len(manager.tickets), len(manager.reconnects))
	}
	if err := manager.Unregister(tabID, "owner_closed"); err != nil {
		t.Fatal(err)
	}
	runtime.mu.Lock()
	closed := runtime.closed
	runtime.mu.Unlock()
	if !closed || len(manager.tickets) != 0 || len(manager.reconnects) != 0 {
		t.Fatalf("unregister did not close/revoke: closed=%v tickets=%d reconnects=%d", closed, len(manager.tickets), len(manager.reconnects))
	}
	if _, err := manager.admit(connection.Ticket); err == nil {
		t.Fatal("ticket minted before close remained redeemable")
	}
	if err := manager.Unregister(tabID, "owner_closed"); err != nil {
		t.Fatalf("idempotent unregister failed: %v", err)
	}
}

type rawEventProvider struct{}

func (*rawEventProvider) Structured() bool { return false }
func (*rawEventProvider) Observe(output []byte) []codex.Event {
	if strings.Contains(string(output), "raw-secret-marker") {
		return []codex.Event{{Kind: codex.EventNeedsAttention}}
	}
	return nil
}

type eventHandler struct{ events chan CodexEventContext }

func (h eventHandler) HandleCodexEvent(value CodexEventContext, _ codex.Event) bool {
	h.events <- value
	return true
}

func TestManagerObservesOnlyCodexTabsBeforeOutputFiltering(t *testing.T) {
	manager, _ := NewManager([]byte("0123456789abcdef0123456789abcdef"), nil)
	defer manager.Close()
	events := make(chan CodexEventContext, 2)
	if err := manager.ConfigureCodexEvents(func() codex.EventProvider { return &rawEventProvider{} }, eventHandler{events: events}); err != nil {
		t.Fatal(err)
	}
	codexTab, _ := NewTabID()
	codexRuntime := newFakeRuntime()
	if err := manager.Register("owner", "workspace", codexTab, codexRuntime, testOutputRedactor(t), true); err != nil {
		t.Fatal(err)
	}
	codexRuntime.output <- []byte("before\x1b]52;c;raw-secret-marker\x07after")
	select {
	case event := <-events:
		if event.OwnerID != "owner" || event.WorkspaceID != "workspace" || event.TabID != codexTab {
			t.Fatalf("unexpected event mapping: %#v", event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("raw output was not observed")
	}
	waitFor(t, func() bool { return manager.tabs[codexTab].ring.After(0).LatestSequence == 1 })
	frames := manager.tabs[codexTab].ring.After(0).Frames
	if len(frames) != 1 || string(frames[0].Payload) != "beforeafter" {
		t.Fatalf("OSC 52 reached sanitized terminal output: %#v", frames)
	}

	shellTab, _ := NewTabID()
	shellRuntime := newFakeRuntime()
	if err := manager.Register("owner", "workspace", shellTab, shellRuntime, testOutputRedactor(t), false); err != nil {
		t.Fatal(err)
	}
	shellRuntime.output <- []byte("raw-secret-marker")
	select {
	case event := <-events:
		t.Fatalf("non-Codex tab emitted an event: %#v", event)
	case <-time.After(25 * time.Millisecond):
	}
}

func TestManagerRedactsGrantedSecretFormsAcrossPTYChunksBeforeReplay(t *testing.T) {
	manager, _ := NewManager([]byte("0123456789abcdef0123456789abcdef"), nil)
	defer manager.Close()
	tabID, _ := NewTabID()
	runtime := newFakeRuntime()
	secret := []byte("granted-runtime-secret-123")
	if err := manager.Register("owner", "workspace", tabID, runtime, testOutputRedactor(t, secret), false); err != nil {
		t.Fatal(err)
	}

	runtime.output <- []byte("plain granted-runtime-")
	runtime.output <- []byte("secret-123 encoded Z3JhbnRlZC1ydW50aW1lLXNlY3JldC0")
	runtime.output <- []byte("xMjM= done")
	waitFor(t, func() bool {
		frames := manager.tabs[tabID].ring.After(0).Frames
		if len(frames) == 0 {
			return false
		}
		var joined []byte
		for _, frame := range frames {
			joined = append(joined, frame.Payload...)
		}
		return strings.Contains(string(joined), "done")
	})
	frames := manager.tabs[tabID].ring.After(0).Frames
	var output []byte
	for _, frame := range frames {
		output = append(output, frame.Payload...)
	}
	if strings.Contains(string(output), string(secret)) || strings.Contains(string(output), "Z3JhbnRlZC1ydW50aW1lLXNlY3JldC0xMjM=") {
		t.Fatalf("granted value reached terminal replay: %q", output)
	}
	if got := string(output); got != "plain [REDACTED] encoded [REDACTED] done" {
		t.Fatalf("unexpected redacted output: %q", got)
	}
}

func TestRegisterRequiresOutputRedactor(t *testing.T) {
	manager, _ := NewManager([]byte("0123456789abcdef0123456789abcdef"), nil)
	defer manager.Close()
	tabID, _ := NewTabID()
	if err := manager.Register("owner", "workspace", tabID, newFakeRuntime(), nil, false); err == nil {
		t.Fatal("terminal registered without the mandatory pre-replay redactor")
	}
}

func testOutputRedactor(t *testing.T, secrets ...[]byte) OutputRedactor {
	t.Helper()
	redactor, err := NewOutputRedactor(secrets...)
	if err != nil {
		t.Fatal(err)
	}
	return redactor
}

func writeTestFrame(t *testing.T, socket *websocket.Conn, frame Frame) {
	t.Helper()
	encoded, err := frame.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err := socket.Write(context.Background(), websocket.MessageBinary, encoded); err != nil {
		t.Fatal(err)
	}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not met")
}
