package terminal

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/codex"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/redact"
	"github.com/coder/websocket"
)

const (
	Subprotocol                   = "codex-mobile-terminal-v1"
	defaultTicketTTL              = 45 * time.Second
	defaultReconnectTTL           = 30 * 24 * time.Hour
	maxRegisteredTabsGlobal       = 64
	maxRegisteredTabsPerOwner     = 48
	maxRegisteredTabsPerWorkspace = 16
	terminalReplayMaxFrames       = 4096
	terminalReplayMaxBytes        = 4 << 20
	maxUnusedTicketsGlobal        = 4096
	maxUnusedTicketsPerOwner      = 1024
	maxUnusedTicketsPerDevice     = 64
	maxUnusedTicketsPerTab        = 64
	maxReconnectsGlobal           = 8192
	maxReconnectsPerOwner         = 2048
	maxReconnectsPerDevice        = 128
	maxReconnectsPerTab           = 128
	maxSubscribersGlobal          = 128
	maxSubscribersPerOwner        = 64
	maxSubscribersPerDevice       = 8
	maxSubscribersPerTab          = 8
	terminalSubscriberQueueFrames = 16
	maxInputBytes                 = 64 << 10
	RuntimeOutputChunkBytes       = 64 << 10
	RuntimeOutputQueueChunks      = 8
	maxInputReceiptsPerDevice     = 2048
	maxInputReceiptsPerTab        = 4096
	maxConfirmedInputKeys         = 8192
	frameWriteTimeout             = 15 * time.Second
	initialReplayWriteTimeout     = 30 * time.Second
)

var (
	ErrTerminalCapacity      = errors.New("terminal connection capacity reached")
	errTerminalAccessRevoked = errors.New("terminal access revoked")
)

type Runtime interface {
	Output() <-chan []byte
	WriteInput(context.Context, []byte) error
	Resize(context.Context, Size) error
	Close() error
}

// OutputRedactor is the mandatory boundary between an authoritative PTY and
// the replay ring delivered to clients. Implementations must handle patterns
// split across Process calls and fail closed after Close.
type OutputRedactor interface {
	Process([]byte) []byte
	Flush() []byte
	Close()
}

func NewOutputRedactor(secrets ...[]byte) (OutputRedactor, error) {
	return redact.NewStream(secrets...)
}

type AuditEvent struct {
	Kind, OwnerID, WorkspaceID, TabID, DeviceID, DisplacedDeviceID string
}

type ActivityEvent struct {
	OwnerID     string
	WorkspaceID string
	Kind        string
	At          time.Time
}

// CodexEventContext is trusted terminal registration metadata. Event handlers
// must never derive these identifiers from terminal output.
type CodexEventContext struct {
	OwnerID     string
	WorkspaceID string
	TabID       TabID
}

// CodexEventHandler receives generic events parsed from raw Codex PTY bytes.
// Implementations must return quickly; the terminal pump cannot wait on a
// database or network provider.
type CodexEventHandler interface {
	HandleCodexEvent(CodexEventContext, codex.Event) bool
}

type Connection struct {
	Ticket              string
	ReconnectToken      string
	LeaseHolderDeviceID string
	ProtocolVersion     uint8
	MaximumFrameBytes   int
}

type ticketRecord struct {
	ownerID, deviceID, workspaceID string
	tabID                          TabID
	afterSequence                  uint64
	expiresAt                      time.Time
}

type reconnectRecord struct {
	ownerID, deviceID, workspaceID string
	tabID                          TabID
	expiresAt                      time.Time
}

type inputReceiptKey struct {
	deviceID string
	sequence uint64
}

type inputReceiptRecord struct {
	payloadHash    [32]byte
	receiptWritten bool
}

type connectionResponse struct {
	frame   Frame
	written chan error
}

type connectionSubscriber struct {
	deviceID   string
	frames     chan Frame
	revoked    chan struct{}
	mutations  *connectionMutationGate
	deliveries *connectionDeliveryGate
	closed     bool
}

type admittedConnection struct {
	record       ticketRecord
	tab          *tabState
	subscriberID uint64
	outbound     <-chan Frame
	revoked      <-chan struct{}
	mutations    *connectionMutationGate
	deliveries   *connectionDeliveryGate
	replay       Replay
}

type tabState struct {
	ownerID, workspaceID string
	id                   TabID
	runtime              Runtime
	events               codex.EventProvider
	ring                 *Ring
	lease                *LeaseManager
	filter               OutputFilter
	redactor             OutputRedactor
	inputMu              sync.Mutex
	inputReceipts        map[inputReceiptKey]inputReceiptRecord
	inputReceiptCounts   map[string]int
	confirmedInputKeys   map[inputReceiptKey][32]byte
	confirmedInputOrder  []inputReceiptKey
	mu                   sync.Mutex
	subscribers          map[uint64]*connectionSubscriber
	nextSubscriber       uint64
	closed               bool
	closeDone            chan struct{}
	runtimeCloseOnce     sync.Once
	runtimeCloseErr      error
}

type ownerDevice struct {
	ownerID  string
	deviceID string
}

type Manager struct {
	mu                  sync.RWMutex
	tabs                map[TabID]*tabState
	tickets             map[[32]byte]ticketRecord
	reconnects          map[[32]byte]reconnectRecord
	pepper              []byte
	random              io.Reader
	now                 func() time.Time
	ticketTTL           time.Duration
	reconnectTTL        time.Duration
	audit               func(AuditEvent)
	eventFactory        func() codex.EventProvider
	eventHandler        CodexEventHandler
	activity            func(ActivityEvent)
	subscribers         int
	subscribersByOwner  map[string]int
	subscribersByDevice map[ownerDevice]int
	subscribersByTab    map[TabID]int
	closed              bool
	closeDone           chan struct{}
	closeErr            error
	ctx                 context.Context
	cancel              context.CancelFunc
}

// ConfigureActivityObserver installs a non-blocking observer before terminal
// registration. The callback is invoked for real input, output, and attention
// events, never for pings or passive reconnects.
func (m *Manager) ConfigureActivityObserver(observer func(ActivityEvent)) error {
	if observer == nil {
		return errors.New("terminal activity observer is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.tabs) != 0 || m.activity != nil {
		return errors.New("terminal activity must be configured once before terminal registration")
	}
	m.activity = observer
	return nil
}

func NewManager(pepper []byte, audit func(AuditEvent)) (*Manager, error) {
	if len(pepper) < 32 {
		return nil, errors.New("terminal ticket pepper must be at least 32 bytes")
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{
		tabs: make(map[TabID]*tabState), tickets: make(map[[32]byte]ticketRecord), reconnects: make(map[[32]byte]reconnectRecord),
		subscribersByOwner: make(map[string]int), subscribersByDevice: make(map[ownerDevice]int), subscribersByTab: make(map[TabID]int),
		closeDone: make(chan struct{}),
		pepper:    append([]byte(nil), pepper...), random: rand.Reader, now: func() time.Time { return time.Now().UTC() },
		ticketTTL: defaultTicketTTL, reconnectTTL: defaultReconnectTTL, audit: audit, ctx: ctx, cancel: cancel,
	}, nil
}

func (m *Manager) Close() error {
	m.cancel()
	m.mu.Lock()
	if m.closed {
		done := m.closeDone
		m.mu.Unlock()
		<-done
		m.mu.RLock()
		err := m.closeErr
		m.mu.RUnlock()
		return err
	}
	m.closed = true
	tabs := make([]*tabState, 0, len(m.tabs))
	for _, tab := range m.tabs {
		tabs = append(tabs, tab)
		tab.beginClose("manager_shutdown")
	}
	for key := range m.tickets {
		delete(m.tickets, key)
	}
	for key := range m.reconnects {
		delete(m.reconnects, key)
	}
	m.mu.Unlock()

	// Never drain a frame while holding the manager lock: an admitted input
	// reports activity through that lock before it can leave its mutation gate.
	var joined error
	for _, tab := range tabs {
		tab.waitClosed()
		joined = errors.Join(joined, tab.closeRuntime())
	}
	m.mu.Lock()
	for _, tab := range tabs {
		if m.tabs[tab.id] == tab {
			delete(m.tabs, tab.id)
		}
	}
	m.closeErr = joined
	close(m.closeDone)
	m.mu.Unlock()
	return joined
}

// ConfigureCodexEvents installs the process-wide event adapter before any
// terminal is registered. Each Codex tab receives its own stateful provider so
// split OSC sequences can never cross tab boundaries.
func (m *Manager) ConfigureCodexEvents(factory func() codex.EventProvider, handler CodexEventHandler) error {
	if factory == nil || handler == nil {
		return errors.New("Codex event provider and handler are required")
	}
	provider := factory()
	if provider == nil {
		return errors.New("Codex event provider factory returned nil")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.tabs) != 0 || m.eventFactory != nil || m.eventHandler != nil {
		return errors.New("Codex events must be configured once before terminal registration")
	}
	m.eventFactory = factory
	m.eventHandler = handler
	return nil
}

func (m *Manager) Register(ownerID, workspaceID string, tabID TabID, runtime Runtime, redactor OutputRedactor, observeCodexEvents bool) error {
	if ownerID == "" || workspaceID == "" || tabID.IsZero() || runtime == nil || runtime.Output() == nil || redactor == nil {
		return errors.New("terminal tab identity, runtime, and output redactor are required")
	}
	ring, err := NewRing(tabID, terminalReplayMaxFrames, terminalReplayMaxBytes)
	if err != nil {
		return err
	}
	lease, err := NewLeaseManager(45 * time.Second)
	if err != nil {
		return err
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return errors.New("terminal manager is closed")
	}
	var provider codex.EventProvider
	if observeCodexEvents && m.eventFactory != nil {
		provider = m.eventFactory()
		if provider == nil {
			m.mu.Unlock()
			return errors.New("Codex event provider factory returned nil")
		}
	}
	tab := &tabState{
		ownerID: ownerID, workspaceID: workspaceID, id: tabID,
		runtime: runtime, events: provider, ring: ring, lease: lease, redactor: redactor,
		inputReceipts:      make(map[inputReceiptKey]inputReceiptRecord),
		inputReceiptCounts: make(map[string]int), confirmedInputKeys: make(map[inputReceiptKey][32]byte),
		subscribers: make(map[uint64]*connectionSubscriber), closeDone: make(chan struct{}),
	}
	if _, exists := m.tabs[tabID]; exists {
		m.mu.Unlock()
		return errors.New("terminal tab already exists")
	}
	if err := m.requireTabCapacityLocked(ownerID, workspaceID); err != nil {
		m.mu.Unlock()
		return err
	}
	m.tabs[tabID] = tab
	m.mu.Unlock()
	go m.pump(tab)
	return nil
}

func (m *Manager) Unregister(tabID TabID, reason string) error {
	m.mu.Lock()
	tab, ok := m.tabs[tabID]
	if ok {
		tab.beginClose(boundedReason(reason))
	}
	for key, record := range m.tickets {
		if record.tabID == tabID {
			delete(m.tickets, key)
		}
	}
	for key, record := range m.reconnects {
		if record.tabID == tabID {
			delete(m.reconnects, key)
		}
	}
	m.mu.Unlock()
	if !ok {
		return nil
	}
	tab.waitClosed()
	err := tab.closeRuntime()
	m.mu.Lock()
	if m.tabs[tabID] == tab {
		delete(m.tabs, tabID)
	}
	m.mu.Unlock()
	return err
}

func (m *Manager) Issue(ownerID, deviceID, workspaceID string, tabID TabID, afterSequence uint64, reconnectToken string) (Connection, error) {
	if ownerID == "" || deviceID == "" || workspaceID == "" || tabID.IsZero() {
		return Connection{}, errors.New("terminal connection identity is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return Connection{}, errors.New("terminal manager is closed")
	}
	tab, ok := m.tabs[tabID]
	if !ok || tab.ownerID != ownerID || tab.workspaceID != workspaceID {
		return Connection{}, errors.New("terminal tab not found")
	}
	if tab.isClosed() {
		return Connection{}, errors.New("terminal tab not found")
	}
	now := m.now()
	m.cleanupLocked(now)
	var consumedReconnect *[32]byte
	if reconnectToken != "" {
		key := m.hash("reconnect", reconnectToken)
		record, exists := m.reconnects[key]
		if !exists || record.ownerID != ownerID || record.deviceID != deviceID || record.workspaceID != workspaceID || record.tabID != tabID || !now.Before(record.expiresAt) {
			return Connection{}, errors.New("invalid terminal reconnect token")
		}
		consumedReconnect = &key
	}
	if err := m.requireCredentialCapacityLocked(ownerID, deviceID, tabID, consumedReconnect); err != nil {
		return Connection{}, err
	}
	ticket, err := randomCredential(m.random, "cm_terminal_ticket_")
	if err != nil {
		return Connection{}, err
	}
	reconnect, err := randomCredential(m.random, "cm_terminal_reconnect_")
	if err != nil {
		return Connection{}, err
	}
	if consumedReconnect != nil {
		delete(m.reconnects, *consumedReconnect)
	}
	m.tickets[m.hash("ticket", ticket)] = ticketRecord{ownerID: ownerID, deviceID: deviceID, workspaceID: workspaceID, tabID: tabID, afterSequence: afterSequence, expiresAt: now.Add(m.ticketTTL)}
	m.reconnects[m.hash("reconnect", reconnect)] = reconnectRecord{ownerID: ownerID, deviceID: deviceID, workspaceID: workspaceID, tabID: tabID, expiresAt: now.Add(m.reconnectTTL)}
	holder := tab.lease.Holder(now)
	return Connection{Ticket: ticket, ReconnectToken: reconnect, LeaseHolderDeviceID: holder.DeviceID, ProtocolVersion: Version, MaximumFrameBytes: MaxPayload}, nil
}

// RevokeDevice invalidates every unused ticket and reconnect token for a
// device and disconnects its active WebSockets without stopping shared PTYs.
// Persistent session revocation must call this after committing its durable
// credential mutation so a redeemed ticket cannot outlive sign-out.
func (m *Manager) RevokeDevice(ownerID, deviceID string) int {
	if ownerID == "" || deviceID == "" {
		return 0
	}
	m.mu.Lock()
	for key, record := range m.tickets {
		if record.ownerID == ownerID && record.deviceID == deviceID {
			delete(m.tickets, key)
		}
	}
	for key, record := range m.reconnects {
		if record.ownerID == ownerID && record.deviceID == deviceID {
			delete(m.reconnects, key)
		}
	}
	type revokedTab struct {
		tab    *tabState
		drains []<-chan struct{}
	}
	revokedTabs := make([]revokedTab, 0, len(m.tabs))
	disconnected := 0
	for _, tab := range m.tabs {
		if tab.ownerID == ownerID {
			count, drains := tab.revokeDevice(deviceID)
			disconnected += count
			revokedTabs = append(revokedTabs, revokedTab{tab: tab, drains: drains})
		}
	}
	m.mu.Unlock()

	// Gate marking is linearized with ticket admission under m.mu, but draining
	// happens after both manager and tab locks are released. Active frames may
	// need those locks to finish their broadcast/activity callbacks.
	for _, revoked := range revokedTabs {
		waitForConnectionDrains(revoked.drains)
		revoked.tab.lease.Release(deviceID)
	}
	return disconnected
}

// admit consumes a one-use ticket and installs its subscriber as one atomic
// operation with respect to device revocation. RevokeDevice uses the same
// manager lock before sweeping subscribers, so it can neither miss a redeemed
// ticket nor race ahead of a subscriber that has not yet been registered.
func (m *Manager) admit(ticket string) (admittedConnection, error) {
	if !strings.HasPrefix(ticket, "cm_terminal_ticket_") || len(ticket) > 256 {
		return admittedConnection{}, errors.New("invalid terminal ticket")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return admittedConnection{}, errors.New("terminal manager is closed")
	}
	key := m.hash("ticket", ticket)
	record, ok := m.tickets[key]
	delete(m.tickets, key)
	if !ok || !m.now().Before(record.expiresAt) {
		return admittedConnection{}, errors.New("invalid terminal ticket")
	}
	tab, ok := m.tabs[record.tabID]
	if !ok || tab.ownerID != record.ownerID || tab.workspaceID != record.workspaceID {
		return admittedConnection{}, errors.New("terminal tab is unavailable")
	}
	if err := m.reserveSubscriberLocked(record); err != nil {
		return admittedConnection{}, err
	}
	subscriberID, outbound, revoked, mutations, deliveries, replay, err := tab.subscribe(record.afterSequence, record.deviceID)
	if err != nil {
		m.releaseSubscriberLocked(record)
		return admittedConnection{}, err
	}
	return admittedConnection{
		record: record, tab: tab, subscriberID: subscriberID,
		outbound: outbound, revoked: revoked, mutations: mutations, replay: replay,
		deliveries: deliveries,
	}, nil
}

func (m *Manager) Notify(tabID TabID, kind string) {
	if kind != "approval" && kind != "question" && kind != "completion" && kind != "failure" {
		kind = "attention"
	}
	m.mu.RLock()
	tab := m.tabs[tabID]
	m.mu.RUnlock()
	if tab != nil {
		tab.broadcast(Frame{Kind: KindAttention, TabID: tabID, Payload: []byte(kind)})
		m.observeActivity(tab, "attention", m.now())
	}
}

func (m *Manager) observeActivity(tab *tabState, kind string, at time.Time) {
	m.mu.RLock()
	observer := m.activity
	m.mu.RUnlock()
	if observer != nil {
		observer(ActivityEvent{OwnerID: tab.ownerID, WorkspaceID: tab.workspaceID, Kind: kind, At: at})
	}
}

func (m *Manager) pump(tab *tabState) {
	for {
		select {
		case <-m.ctx.Done():
			return
		case output, ok := <-tab.runtime.Output():
			if !ok {
				m.appendRedactedOutput(tab, tab.redactor.Flush())
				tab.close("runtime_closed")
				return
			}
			if len(output) != 0 {
				m.observeActivity(tab, "output", m.now())
			}
			// Observe the original PTY chunk before the output filter consumes OSC
			// sequences. Only tabs registered as Codex terminals have a provider.
			if tab.events != nil {
				for _, event := range tab.events.Observe(output) {
					m.mu.RLock()
					handler := m.eventHandler
					m.mu.RUnlock()
					if handler != nil {
						handler.HandleCodexEvent(CodexEventContext{OwnerID: tab.ownerID, WorkspaceID: tab.workspaceID, TabID: tab.id}, event)
					}
				}
			}
			filtered := tab.filter.Process(output)
			m.appendRedactedOutput(tab, tab.redactor.Process(filtered))
		}
	}
}

func (m *Manager) appendRedactedOutput(tab *tabState, output []byte) {
	defer clear(output)
	for len(output) > 0 {
		n := min(len(output), RuntimeOutputChunkBytes)
		tab.appendOutput(output[:n])
		output = output[n:]
	}
}

func (m *Manager) hash(domain, token string) [32]byte {
	h := hmac.New(sha256.New, m.pepper)
	h.Write([]byte("codex-mobile:terminal:v1:" + domain + ":"))
	h.Write([]byte(token))
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func (m *Manager) cleanupLocked(now time.Time) {
	for key, record := range m.tickets {
		if !now.Before(record.expiresAt) {
			delete(m.tickets, key)
		}
	}
	for key, record := range m.reconnects {
		if !now.Before(record.expiresAt) {
			delete(m.reconnects, key)
		}
	}
}

func (t *tabState) appendOutput(payload []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	frame, err := t.ring.Append(payload)
	if err == nil {
		t.broadcastLocked(frame)
	}
}

func (t *tabState) broadcast(frame Frame) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.closed {
		t.broadcastLocked(frame)
	}
}

func (t *tabState) broadcastLocked(frame Frame) {
	for _, subscriber := range t.subscribers {
		if subscriber.closed {
			continue
		}
		select {
		case subscriber.frames <- frame:
		default:
			closeSubscriber(subscriber)
		}
	}
}

func (t *tabState) subscribe(after uint64, deviceID string) (uint64, <-chan Frame, <-chan struct{}, *connectionMutationGate, *connectionDeliveryGate, Replay, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || deviceID == "" {
		return 0, nil, nil, nil, nil, Replay{}, errors.New("terminal tab closed")
	}
	if len(t.subscribers) >= maxSubscribersPerTab {
		return 0, nil, nil, nil, nil, Replay{}, ErrTerminalCapacity
	}
	t.nextSubscriber++
	id := t.nextSubscriber
	channel := make(chan Frame, terminalSubscriberQueueFrames)
	revoked := make(chan struct{})
	mutations := newConnectionMutationGate()
	deliveries := newConnectionDeliveryGate()
	replay := t.ring.After(after)
	t.subscribers[id] = &connectionSubscriber{deviceID: deviceID, frames: channel, revoked: revoked, mutations: mutations, deliveries: deliveries}
	return id, channel, revoked, mutations, deliveries, replay, nil
}

func (t *tabState) unsubscribe(id uint64) bool {
	t.mu.Lock()
	subscriber, ok := t.subscribers[id]
	var drains []<-chan struct{}
	if ok {
		delete(t.subscribers, id)
		drains = append(drains, subscriber.mutations.revoke(), subscriber.deliveries.revoke())
		closeSubscriber(subscriber)
	}
	t.mu.Unlock()
	if !ok {
		return false
	}
	waitForConnectionDrains(drains)
	return true
}

func (t *tabState) revokeDevice(deviceID string) (int, []<-chan struct{}) {
	t.mu.Lock()
	defer t.mu.Unlock()
	disconnected := 0
	var drains []<-chan struct{}
	for _, subscriber := range t.subscribers {
		if subscriber.deviceID == deviceID {
			// Both revocation marks occur while the subscriber lock is held.
			// RevokeDevice drains them only after releasing manager/tab locks.
			drains = append(drains, subscriber.mutations.revoke(), subscriber.deliveries.revoke())
			if closeSubscriber(subscriber) {
				disconnected++
			}
		}
	}
	return disconnected, drains
}

func (t *tabState) beginClose(reason string) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	frame := Frame{Kind: KindTabClosed, TabID: t.id, Payload: []byte(reason)}
	t.broadcastLocked(frame)
	drains := make([]<-chan struct{}, 0, len(t.subscribers))
	for _, subscriber := range t.subscribers {
		drains = append(drains, subscriber.mutations.revoke(), subscriber.deliveries.revoke())
		closeSubscriber(subscriber)
	}
	t.filter.Reset()
	t.redactor.Close()
	done := t.closeDone
	t.mu.Unlock()

	go func() {
		waitForConnectionDrains(drains)
		close(done)
	}()
}

func (t *tabState) waitClosed() {
	<-t.closeDone
}

func (t *tabState) close(reason string) {
	t.beginClose(reason)
	t.waitClosed()
}

func (t *tabState) closeRuntime() error {
	t.runtimeCloseOnce.Do(func() {
		t.runtimeCloseErr = t.runtime.Close()
	})
	return t.runtimeCloseErr
}

func (t *tabState) isClosed() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closed
}

func closeSubscriber(subscriber *connectionSubscriber) bool {
	if subscriber.closed {
		return false
	}
	subscriber.closed = true
	// Queue overflow and shutdown use this helper too. Mark both gates before
	// publishing channel closure so neither reader nor writer can start new
	// privileged work after observing the close.
	_ = subscriber.mutations.revoke()
	_ = subscriber.deliveries.revoke()
	close(subscriber.revoked)
	close(subscriber.frames)
	return true
}

func (t *tabState) inputWasApplied(key inputReceiptKey, payloadHash [32]byte) (bool, error) {
	t.inputMu.Lock()
	defer t.inputMu.Unlock()
	if record, ok := t.inputReceipts[key]; ok {
		if !hmac.Equal(record.payloadHash[:], payloadHash[:]) {
			return false, errors.New("terminal input idempotency key was reused with different bytes")
		}
		return true, nil
	}
	if confirmedHash, ok := t.confirmedInputKeys[key]; ok {
		if !hmac.Equal(confirmedHash[:], payloadHash[:]) {
			return false, errors.New("confirmed terminal input idempotency key was reused with different bytes")
		}
		return true, nil
	}
	return false, nil
}

func (t *tabState) writeInput(ctx context.Context, payload []byte, key *inputReceiptKey, payloadHash [32]byte) (bool, error) {
	// Serialize PTY writes so two connections using the same idempotency key
	// cannot both pass a check-before-write race.
	t.inputMu.Lock()
	defer t.inputMu.Unlock()
	if key != nil {
		if record, ok := t.inputReceipts[*key]; ok {
			if !hmac.Equal(record.payloadHash[:], payloadHash[:]) {
				return false, errors.New("terminal input idempotency key was reused with different bytes")
			}
			return false, nil
		}
		if confirmedHash, ok := t.confirmedInputKeys[*key]; ok {
			if !hmac.Equal(confirmedHash[:], payloadHash[:]) {
				return false, errors.New("confirmed terminal input idempotency key was reused with different bytes")
			}
			return false, nil
		}
		if len(t.inputReceipts) >= maxInputReceiptsPerTab || t.inputReceiptCounts[key.deviceID] >= maxInputReceiptsPerDevice {
			// Never evict an ambiguous applied-input record: doing so could turn a
			// late retry into a duplicate PTY write. Reject before writing instead.
			return false, errors.New("terminal input receipt capacity reached")
		}
	}
	if err := t.runtime.WriteInput(ctx, payload); err != nil {
		return false, err
	}
	if key == nil {
		return true, nil
	}
	t.inputReceipts[*key] = inputReceiptRecord{payloadHash: payloadHash}
	t.inputReceiptCounts[key.deviceID]++
	return true, nil
}

func (t *tabState) markInputReceiptWritten(key inputReceiptKey, payloadHash [32]byte) error {
	t.inputMu.Lock()
	defer t.inputMu.Unlock()
	if record, ok := t.inputReceipts[key]; ok {
		if !hmac.Equal(record.payloadHash[:], payloadHash[:]) {
			return errors.New("terminal input receipt digest changed before delivery")
		}
		record.receiptWritten = true
		t.inputReceipts[key] = record
		return nil
	}
	if confirmedHash, ok := t.confirmedInputKeys[key]; ok && hmac.Equal(confirmedHash[:], payloadHash[:]) {
		// Another connection for the same device may have already delivered and
		// confirmed this key while this targeted receipt was in flight.
		return nil
	}
	return errors.New("terminal input receipt record disappeared before delivery")
}

func (t *tabState) confirmInputReceipt(key inputReceiptKey) error {
	t.inputMu.Lock()
	defer t.inputMu.Unlock()
	if record, ok := t.inputReceipts[key]; ok {
		if !record.receiptWritten {
			return errors.New("terminal input receipt was confirmed before delivery")
		}
		delete(t.inputReceipts, key)
		t.inputReceiptCounts[key.deviceID]--
		if t.inputReceiptCounts[key.deviceID] == 0 {
			delete(t.inputReceiptCounts, key.deviceID)
		}
		t.rememberConfirmedInputLocked(key, record.payloadHash)
		return nil
	}
	// Confirmation is idempotent. A matching tombstone means cleanup already
	// happened; an unknown key has no state it could maliciously delete.
	return nil
}

func (t *tabState) rememberConfirmedInputLocked(key inputReceiptKey, payloadHash [32]byte) {
	if _, exists := t.confirmedInputKeys[key]; exists {
		return
	}
	if len(t.confirmedInputOrder) == maxConfirmedInputKeys {
		oldest := t.confirmedInputOrder[0]
		delete(t.confirmedInputKeys, oldest)
		copy(t.confirmedInputOrder, t.confirmedInputOrder[1:])
		t.confirmedInputOrder[len(t.confirmedInputOrder)-1] = inputReceiptKey{}
		t.confirmedInputOrder = t.confirmedInputOrder[:len(t.confirmedInputOrder)-1]
	}
	t.confirmedInputKeys[key] = payloadHash
	t.confirmedInputOrder = append(t.confirmedInputOrder, key)
}

type Gateway struct {
	manager       *Manager
	allowedOrigin string
}

func NewGateway(manager *Manager, allowedOrigin string) (*Gateway, error) {
	if manager == nil {
		return nil, errors.New("terminal manager is required")
	}
	if allowedOrigin == "" || strings.ContainsAny(allowedOrigin, "\r\n") {
		return nil, errors.New("exact terminal origin is required")
	}
	return &Gateway{manager: manager, allowedOrigin: strings.TrimRight(allowedOrigin, "/")}, nil
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" && strings.TrimRight(origin, "/") != g.allowedOrigin {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}
	ticket, ok := bearer(r.Header.Get("Authorization"))
	if !ok {
		http.Error(w, "terminal ticket required", http.StatusUnauthorized)
		return
	}
	admission, err := g.manager.admit(ticket)
	if err != nil {
		if errors.Is(err, ErrTerminalCapacity) {
			http.Error(w, "terminal capacity unavailable", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "invalid terminal ticket", http.StatusUnauthorized)
		return
	}
	defer g.manager.unsubscribe(admission)
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{Subprotocol}, InsecureSkipVerify: true, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer conn.CloseNow()
	if conn.Subprotocol() != Subprotocol {
		_ = conn.Close(websocket.StatusPolicyViolation, "terminal subprotocol required")
		return
	}
	conn.SetReadLimit(HeaderSize + MaxPayload)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	initial := make([]Frame, 0, len(admission.replay.Frames)+1)
	if admission.replay.Gap {
		initial = append(initial, Frame{Kind: KindReplayGap, Sequence: admission.replay.EarliestSequence, TabID: admission.tab.id, Payload: []byte("scrollback_truncated")})
	}
	initial = append(initial, admission.replay.Frames...)
	responses := make(chan connectionResponse)
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		defer cancel()
		if err := writeFrames(ctx, conn, initial, responses, admission.outbound, admission.revoked, admission.deliveries); err != nil {
			_ = conn.CloseNow()
		}
	}()
	g.readFrames(ctx, conn, admission.tab, admission.record, admission.mutations, responses)
	cancel()
	_ = conn.Close(websocket.StatusNormalClosure, "")
	<-writerDone
}

type terminalFrameWriter interface {
	Write(context.Context, websocket.MessageType, []byte) error
}

func writeFrames(ctx context.Context, conn terminalFrameWriter, initial []Frame, responses <-chan connectionResponse, outbound <-chan Frame, revoked <-chan struct{}, deliveries *connectionDeliveryGate) error {
	replayContext, cancelReplay := context.WithTimeout(ctx, initialReplayWriteTimeout)
	defer cancelReplay()
	for _, frame := range initial {
		if err := writeFrame(replayContext, conn, deliveries, frame); err != nil {
			cancelReplay()
			return err
		}
	}
	cancelReplay()
	for {
		// Per-connection responses (notably input receipts) are reliable and
		// targeted. Give a waiting response priority over lossy broadcast output.
		select {
		case response := <-responses:
			if err := writeConnectionResponse(ctx, conn, deliveries, response); err != nil {
				return err
			}
			continue
		default:
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-revoked:
			return errTerminalAccessRevoked
		case response := <-responses:
			if err := writeConnectionResponse(ctx, conn, deliveries, response); err != nil {
				return err
			}
		case frame, ok := <-outbound:
			if !ok {
				return nil
			}
			if err := writeFrame(ctx, conn, deliveries, frame); err != nil {
				return err
			}
		}
	}
}

func writeConnectionResponse(ctx context.Context, conn terminalFrameWriter, deliveries *connectionDeliveryGate, response connectionResponse) error {
	err := writeFrame(ctx, conn, deliveries, response.frame)
	response.written <- err
	return err
}

func writeFrame(ctx context.Context, conn terminalFrameWriter, deliveries *connectionDeliveryGate, frame Frame) error {
	encoded, err := frame.MarshalBinary()
	if err != nil {
		return err
	}
	// Marshal before admission so revocation never waits on local encoding.
	// begin/revoke is the write linearization point: after revoke wins, no call
	// to the underlying WebSocket writer can start.
	if !deliveries.begin() {
		return errTerminalAccessRevoked
	}
	defer deliveries.end()
	writeContext, cancel := context.WithTimeout(ctx, frameWriteTimeout)
	defer cancel()
	return conn.Write(writeContext, websocket.MessageBinary, encoded)
}

func (g *Gateway) readFrames(ctx context.Context, conn *websocket.Conn, tab *tabState, record ticketRecord, mutations *connectionMutationGate, responses chan<- connectionResponse) {
	for {
		messageType, data, err := conn.Read(ctx)
		if err != nil {
			return
		}
		if messageType != websocket.MessageBinary {
			_ = conn.Close(websocket.StatusUnsupportedData, "binary terminal frames required")
			return
		}
		frame, err := ParseFrame(data)
		if err != nil || (!frame.TabID.IsZero() && frame.TabID != tab.id) {
			_ = conn.Close(websocket.StatusPolicyViolation, "invalid terminal frame")
			return
		}
		if err := g.handleFrame(ctx, tab, record, mutations, frame, responses); err != nil {
			_ = conn.Close(websocket.StatusPolicyViolation, boundedReason(err.Error()))
			return
		}
	}
}

func (g *Gateway) handleFrame(ctx context.Context, tab *tabState, record ticketRecord, mutations *connectionMutationGate, frame Frame, responses chan<- connectionResponse) error {
	if frameMutatesTerminalState(frame) {
		if !mutations.begin() {
			return errTerminalAccessRevoked
		}
		defer mutations.end()
	}
	now := g.manager.now()
	switch frame.Kind {
	case KindInput:
		if len(frame.Payload) > maxInputBytes {
			return errors.New("terminal input too large")
		}
		var receiptKey *inputReceiptKey
		var payloadHash [32]byte
		if frame.Flags&FlagIdempotentInput != 0 {
			key := inputReceiptKey{deviceID: record.deviceID, sequence: frame.Sequence}
			receiptKey = &key
			payloadHash = sha256.Sum256(frame.Payload)
			// A retry of an input that was already applied is safe to acknowledge
			// even if another device acquired the lease in the meantime.
			applied, err := tab.inputWasApplied(key, payloadHash)
			if err != nil {
				return err
			}
			if applied {
				return sendInputReceipt(ctx, tab, responses, key, payloadHash)
			}
		}
		if _, err := tab.lease.Renew(record.deviceID, now); err != nil {
			tab.broadcast(Frame{Kind: KindLeaseDenied, TabID: tab.id, Payload: []byte(tab.lease.Holder(now).DeviceID)})
			return err
		}
		wrote, err := tab.writeInput(ctx, frame.Payload, receiptKey, payloadHash)
		if err != nil {
			return err
		}
		if wrote {
			g.manager.observeActivity(tab, "input", now)
		}
		if receiptKey != nil {
			return sendInputReceipt(ctx, tab, responses, *receiptKey, payloadHash)
		}
		return nil
	case KindResize:
		if _, err := tab.lease.Renew(record.deviceID, now); err != nil {
			return err
		}
		size, err := ParseSize(frame.Payload)
		if err != nil {
			return err
		}
		return tab.runtime.Resize(ctx, size)
	case KindLeaseRequest:
		if string(frame.Payload) != record.deviceID || len(frame.Payload) > 256 {
			return errors.New("lease identity mismatch")
		}
		decision, err := tab.lease.Request(record.deviceID, frame.Flags&FlagTakeLease != 0, now)
		if err != nil {
			tab.broadcast(Frame{Kind: KindLeaseDenied, TabID: tab.id, Payload: []byte(decision.Lease.DeviceID)})
			return nil
		}
		tab.broadcast(Frame{Kind: KindLeaseGranted, TabID: tab.id, Payload: []byte(decision.Lease.DeviceID)})
		if g.manager.audit != nil {
			g.manager.audit(AuditEvent{Kind: "terminal_lease_granted", OwnerID: record.ownerID, WorkspaceID: record.workspaceID, TabID: tab.id.String(), DeviceID: record.deviceID, DisplacedDeviceID: decision.Displaced})
		}
		return nil
	case KindPing:
		return sendResponse(ctx, responses, Frame{Kind: KindPong, Sequence: frame.Sequence, TabID: frame.TabID, Payload: frame.Payload})
	case KindPong:
		return nil
	case KindAck:
		switch frame.Flags {
		case 0:
			return nil
		case FlagInputReceiptConfirmed:
			return tab.confirmInputReceipt(inputReceiptKey{deviceID: record.deviceID, sequence: frame.Sequence})
		default:
			return errors.New("client sent a server-only input receipt")
		}
	default:
		return errors.New("client sent a server-only terminal frame")
	}
}

func frameMutatesTerminalState(frame Frame) bool {
	switch frame.Kind {
	case KindInput, KindResize, KindLeaseRequest:
		return true
	case KindAck:
		return frame.Flags == FlagInputReceiptConfirmed
	default:
		return false
	}
}

func sendInputReceipt(ctx context.Context, tab *tabState, responses chan<- connectionResponse, key inputReceiptKey, payloadHash [32]byte) error {
	if err := sendResponse(ctx, responses, Frame{
		Kind: KindAck, Flags: FlagInputReceipt, Sequence: key.sequence, TabID: tab.id,
	}); err != nil {
		return err
	}
	return tab.markInputReceiptWritten(key, payloadHash)
}

func sendResponse(ctx context.Context, responses chan<- connectionResponse, frame Frame) error {
	written := make(chan error, 1)
	select {
	case responses <- connectionResponse{frame: frame, written: written}:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-written:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func NewTabID() (TabID, error) {
	var id TabID
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		return TabID{}, err
	}
	// UUID v4 variant bits keep IDs portable to Foundation.UUID.
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	return id, nil
}

func ParseTabID(value string) (TabID, error) {
	compact := strings.ReplaceAll(value, "-", "")
	decoded, err := hex.DecodeString(compact)
	if err != nil || len(decoded) != 16 {
		return TabID{}, errors.New("invalid terminal tab UUID")
	}
	var id TabID
	copy(id[:], decoded)
	if id.IsZero() {
		return TabID{}, errors.New("terminal tab UUID cannot be zero")
	}
	return id, nil
}

func (id TabID) String() string {
	encoded := hex.EncodeToString(id[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:])
}

func randomCredential(source io.Reader, prefix string) (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(source, b); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b), nil
}

func bearer(value string) (string, bool) {
	if len(value) < 8 || !strings.EqualFold(value[:7], "Bearer ") {
		return "", false
	}
	token := strings.TrimSpace(value[7:])
	return token, token != "" && !strings.ContainsAny(token, " \t\r\n")
}

func boundedReason(reason string) string {
	reason = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, reason)
	if len(reason) > 120 {
		reason = reason[:120]
	}
	if reason == "" {
		return "terminal_closed"
	}
	return reason
}
