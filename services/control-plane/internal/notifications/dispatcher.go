package notifications

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/apns"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/codex"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/postgres"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/terminal"
)

const (
	defaultQueueCapacity = 256
	defaultWorkers       = 2
	defaultMaxAttempts   = 3
	defaultSendTimeout   = 15 * time.Second
	defaultEventTimeout  = 45 * time.Second
	defaultRetryBase     = 100 * time.Millisecond
	defaultRetryMaximum  = 2 * time.Second
)

type Store interface {
	AddActivity(context.Context, string, postgres.ActivityRecord) error
	GetSettings(context.Context, string) (postgres.Settings, error)
	ListNotificationEndpoints(context.Context, string) ([]postgres.NotificationEndpointRecord, error)
	MarkNotificationDelivered(context.Context, string, string, time.Time) error
	MarkNotificationFailed(context.Context, string, string, bool, time.Time) error
}

type Sender interface {
	Send(context.Context, apns.Environment, string, apns.Notification) error
}

type Attention interface {
	Notify(terminal.TabID, string)
}

type Clock interface {
	Now() time.Time
}

type Recorder interface {
	RecordNotification(bool)
}

type Config struct {
	APNSEnabled   bool
	Topic         string
	PublicOrigin  string
	QueueCapacity int
	Workers       int
	MaxAttempts   int
	SendTimeout   time.Duration
	EventTimeout  time.Duration
	RetryBase     time.Duration
	RetryMaximum  time.Duration
	Random        io.Reader
	Clock         Clock
	Recorder      Recorder
}

type Dispatcher struct {
	config       Config
	store        Store
	sender       Sender
	attention    Attention
	publicOrigin string

	ctx      context.Context
	cancel   context.CancelFunc
	queue    chan task
	wg       sync.WaitGroup
	close    sync.Once
	randomMu sync.Mutex
}

type task struct {
	context  terminal.CodexEventContext
	event    codex.Event
	activity *activityNotification
}

type activityNotification struct {
	ownerID, activityID, kind, deepLinkPath string
}

type utcClock struct{}

func (utcClock) Now() time.Time { return time.Now().UTC() }

func New(config Config, store Store, attention Attention, sender Sender) (*Dispatcher, error) {
	if store == nil || attention == nil {
		return nil, errors.New("notification store and terminal attention sink are required")
	}
	if config.APNSEnabled && sender == nil {
		return nil, errors.New("APNs sender is required when delivery is enabled")
	}
	if !config.APNSEnabled && sender != nil {
		return nil, errors.New("APNs sender must not be installed when delivery is disabled")
	}
	if config.QueueCapacity == 0 {
		config.QueueCapacity = defaultQueueCapacity
	}
	if config.Workers == 0 {
		config.Workers = defaultWorkers
	}
	if config.MaxAttempts == 0 {
		config.MaxAttempts = defaultMaxAttempts
	}
	if config.SendTimeout == 0 {
		config.SendTimeout = defaultSendTimeout
	}
	if config.EventTimeout == 0 {
		config.EventTimeout = defaultEventTimeout
	}
	if config.RetryBase == 0 {
		config.RetryBase = defaultRetryBase
	}
	if config.RetryMaximum == 0 {
		config.RetryMaximum = defaultRetryMaximum
	}
	if config.QueueCapacity < 1 || config.QueueCapacity > 4096 || config.Workers < 1 || config.Workers > 8 ||
		config.MaxAttempts < 1 || config.MaxAttempts > 5 || config.SendTimeout < time.Second || config.SendTimeout > 30*time.Second ||
		config.EventTimeout < config.SendTimeout || config.EventTimeout > 2*time.Minute ||
		config.RetryBase < time.Millisecond || config.RetryMaximum < config.RetryBase || config.RetryMaximum > 10*time.Second {
		return nil, errors.New("notification dispatcher limits are invalid")
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	if config.Clock == nil {
		config.Clock = utcClock{}
	}
	publicOrigin := ""
	if config.APNSEnabled {
		if config.Topic == "" || len(config.Topic) > 255 || strings.ContainsAny(config.Topic, "\x00\r\n") {
			return nil, errors.New("APNs topic is required and must be bounded")
		}
		origin, err := url.Parse(config.PublicOrigin)
		if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.Path != "" ||
			origin.RawQuery != "" || origin.Fragment != "" {
			return nil, errors.New("APNs deep-link origin must be an absolute HTTPS origin")
		}
		publicOrigin = strings.TrimRight(origin.String(), "/")
	}
	ctx, cancel := context.WithCancel(context.Background())
	dispatcher := &Dispatcher{
		config: config, store: store, sender: sender, attention: attention, publicOrigin: publicOrigin,
		ctx: ctx, cancel: cancel, queue: make(chan task, config.QueueCapacity),
	}
	for range config.Workers {
		dispatcher.wg.Add(1)
		go dispatcher.worker()
	}
	return dispatcher, nil
}

// NotifyActivity delivers an already-persisted, generic activity. Setup
// approvals use this path so the APNs tap opens an authenticated native review
// without exposing repository, command, prompt, or approval controls on the
// lock screen.
func (d *Dispatcher) NotifyActivity(ownerID, activityID, kind, deepLinkPath string) bool {
	if ownerID == "" || len(ownerID) > 128 || strings.ContainsAny(ownerID, "\x00\r\n") ||
		!validOpaqueNotificationID(activityID) || !validActivityNotificationKind(kind) || !validActivityDeepLinkPath(deepLinkPath) {
		return false
	}
	if !d.config.APNSEnabled {
		return true
	}
	value := &activityNotification{ownerID: ownerID, activityID: activityID, kind: kind, deepLinkPath: deepLinkPath}
	select {
	case <-d.ctx.Done():
		return false
	case d.queue <- task{activity: value}:
		return true
	default:
		return false
	}
}

// HandleCodexEvent is intentionally non-blocking. It always emits the local
// terminal attention frame first, then places persistence/APNs work on a
// bounded queue. It ignores every human-readable event field and constructs
// generic text from the trusted event kind only.
func (d *Dispatcher) HandleCodexEvent(eventContext terminal.CodexEventContext, event codex.Event) bool {
	if eventContext.OwnerID == "" || eventContext.WorkspaceID == "" || eventContext.TabID.IsZero() ||
		(event.Kind != codex.EventNeedsAttention && event.Kind != codex.EventTurnComplete) {
		return false
	}
	d.attention.Notify(eventContext.TabID, terminalAttentionKind(event.Kind))
	select {
	case <-d.ctx.Done():
		return false
	case d.queue <- task{context: eventContext, event: codex.Event{Kind: event.Kind}}:
		return true
	default:
		return false
	}
}

func (d *Dispatcher) Close() error {
	d.close.Do(func() {
		d.cancel()
		d.wg.Wait()
	})
	return nil
}

func (d *Dispatcher) worker() {
	defer d.wg.Done()
	for {
		select {
		case <-d.ctx.Done():
			return
		case value := <-d.queue:
			if value.activity != nil {
				d.processActivity(*value.activity)
			} else {
				d.process(value)
			}
		}
	}
}

func (d *Dispatcher) process(value task) {
	ctx, cancel := context.WithTimeout(d.ctx, d.config.EventTimeout)
	defer cancel()
	activityID, err := d.newID()
	if err != nil {
		return
	}
	now := d.config.Clock.Now().UTC()
	workspaceID := value.context.WorkspaceID
	metadata, err := json.Marshal(map[string]any{
		"structured_detail_available": false,
		"terminal_tab_id":             value.context.TabID.String(),
	})
	if err != nil {
		return
	}
	if err := d.store.AddActivity(ctx, value.context.OwnerID, postgres.ActivityRecord{
		ID: activityID, WorkspaceID: &workspaceID, Kind: activityKind(value.event.Kind),
		Summary: genericSummary(value.event.Kind), Unread: true, Metadata: metadata, CreatedAt: now,
	}); err != nil {
		return
	}
	d.dispatchAPNS(ctx, value.context.OwnerID, apns.Notification{
		Kind: notificationKind(value.event.Kind), ActivityID: activityID, DeepLink: d.publicOrigin + "/app/activity",
	})
}

func (d *Dispatcher) processActivity(value activityNotification) {
	if !d.config.APNSEnabled {
		return
	}
	ctx, cancel := context.WithTimeout(d.ctx, d.config.EventTimeout)
	defer cancel()
	d.dispatchAPNS(ctx, value.ownerID, apns.Notification{
		Kind: value.kind, ActivityID: value.activityID, DeepLink: d.publicOrigin + value.deepLinkPath,
	})
}

func (d *Dispatcher) dispatchAPNS(ctx context.Context, ownerID string, notification apns.Notification) {
	if !d.config.APNSEnabled {
		return
	}
	settings, err := d.store.GetSettings(ctx, ownerID)
	if err != nil || settings.QuietHoursEnabled {
		return
	}
	endpoints, err := d.store.ListNotificationEndpoints(ctx, ownerID)
	if err != nil {
		return
	}
	defer func() {
		for index := range endpoints {
			clear(endpoints[index].Token)
		}
	}()
	for index := range endpoints {
		if ctx.Err() != nil {
			return
		}
		endpoint := &endpoints[index]
		if endpoint.OwnerID != ownerID || endpoint.Topic != d.config.Topic {
			d.markFailed(ctx, ownerID, endpoint.ID, true)
			continue
		}
		environment := apns.Environment(endpoint.Environment)
		if environment != apns.Sandbox && environment != apns.Production {
			d.markFailed(ctx, ownerID, endpoint.ID, true)
			continue
		}
		d.deliver(ctx, ownerID, endpoint.ID, environment, string(endpoint.Token), notification)
	}
}

func validActivityNotificationKind(value string) bool {
	switch value {
	case "approval", "attention", "completion", "failure", "maintenance", "security":
		return true
	default:
		return false
	}
}

func validActivityDeepLinkPath(value string) bool {
	if value == "/app/activity" {
		return true
	}
	for _, prefix := range []string{"/app/approvals/", "/app/workspaces/"} {
		if strings.HasPrefix(value, prefix) && validOpaqueNotificationID(strings.TrimPrefix(value, prefix)) {
			return true
		}
	}
	return false
}

func validOpaqueNotificationID(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for index := range len(value) {
		character := value[index]
		alphanumeric := character >= '0' && character <= '9' || character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z'
		if !alphanumeric && (index == 0 || character != '.' && character != '_' && character != ':' && character != '-') {
			return false
		}
	}
	return true
}

func (d *Dispatcher) deliver(parent context.Context, ownerID, endpointID string, environment apns.Environment, token string, notification apns.Notification) {
	var lastErr error
	for attempt := 1; attempt <= d.config.MaxAttempts; attempt++ {
		if parent.Err() != nil {
			return
		}
		ctx, cancel := context.WithTimeout(parent, d.config.SendTimeout)
		err := d.sender.Send(ctx, environment, token, notification)
		cancel()
		if err == nil {
			statusCtx, statusCancel := context.WithTimeout(parent, 5*time.Second)
			_ = d.store.MarkNotificationDelivered(statusCtx, ownerID, endpointID, d.config.Clock.Now().UTC())
			statusCancel()
			if d.config.Recorder != nil {
				d.config.Recorder.RecordNotification(true)
			}
			return
		}
		lastErr = err
		if errors.Is(err, apns.ErrUnregistered) {
			d.markFailed(parent, ownerID, endpointID, true)
			return
		}
		retry, delay := d.retry(parent, err, attempt)
		if !retry || attempt == d.config.MaxAttempts {
			break
		}
		timer := time.NewTimer(delay)
		select {
		case <-parent.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}
	}
	if lastErr != nil {
		d.markFailed(parent, ownerID, endpointID, false)
	}
}

func (d *Dispatcher) retry(parent context.Context, err error, attempt int) (bool, time.Duration) {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) && parent.Err() != nil {
		return false, 0
	}
	delay := d.config.RetryBase << (attempt - 1)
	var delivery *apns.DeliveryError
	if errors.As(err, &delivery) {
		if delivery.Status != 429 && delivery.Status < 500 {
			return false, 0
		}
		if delivery.RetryAfter > delay {
			delay = delivery.RetryAfter
		}
	}
	if delay > d.config.RetryMaximum {
		delay = d.config.RetryMaximum
	}
	return true, delay
}

func (d *Dispatcher) markFailed(parent context.Context, ownerID, endpointID string, disable bool) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	_ = d.store.MarkNotificationFailed(ctx, ownerID, endpointID, disable, d.config.Clock.Now().UTC())
	if d.config.Recorder != nil {
		d.config.Recorder.RecordNotification(false)
	}
}

func (d *Dispatcher) newID() (string, error) {
	buffer := make([]byte, 16)
	d.randomMu.Lock()
	_, err := io.ReadFull(d.config.Random, buffer)
	d.randomMu.Unlock()
	if err != nil {
		return "", fmt.Errorf("generate activity identity: %w", err)
	}
	return "activity_" + base64.RawURLEncoding.EncodeToString(buffer), nil
}

func activityKind(kind codex.EventKind) string {
	if kind == codex.EventTurnComplete {
		return "completed"
	}
	return "question"
}

func notificationKind(kind codex.EventKind) string {
	if kind == codex.EventTurnComplete {
		return "completion"
	}
	return "attention"
}

func terminalAttentionKind(kind codex.EventKind) string {
	if kind == codex.EventTurnComplete {
		return "completion"
	}
	return "attention"
}

func genericSummary(kind codex.EventKind) string {
	if kind == codex.EventTurnComplete {
		return "A session completed."
	}
	return "A session needs attention."
}

var _ terminal.CodexEventHandler = (*Dispatcher)(nil)
var _ Sender = (*apns.Client)(nil)
