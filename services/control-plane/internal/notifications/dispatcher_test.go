package notifications

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/apns"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/codex"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/postgres"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/terminal"
)

type fakeClock struct{ now time.Time }

func (f fakeClock) Now() time.Time { return f.now }

type fakeStore struct {
	mu         sync.Mutex
	settings   postgres.Settings
	endpoints  []postgres.NotificationEndpointRecord
	activities []postgres.ActivityRecord
	delivered  []string
	failed     map[string]bool
	activityCh chan postgres.ActivityRecord
	started    chan struct{}
	release    chan struct{}
}

func (f *fakeStore) AddActivity(_ context.Context, ownerID string, value postgres.ActivityRecord) error {
	if ownerID == "" {
		return errors.New("owner missing")
	}
	if f.started != nil {
		select {
		case f.started <- struct{}{}:
		default:
		}
		<-f.release
	}
	f.mu.Lock()
	f.activities = append(f.activities, value)
	f.mu.Unlock()
	if f.activityCh != nil {
		f.activityCh <- value
	}
	return nil
}

func (f *fakeStore) GetSettings(context.Context, string) (postgres.Settings, error) {
	return f.settings, nil
}

func (f *fakeStore) ListNotificationEndpoints(context.Context, string) ([]postgres.NotificationEndpointRecord, error) {
	result := make([]postgres.NotificationEndpointRecord, len(f.endpoints))
	for index := range f.endpoints {
		result[index] = f.endpoints[index]
		result[index].Token = append([]byte(nil), f.endpoints[index].Token...)
	}
	return result, nil
}

func (f *fakeStore) MarkNotificationDelivered(_ context.Context, _ string, endpointID string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delivered = append(f.delivered, endpointID)
	return nil
}

func (f *fakeStore) MarkNotificationFailed(_ context.Context, _ string, endpointID string, disable bool, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failed == nil {
		f.failed = make(map[string]bool)
	}
	f.failed[endpointID] = disable
	return nil
}

type sendCall struct {
	environment  apns.Environment
	token        string
	notification apns.Notification
}

type fakeSender struct {
	mu     sync.Mutex
	calls  []sendCall
	errors []error
	callCh chan sendCall
}

func (f *fakeSender) Send(_ context.Context, environment apns.Environment, token string, notification apns.Notification) error {
	f.mu.Lock()
	call := sendCall{environment: environment, token: token, notification: notification}
	f.calls = append(f.calls, call)
	index := len(f.calls) - 1
	var err error
	if index < len(f.errors) {
		err = f.errors[index]
	}
	f.mu.Unlock()
	if f.callCh != nil {
		f.callCh <- call
	}
	return err
}

type fakeAttention struct {
	mu    sync.Mutex
	calls []string
}

type notificationRecorder struct {
	mu     sync.Mutex
	values []bool
}

func (r *notificationRecorder) RecordNotification(success bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.values = append(r.values, success)
}

func (f *fakeAttention) Notify(id terminal.TabID, kind string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, id.String()+":"+kind)
}

func TestDispatcherCreatesGenericActivityAttentionAndAPNS(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_750_000_000, 0).UTC()
	store := &fakeStore{
		settings:   postgres.DefaultSettings(),
		activityCh: make(chan postgres.ActivityRecord, 1),
		endpoints: []postgres.NotificationEndpointRecord{{
			ID: "endpoint-1", OwnerID: "owner-1", DeviceID: "device-1", Environment: "production",
			Token: []byte(strings.Repeat("ab", 32)), Topic: "com.example.CodexMobile",
		}},
	}
	sender := &fakeSender{callCh: make(chan sendCall, 1)}
	attention := &fakeAttention{}
	recorder := &notificationRecorder{}
	dispatcher, err := New(Config{
		APNSEnabled: true, Topic: "com.example.CodexMobile", PublicOrigin: "https://codex.example",
		Clock: fakeClock{now}, Random: strings.NewReader(strings.Repeat("r", 64)), RetryBase: time.Millisecond,
		Recorder: recorder,
	}, store, attention, sender)
	if err != nil {
		t.Fatal(err)
	}
	defer dispatcher.Close()
	tabID, _ := terminal.ParseTabID("52e782d5-6e80-4944-a42f-a21201900c74")
	if !dispatcher.HandleCodexEvent(terminal.CodexEventContext{OwnerID: "owner-1", WorkspaceID: "workspace-1", TabID: tabID}, codex.Event{
		Kind: codex.EventNeedsAttention, GenericSummary: "SECRET command and repository", StructuredDetail: true,
	}) {
		t.Fatal("event was not queued")
	}

	var activity postgres.ActivityRecord
	select {
	case activity = <-store.activityCh:
	case <-time.After(2 * time.Second):
		t.Fatal("activity was not stored")
	}
	var call sendCall
	select {
	case call = <-sender.callCh:
	case <-time.After(2 * time.Second):
		t.Fatal("APNs delivery was not attempted")
	}
	if activity.Kind != "question" || activity.Summary != "A session needs attention." ||
		strings.Contains(string(activity.Metadata), "SECRET") || !activity.Unread {
		t.Fatalf("unsafe or incomplete activity: %#v", activity)
	}
	if call.notification.Kind != "attention" || call.notification.Title != "" ||
		call.notification.DeepLink != "https://codex.example/app/activity" ||
		call.notification.ActivityID != activity.ID || strings.Contains(call.notification.DeepLink, "workspace") {
		t.Fatalf("unsafe APNs notification: %#v", call.notification)
	}
	if call.environment != apns.Production || call.token != strings.Repeat("ab", 32) {
		t.Fatalf("unexpected endpoint delivery: %#v", call)
	}
	waitFor(t, func() bool {
		store.mu.Lock()
		defer store.mu.Unlock()
		return len(store.delivered) == 1
	})
	waitFor(t, func() bool {
		recorder.mu.Lock()
		defer recorder.mu.Unlock()
		return len(recorder.values) == 1 && recorder.values[0]
	})
	attention.mu.Lock()
	defer attention.mu.Unlock()
	if len(attention.calls) != 1 || !strings.HasSuffix(attention.calls[0], ":attention") {
		t.Fatalf("unexpected attention calls: %#v", attention.calls)
	}
}

func TestDispatcherRetriesTransientAPNSErrorAndDisablesUnregisteredEndpoint(t *testing.T) {
	t.Parallel()
	store := &fakeStore{
		settings:   postgres.DefaultSettings(),
		activityCh: make(chan postgres.ActivityRecord, 2),
		endpoints: []postgres.NotificationEndpointRecord{{
			ID: "endpoint-1", OwnerID: "owner-1", DeviceID: "device-1", Environment: "sandbox",
			Token: []byte(strings.Repeat("cd", 32)), Topic: "com.example.CodexMobile",
		}},
	}
	sender := &fakeSender{errors: []error{
		&apns.DeliveryError{Status: 503, Reason: "ServiceUnavailable"}, nil,
		fmtUnregistered(),
	}, callCh: make(chan sendCall, 3)}
	dispatcher, err := New(Config{
		APNSEnabled: true, Topic: "com.example.CodexMobile", PublicOrigin: "https://codex.example",
		Clock: fakeClock{time.Unix(100, 0)}, Random: strings.NewReader(strings.Repeat("x", 64)),
		Workers: 1, RetryBase: time.Millisecond, RetryMaximum: 2 * time.Millisecond,
	}, store, &fakeAttention{}, sender)
	if err != nil {
		t.Fatal(err)
	}
	defer dispatcher.Close()
	tabID, _ := terminal.NewTabID()
	context := terminal.CodexEventContext{OwnerID: "owner-1", WorkspaceID: "workspace-1", TabID: tabID}
	if !dispatcher.HandleCodexEvent(context, codex.Event{Kind: codex.EventTurnComplete}) {
		t.Fatal("first event was not queued")
	}
	waitFor(t, func() bool {
		sender.mu.Lock()
		defer sender.mu.Unlock()
		return len(sender.calls) >= 2
	})
	waitFor(t, func() bool {
		store.mu.Lock()
		defer store.mu.Unlock()
		return len(store.delivered) == 1
	})
	if !dispatcher.HandleCodexEvent(context, codex.Event{Kind: codex.EventNeedsAttention}) {
		t.Fatal("second event was not queued")
	}
	waitFor(t, func() bool {
		store.mu.Lock()
		defer store.mu.Unlock()
		return store.failed["endpoint-1"]
	})
}

func TestDispatcherDeliversPersistedApprovalWithAuthenticatedDeepLink(t *testing.T) {
	t.Parallel()
	store := &fakeStore{
		settings: postgres.DefaultSettings(),
		endpoints: []postgres.NotificationEndpointRecord{{
			ID: "endpoint-1", OwnerID: "owner-1", DeviceID: "device-1", Environment: "production",
			Token: []byte(strings.Repeat("ab", 32)), Topic: "com.example.CodexMobile",
		}},
	}
	sender := &fakeSender{callCh: make(chan sendCall, 1)}
	dispatcher, err := New(Config{
		APNSEnabled: true, Topic: "com.example.CodexMobile", PublicOrigin: "https://codex.example",
		RetryBase: time.Millisecond,
	}, store, &fakeAttention{}, sender)
	if err != nil {
		t.Fatal(err)
	}
	defer dispatcher.Close()
	if !dispatcher.NotifyActivity("owner-1", "activity_123", "approval", "/app/approvals/approval_123") {
		t.Fatal("persisted approval notification was not queued")
	}
	select {
	case call := <-sender.callCh:
		if call.notification.Kind != "approval" || call.notification.ActivityID != "activity_123" ||
			call.notification.DeepLink != "https://codex.example/app/approvals/approval_123" || call.notification.Title != "" {
			t.Fatalf("approval notification leaked detail or lost routing: %#v", call.notification)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("persisted approval APNs delivery was not attempted")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.activities) != 0 {
		t.Fatalf("approval notification duplicated its persisted activity: %#v", store.activities)
	}
	for _, invalid := range []string{"/app/approvals/..", "/app/approvals/a/decision", "https://evil.example/app/approvals/a"} {
		if dispatcher.NotifyActivity("owner-1", "activity_123", "approval", invalid) {
			t.Fatalf("unsafe approval deep link was queued: %q", invalid)
		}
	}
}

func TestDispatcherQuietHoursAndDisabledAPNSFailClosed(t *testing.T) {
	t.Parallel()
	settings := postgres.DefaultSettings()
	settings.QuietHoursEnabled = true
	store := &fakeStore{settings: settings, activityCh: make(chan postgres.ActivityRecord, 2), endpoints: []postgres.NotificationEndpointRecord{{
		ID: "endpoint-1", OwnerID: "owner-1", Environment: "production", Token: []byte(strings.Repeat("ef", 32)), Topic: "topic",
	}}}
	sender := &fakeSender{}
	dispatcher, err := New(Config{APNSEnabled: true, Topic: "topic", PublicOrigin: "https://codex.example"}, store, &fakeAttention{}, sender)
	if err != nil {
		t.Fatal(err)
	}
	tabID, _ := terminal.NewTabID()
	dispatcher.HandleCodexEvent(terminal.CodexEventContext{OwnerID: "owner-1", WorkspaceID: "workspace-1", TabID: tabID}, codex.Event{Kind: codex.EventNeedsAttention})
	select {
	case <-store.activityCh:
	case <-time.After(2 * time.Second):
		t.Fatal("quiet hours suppressed in-app activity")
	}
	time.Sleep(10 * time.Millisecond)
	sender.mu.Lock()
	if len(sender.calls) != 0 {
		t.Fatalf("quiet hours sent APNs: %#v", sender.calls)
	}
	sender.mu.Unlock()
	_ = dispatcher.Close()

	if _, err := New(Config{APNSEnabled: false}, store, &fakeAttention{}, sender); err == nil {
		t.Fatal("disabled APNs accepted a live sender")
	}
	disabled, err := New(Config{APNSEnabled: false}, store, &fakeAttention{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer disabled.Close()
}

func TestDispatcherQueueIsBoundedWithoutBlockingTerminalAttention(t *testing.T) {
	t.Parallel()
	store := &fakeStore{settings: postgres.DefaultSettings(), started: make(chan struct{}, 1), release: make(chan struct{})}
	attention := &fakeAttention{}
	dispatcher, err := New(Config{QueueCapacity: 1, Workers: 1}, store, attention, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer dispatcher.Close()
	tabID, _ := terminal.NewTabID()
	value := terminal.CodexEventContext{OwnerID: "owner-1", WorkspaceID: "workspace-1", TabID: tabID}
	if !dispatcher.HandleCodexEvent(value, codex.Event{Kind: codex.EventNeedsAttention}) {
		t.Fatal("first event was not queued")
	}
	select {
	case <-store.started:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not start")
	}
	if !dispatcher.HandleCodexEvent(value, codex.Event{Kind: codex.EventNeedsAttention}) {
		t.Fatal("second event did not fill queue")
	}
	if dispatcher.HandleCodexEvent(value, codex.Event{Kind: codex.EventNeedsAttention}) {
		t.Fatal("full queue accepted an unbounded event")
	}
	attention.mu.Lock()
	if len(attention.calls) != 3 {
		t.Fatalf("queue pressure suppressed terminal attention: %#v", attention.calls)
	}
	attention.mu.Unlock()
	close(store.release)
}

func fmtUnregistered() error {
	return errors.Join(apns.ErrUnregistered, errors.New("provider rejected endpoint"))
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
