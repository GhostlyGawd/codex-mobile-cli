package terminal

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCredentialCapacityEnforcesEveryScope(t *testing.T) {
	targetTab := seededTabID("target")
	tests := []struct {
		credential string
		scope      string
		limit      int
	}{
		{"ticket", "global", maxUnusedTicketsGlobal},
		{"ticket", "owner", maxUnusedTicketsPerOwner},
		{"ticket", "device", maxUnusedTicketsPerDevice},
		{"ticket", "tab", maxUnusedTicketsPerTab},
		{"reconnect", "global", maxReconnectsGlobal},
		{"reconnect", "owner", maxReconnectsPerOwner},
		{"reconnect", "device", maxReconnectsPerDevice},
		{"reconnect", "tab", maxReconnectsPerTab},
	}
	for _, test := range tests {
		t.Run(test.credential+"_"+test.scope, func(t *testing.T) {
			manager, err := NewManager([]byte("0123456789abcdef0123456789abcdef"), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer manager.Close()
			for index := 0; index < test.limit; index++ {
				record := capacityRecord(test.scope, index, targetTab)
				key := sha256.Sum256([]byte(fmt.Sprintf("%s-%s-%d", test.credential, test.scope, index)))
				if test.credential == "ticket" {
					manager.tickets[key] = record
				} else {
					manager.reconnects[key] = reconnectRecord{
						ownerID: record.ownerID, deviceID: record.deviceID, workspaceID: record.workspaceID,
						tabID: record.tabID, expiresAt: record.expiresAt,
					}
				}
			}
			if err := manager.requireCredentialCapacityLocked("target-owner", "target-device", targetTab, nil); !errors.Is(err, ErrTerminalCapacity) {
				t.Fatalf("%s %s capacity error = %v", test.credential, test.scope, err)
			}
		})
	}
}

func TestCredentialCapacityRecoversAfterExpiryAndDeviceRevocation(t *testing.T) {
	manager, tabID := newCapacityManager(t)
	now := time.Unix(10_000, 0).UTC()
	manager.now = func() time.Time { return now }
	manager.ticketTTL = time.Minute
	manager.reconnectTTL = time.Minute
	for index := 0; index < maxUnusedTicketsPerTab; index++ {
		if _, err := manager.Issue("owner", fmt.Sprintf("device-%d", index), "workspace", tabID, 0, ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := manager.Issue("owner", "overflow", "workspace", tabID, 0, ""); !errors.Is(err, ErrTerminalCapacity) {
		t.Fatalf("ticket cap error = %v", err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := manager.Issue("owner", "after-expiry", "workspace", tabID, 0, ""); err != nil {
		t.Fatalf("expired credentials did not free capacity: %v", err)
	}
	if len(manager.tickets) != 1 || len(manager.reconnects) != 1 {
		t.Fatalf("expiry cleanup retained credentials: tickets=%d reconnects=%d", len(manager.tickets), len(manager.reconnects))
	}

	manager.RevokeDevice("owner", "after-expiry")
	if len(manager.tickets) != 0 || len(manager.reconnects) != 0 {
		t.Fatalf("device revocation retained credentials: tickets=%d reconnects=%d", len(manager.tickets), len(manager.reconnects))
	}
	if _, err := manager.Issue("owner", "after-expiry", "workspace", tabID, 0, ""); err != nil {
		t.Fatalf("revocation did not free credential capacity: %v", err)
	}
}

func TestReconnectReplacementSucceedsAtCapacity(t *testing.T) {
	manager, tabID := newCapacityManager(t)
	tokens := make([]string, 0, maxReconnectsPerDevice)
	for index := 0; index < maxReconnectsPerDevice; index++ {
		connection, err := manager.Issue("owner", "device", "workspace", tabID, 0, "")
		if err != nil {
			t.Fatal(err)
		}
		tokens = append(tokens, connection.ReconnectToken)
		admission, err := manager.admit(connection.Ticket)
		if err != nil {
			t.Fatal(err)
		}
		manager.unsubscribe(admission)
	}
	if _, err := manager.Issue("owner", "device", "workspace", tabID, 0, ""); !errors.Is(err, ErrTerminalCapacity) {
		t.Fatalf("reconnect cap error = %v", err)
	}
	if _, err := manager.Issue("owner", "device", "workspace", tabID, 0, tokens[0]); err != nil {
		t.Fatalf("one-use reconnect replacement failed at capacity: %v", err)
	}
	if len(manager.reconnects) != maxReconnectsPerDevice {
		t.Fatalf("reconnect replacement changed bounded size: %d", len(manager.reconnects))
	}
	if _, err := manager.Issue("owner", "device", "workspace", tabID, 0, tokens[0]); err == nil || errors.Is(err, ErrTerminalCapacity) {
		t.Fatalf("consumed reconnect error = %v", err)
	}
}

func TestSubscriberCapacityEnforcesEveryScope(t *testing.T) {
	record := ticketRecord{ownerID: "owner", deviceID: "device", tabID: seededTabID("subscriber")}
	tests := []struct {
		name string
		seed func(*Manager)
	}{
		{"global", func(manager *Manager) { manager.subscribers = maxSubscribersGlobal }},
		{"owner", func(manager *Manager) {
			manager.subscribers = maxSubscribersPerOwner
			manager.subscribersByOwner[record.ownerID] = maxSubscribersPerOwner
		}},
		{"device", func(manager *Manager) {
			manager.subscribers = maxSubscribersPerDevice
			manager.subscribersByDevice[ownerDevice{ownerID: record.ownerID, deviceID: record.deviceID}] = maxSubscribersPerDevice
		}},
		{"tab", func(manager *Manager) {
			manager.subscribers = maxSubscribersPerTab
			manager.subscribersByTab[record.tabID] = maxSubscribersPerTab
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager, err := NewManager([]byte("0123456789abcdef0123456789abcdef"), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer manager.Close()
			test.seed(manager)
			if err := manager.reserveSubscriberLocked(record); !errors.Is(err, ErrTerminalCapacity) {
				t.Fatalf("subscriber %s cap error = %v", test.name, err)
			}
		})
	}
}

func TestGatewaySubscriberCapacityIs503AndRecoversAfterRevokeUnsubscribe(t *testing.T) {
	manager, tabID := newCapacityManager(t)
	admissions := make([]admittedConnection, 0, maxSubscribersPerDevice)
	defer func() {
		for _, admission := range admissions {
			manager.unsubscribe(admission)
		}
	}()
	for index := 0; index < maxSubscribersPerDevice; index++ {
		connection, err := manager.Issue("owner", "device", "workspace", tabID, 0, "")
		if err != nil {
			t.Fatal(err)
		}
		admission, err := manager.admit(connection.Ticket)
		if err != nil {
			t.Fatal(err)
		}
		admissions = append(admissions, admission)
	}

	capacityConnection, err := manager.Issue("owner", "device", "workspace", tabID, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := NewGateway(manager, "https://api.example.test")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/terminal", nil)
	request.Header.Set("Authorization", "Bearer "+capacityConnection.Ticket)
	response := httptest.NewRecorder()
	gateway.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || strings.TrimSpace(response.Body.String()) != "terminal capacity unavailable" {
		t.Fatalf("gateway capacity response = %d %q", response.Code, response.Body.String())
	}

	invalidRequest := httptest.NewRequest(http.MethodGet, "/v1/terminal", nil)
	invalidRequest.Header.Set("Authorization", "Bearer cm_terminal_ticket_invalid")
	invalidResponse := httptest.NewRecorder()
	gateway.ServeHTTP(invalidResponse, invalidRequest)
	if invalidResponse.Code != http.StatusUnauthorized {
		t.Fatalf("invalid ticket status = %d", invalidResponse.Code)
	}

	if disconnected := manager.RevokeDevice("owner", "device"); disconnected != maxSubscribersPerDevice {
		t.Fatalf("revoked subscribers = %d", disconnected)
	}
	for _, admission := range admissions {
		manager.unsubscribe(admission)
	}
	admissions = nil
	connection, err := manager.Issue("owner", "device", "workspace", tabID, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := manager.admit(connection.Ticket)
	if err != nil {
		t.Fatalf("subscriber capacity did not recover after revoke/unsubscribe: %v", err)
	}
	admissions = append(admissions, recovered)
}

func newCapacityManager(t *testing.T) (*Manager, TabID) {
	t.Helper()
	manager, err := NewManager([]byte("0123456789abcdef0123456789abcdef"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	tabID := seededTabID(t.Name())
	if err := manager.Register("owner", "workspace", tabID, newFakeRuntime(), testOutputRedactor(t), false); err != nil {
		t.Fatal(err)
	}
	return manager, tabID
}

func capacityRecord(scope string, index int, targetTab TabID) ticketRecord {
	record := ticketRecord{
		ownerID: "target-owner", deviceID: "target-device", workspaceID: "workspace",
		tabID: seededTabID(fmt.Sprintf("record-%d", index)), expiresAt: time.Unix(1<<30, 0),
	}
	switch scope {
	case "global":
		record.ownerID = fmt.Sprintf("owner-%d", index)
		record.deviceID = fmt.Sprintf("device-%d", index)
	case "owner":
		record.deviceID = fmt.Sprintf("device-%d", index)
	case "device":
	case "tab":
		record.ownerID = fmt.Sprintf("other-owner-%d", index)
		record.deviceID = fmt.Sprintf("other-device-%d", index)
		record.tabID = targetTab
	default:
		panic("unknown capacity scope")
	}
	return record
}

func seededTabID(seed string) TabID {
	digest := sha256.Sum256([]byte(seed))
	var id TabID
	copy(id[:], digest[:16])
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	return id
}
