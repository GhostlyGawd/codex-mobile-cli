package application

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/httpapi"
)

func TestMutationGateIndexesReleaseHostileKeys(t *testing.T) {
	application := &Application{
		mutationLocks: make(map[string]*mutationGate),
		secretLocks:   make(map[string]*mutationGate),
		terminalLocks: make(map[string]*mutationGate),
	}

	for index := 0; index < 10_000; index++ {
		workspaceID := fmt.Sprintf("hostile-workspace-%d", index)
		ownerID := fmt.Sprintf("hostile-owner-%d", index)
		deviceID := fmt.Sprintf("hostile-device-%d", index)
		secretID := fmt.Sprintf("hostile-secret-%d", index)

		releaseWorkspace := application.acquireWorkspaceMutation(workspaceID)
		releaseWorkspace()
		releaseSecret := application.acquireSecretMutation(ownerID, secretID)
		releaseSecret()
		releaseTerminal := application.acquireTerminalAdmission(ownerID, deviceID)
		releaseTerminal()
	}

	application.mutationMu.Lock()
	defer application.mutationMu.Unlock()
	if count := len(application.mutationLocks); count != 0 {
		t.Fatalf("workspace mutation index retained %d hostile keys", count)
	}
	if count := len(application.secretLocks); count != 0 {
		t.Fatalf("secret mutation index retained %d hostile keys", count)
	}
	if count := len(application.terminalLocks); count != 0 {
		t.Fatalf("terminal admission index retained %d hostile keys", count)
	}
}

func TestAuditNormalizesUnknownResultInsteadOfDroppingEvent(t *testing.T) {
	state := &fakeState{}
	application := &Application{deps: Dependencies{State: state, Clock: fixedClock{time.Unix(100, 0)}}}
	application.audit(
		httpapi.Principal{OwnerID: "owner", DeviceID: "device"}, "", "security.event", "misspelled",
		"session", "family", map[string]any{"metadata_only": true},
	)
	if len(state.audits) != 1 || state.audits[0].result != "failed" {
		t.Fatalf("normalized audit event = %#v", state.audits)
	}
	var details map[string]any
	if err := json.Unmarshal(state.audits[0].details, &details); err != nil {
		t.Fatal(err)
	}
	if details["audit_result_normalized"] != true || details["metadata_only"] != true {
		t.Fatalf("normalized audit details = %#v", details)
	}
}

func TestMutationGateRetainsIndexAcrossWaiters(t *testing.T) {
	application := &Application{mutationLocks: make(map[string]*mutationGate)}
	firstRelease := application.acquireWorkspaceMutation("workspace")
	secondAcquired := make(chan func(), 1)
	go func() {
		secondAcquired <- application.acquireWorkspaceMutation("workspace")
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		application.mutationMu.Lock()
		gate := application.mutationLocks["workspace"]
		refs := 0
		if gate != nil {
			refs = gate.refs
		}
		application.mutationMu.Unlock()
		if refs == 2 {
			break
		}
		if time.Now().After(deadline) {
			firstRelease()
			t.Fatal("second mutation waiter was not indexed")
		}
		time.Sleep(time.Millisecond)
	}

	select {
	case release := <-secondAcquired:
		release()
		firstRelease()
		t.Fatal("second mutation entered before the first released")
	default:
	}

	firstRelease()
	var secondRelease func()
	select {
	case secondRelease = <-secondAcquired:
	case <-time.After(2 * time.Second):
		t.Fatal("second mutation did not enter after the first released")
	}

	application.mutationMu.Lock()
	gate := application.mutationLocks["workspace"]
	if gate == nil || gate.refs != 1 {
		application.mutationMu.Unlock()
		secondRelease()
		t.Fatalf("mutation index split while a waiter held the gate: %#v", gate)
	}
	application.mutationMu.Unlock()

	secondRelease()
	application.mutationMu.Lock()
	defer application.mutationMu.Unlock()
	if _, retained := application.mutationLocks["workspace"]; retained {
		t.Fatal("mutation index retained a gate after the final release")
	}
}

func TestMutationGateCompositeKeysDoNotAlias(t *testing.T) {
	application := &Application{
		secretLocks:   make(map[string]*mutationGate),
		terminalLocks: make(map[string]*mutationGate),
	}

	releaseSecretA := application.acquireSecretMutation("a:b", "c")
	releaseSecretB := application.acquireSecretMutation("a", "b:c")
	releaseTerminalA := application.acquireTerminalAdmission("a:b", "c")
	releaseTerminalB := application.acquireTerminalAdmission("a", "b:c")

	application.mutationMu.Lock()
	if count := len(application.secretLocks); count != 2 {
		application.mutationMu.Unlock()
		t.Fatalf("secret mutation composite keys aliased: %d entries", count)
	}
	if count := len(application.terminalLocks); count != 2 {
		application.mutationMu.Unlock()
		t.Fatalf("terminal admission composite keys aliased: %d entries", count)
	}
	application.mutationMu.Unlock()

	releaseSecretA()
	releaseSecretB()
	releaseTerminalA()
	releaseTerminalB()
}
