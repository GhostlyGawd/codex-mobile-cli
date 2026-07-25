package checkpoint

import (
	"fmt"
	"testing"
	"time"
)

func TestOperationGateIndexReleasesWorkspaceKeys(t *testing.T) {
	service := &Service{operations: make(map[string]*operationGate)}
	for index := 0; index < 10_000; index++ {
		release := service.acquireOperation(fmt.Sprintf("deleted-workspace-%d", index))
		release()
	}
	service.operationMu.Lock()
	defer service.operationMu.Unlock()
	if count := len(service.operations); count != 0 {
		t.Fatalf("checkpoint operation index retained %d workspace keys", count)
	}
}

func TestOperationGateDoesNotSplitAcrossWaiters(t *testing.T) {
	service := &Service{operations: make(map[string]*operationGate)}
	firstRelease := service.acquireOperation("workspace")
	secondAcquired := make(chan func(), 1)
	go func() { secondAcquired <- service.acquireOperation("workspace") }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		service.operationMu.Lock()
		gate := service.operations["workspace"]
		refs := 0
		if gate != nil {
			refs = gate.refs
		}
		service.operationMu.Unlock()
		if refs == 2 {
			break
		}
		if time.Now().After(deadline) {
			firstRelease()
			t.Fatal("checkpoint waiter was not indexed")
		}
		time.Sleep(time.Millisecond)
	}

	select {
	case release := <-secondAcquired:
		release()
		firstRelease()
		t.Fatal("checkpoint operations for one workspace overlapped")
	default:
	}
	firstRelease()

	var secondRelease func()
	select {
	case secondRelease = <-secondAcquired:
	case <-time.After(2 * time.Second):
		t.Fatal("checkpoint waiter did not acquire after release")
	}
	service.operationMu.Lock()
	gate := service.operations["workspace"]
	if gate == nil || gate.refs != 1 {
		service.operationMu.Unlock()
		secondRelease()
		t.Fatalf("checkpoint operation index split across a waiter: %#v", gate)
	}
	service.operationMu.Unlock()
	secondRelease()

	service.operationMu.Lock()
	defer service.operationMu.Unlock()
	if _, retained := service.operations["workspace"]; retained {
		t.Fatal("checkpoint operation index retained the final gate")
	}
}
