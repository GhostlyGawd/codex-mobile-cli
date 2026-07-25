package terminal

import "sync"

// connectionMutationGate linearizes state-changing frames with device and tab
// revocation. A gate belongs to exactly one admitted connection, so its memory
// is bounded by the subscriber caps and disappears with that connection.
//
// begin and revoke serialize through mu. Once revoke wins, no later mutation
// can start. revoke returns a channel that closes only after every mutation
// which began earlier has left the gate.
type connectionMutationGate struct {
	mu       sync.Mutex
	revoked  bool
	inFlight uint32
	drained  chan struct{}
}

func newConnectionMutationGate() *connectionMutationGate {
	return &connectionMutationGate{drained: make(chan struct{})}
}

func (g *connectionMutationGate) begin() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.revoked {
		return false
	}
	g.inFlight++
	return true
}

func (g *connectionMutationGate) end() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.inFlight == 0 {
		panic("terminal mutation gate ended without admission")
	}
	g.inFlight--
	if g.revoked && g.inFlight == 0 {
		close(g.drained)
	}
}

func (g *connectionMutationGate) revoke() <-chan struct{} {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.revoked {
		g.revoked = true
		if g.inFlight == 0 {
			close(g.drained)
		}
	}
	return g.drained
}

func waitForConnectionDrains(drains []<-chan struct{}) {
	for _, drained := range drains {
		<-drained
	}
}

// connectionDeliveryGate linearizes every WebSocket write with revocation.
// Once revoke wins, no later replay, response, output, or attention write can
// begin. revoke's drain closes only after a write admitted earlier completes.
type connectionDeliveryGate struct {
	mu       sync.Mutex
	revoked  bool
	inFlight uint32
	drained  chan struct{}
}

func newConnectionDeliveryGate() *connectionDeliveryGate {
	return &connectionDeliveryGate{drained: make(chan struct{})}
}

func (g *connectionDeliveryGate) begin() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.revoked {
		return false
	}
	g.inFlight++
	return true
}

func (g *connectionDeliveryGate) end() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.inFlight == 0 {
		panic("terminal delivery gate ended without admission")
	}
	g.inFlight--
	if g.revoked && g.inFlight == 0 {
		close(g.drained)
	}
}

func (g *connectionDeliveryGate) revoke() <-chan struct{} {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.revoked {
		g.revoked = true
		if g.inFlight == 0 {
			close(g.drained)
		}
	}
	return g.drained
}
