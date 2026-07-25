package codex

import (
	"bytes"
	"sync"
)

type EventKind string

const (
	EventNeedsAttention EventKind = "needs_attention"
	EventTurnComplete   EventKind = "turn_complete"
)

type Event struct {
	Kind             EventKind
	GenericSummary   string
	StructuredDetail bool
}

type EventProvider interface {
	Observe(output []byte) []Event
	Structured() bool
}

// OSC9Provider parses only notification boundaries and deliberately discards
// terminal-derived content. The owner must inspect the authenticated live TUI.
type OSC9Provider struct {
	mu      sync.Mutex
	pending []byte
}

func (p *OSC9Provider) Structured() bool { return false }

func (p *OSC9Provider) Observe(output []byte) []Event {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pending = append(p.pending, output...)
	if len(p.pending) > 64<<10 {
		p.pending = append([]byte(nil), p.pending[len(p.pending)-(64<<10):]...)
	}
	events := make([]Event, 0)
	for {
		start := bytes.Index(p.pending, []byte{0x1b, ']', '9', ';'})
		if start < 0 {
			if len(p.pending) > 3 {
				p.pending = append([]byte(nil), p.pending[len(p.pending)-3:]...)
			}
			break
		}
		end, terminator := notificationEnd(p.pending[start+4:])
		if end < 0 {
			p.pending = append([]byte(nil), p.pending[start:]...)
			break
		}
		// Codex deliberately renders human-readable notification text into OSC 9,
		// not a machine-readable event discriminator. The text may contain model
		// output, commands, paths, or repository-controlled content, so it must
		// never be scraped to infer an approval or completion. A recognized OSC 9
		// boundary from a trusted Codex terminal is therefore only a generic
		// attention signal. The optional app-server adapter is the only place that
		// may later produce a typed completion event.
		events = append(events, Event{Kind: EventNeedsAttention, GenericSummary: "A session needs attention."})
		p.pending = append([]byte(nil), p.pending[start+4+end+terminator:]...)
	}
	return events
}

func notificationEnd(input []byte) (int, int) {
	for i := 0; i < len(input); i++ {
		if input[i] == 0x07 {
			return i, 1
		}
		if input[i] == 0x1b && i+1 < len(input) && input[i+1] == '\\' {
			return i, 2
		}
	}
	return -1, 0
}

type AppServerProvider struct {
	enabled bool
}

func NewAppServerProvider(enabled bool) *AppServerProvider {
	return &AppServerProvider{enabled: enabled}
}
func (p *AppServerProvider) Structured() bool       { return p.enabled }
func (p *AppServerProvider) Observe([]byte) []Event { return nil }
