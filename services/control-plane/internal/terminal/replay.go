package terminal

import (
	"errors"
	"sync"
)

type Replay struct {
	Frames           []Frame
	Gap              bool
	EarliestSequence uint64
	LatestSequence   uint64
}

type Ring struct {
	mu        sync.RWMutex
	tabID     TabID
	frames    []Frame
	bytes     int
	maxFrames int
	maxBytes  int
	next      uint64
}

func NewRing(tabID TabID, maxFrames, maxBytes int) (*Ring, error) {
	if tabID.IsZero() || maxFrames < 1 || maxBytes < 1 || maxBytes > 64*MaxPayload {
		return nil, errors.New("invalid replay ring configuration")
	}
	return &Ring{tabID: tabID, maxFrames: maxFrames, maxBytes: maxBytes, next: 1}, nil
}

func (r *Ring) Append(payload []byte) (Frame, error) {
	if len(payload) > MaxPayload {
		return Frame{}, errors.New("terminal output frame too large")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	frame := Frame{Kind: KindOutput, Sequence: r.next, TabID: r.tabID, Payload: append([]byte(nil), payload...)}
	r.next++
	r.frames = append(r.frames, frame)
	r.bytes += len(payload)
	for len(r.frames) > r.maxFrames || (r.bytes > r.maxBytes && len(r.frames) > 1) {
		r.bytes -= len(r.frames[0].Payload)
		r.frames[0].Payload = nil
		r.frames = r.frames[1:]
	}
	return frame, nil
}

func (r *Ring) After(sequence uint64) Replay {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := Replay{LatestSequence: r.next - 1}
	if len(r.frames) == 0 {
		if sequence > result.LatestSequence {
			// The client cursor came from an earlier gateway generation. Announce
			// the next coherent sequence even though there is nothing to replay yet.
			result.Gap = true
			result.EarliestSequence = r.next
		}
		return result
	}
	result.EarliestSequence = r.frames[0].Sequence
	startSequence := sequence
	if sequence < result.EarliestSequence-1 || sequence > result.LatestSequence {
		result.Gap = true
		// A gap is a reset boundary, not an empty replay. Return the complete
		// retained window so a client can clear its renderer/history and rebuild
		// a coherent view beginning at EarliestSequence.
		startSequence = result.EarliestSequence - 1
	}
	for _, frame := range r.frames {
		if frame.Sequence > startSequence {
			copyFrame := frame
			copyFrame.Payload = append([]byte(nil), frame.Payload...)
			result.Frames = append(result.Frames, copyFrame)
		}
	}
	return result
}
