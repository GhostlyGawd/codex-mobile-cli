package terminal

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func testTabID() TabID {
	var id TabID
	for i := range id {
		id[i] = byte(i + 1)
	}
	return id
}

func TestFrameRoundTrip(t *testing.T) {
	t.Parallel()
	size, _ := (Size{Rows: 24, Columns: 80, WidthPixels: 640, HeightPixels: 480}).MarshalBinary()
	want := Frame{Kind: KindResize, TabID: testTabID(), Payload: size}
	b, err := want.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseFrame(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != want.Kind || got.Sequence != want.Sequence || got.TabID != want.TabID || !bytes.Equal(got.Payload, want.Payload) {
		t.Fatalf("round trip = %#v, want %#v", got, want)
	}
}

func TestIdempotentInputAndReceiptRoundTrip(t *testing.T) {
	t.Parallel()
	frames := []Frame{
		{Kind: KindInput, Flags: FlagIdempotentInput, Sequence: 42, TabID: testTabID(), Payload: []byte("command\n")},
		{Kind: KindAck, Flags: FlagInputReceipt, Sequence: 42, TabID: testTabID()},
		{Kind: KindAck, Flags: FlagInputReceiptConfirmed, Sequence: 42, TabID: testTabID()},
	}
	for _, want := range frames {
		data, err := want.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseFrame(data)
		if err != nil {
			t.Fatal(err)
		}
		if got.Kind != want.Kind || got.Flags != want.Flags || got.Sequence != want.Sequence || got.TabID != want.TabID || !bytes.Equal(got.Payload, want.Payload) {
			t.Fatalf("round trip = %#v, want %#v", got, want)
		}
	}
}

func TestIdempotentInputAndReceiptRequireSequence(t *testing.T) {
	t.Parallel()
	for _, frame := range []Frame{
		{Kind: KindInput, Flags: FlagIdempotentInput, TabID: testTabID(), Payload: []byte("x")},
		{Kind: KindAck, Flags: FlagInputReceipt, TabID: testTabID()},
		{Kind: KindAck, Flags: FlagInputReceiptConfirmed, TabID: testTabID()},
		{Kind: KindAck, Flags: FlagInputReceipt | FlagInputReceiptConfirmed, Sequence: 42, TabID: testTabID()},
		{Kind: KindInput, Sequence: 42, TabID: testTabID(), Payload: []byte("x")},
	} {
		if _, err := frame.MarshalBinary(); err == nil {
			t.Fatalf("invalid frame accepted: %#v", frame)
		}
	}
}

func TestFrameRejectsLengthAndFlags(t *testing.T) {
	t.Parallel()
	b, _ := (Frame{Kind: KindInput, TabID: testTabID(), Payload: []byte("x")}).MarshalBinary()
	if _, err := ParseFrame(b[:len(b)-1]); err == nil {
		t.Fatal("truncated frame accepted")
	}
	b, _ = (Frame{Kind: KindLeaseRequest, Flags: FlagTakeLease, TabID: testTabID(), Payload: []byte("device")}).MarshalBinary()
	b[4], b[5] = 0x80, 0
	if _, err := ParseFrame(b); err == nil {
		t.Fatal("unknown flag accepted")
	}
}

func TestReplayGapIsExplicit(t *testing.T) {
	t.Parallel()
	ring, _ := NewRing(testTabID(), 2, 1024)
	for _, text := range []string{"one", "two", "three"} {
		_, _ = ring.Append([]byte(text))
	}
	replay := ring.After(0)
	if !replay.Gap || replay.EarliestSequence != 2 || len(replay.Frames) != 2 || replay.Frames[0].Sequence != 2 {
		t.Fatalf("unexpected gap replay: %#v", replay)
	}
	replay = ring.After(1)
	if replay.Gap || len(replay.Frames) != 2 || replay.Frames[0].Sequence != 2 {
		t.Fatalf("unexpected retained replay: %#v", replay)
	}
}

func TestReplayCursorFromEarlierGatewayGenerationForcesReset(t *testing.T) {
	t.Parallel()
	ring, _ := NewRing(testTabID(), 2, 1024)
	replay := ring.After(99)
	if !replay.Gap || replay.EarliestSequence != 1 || replay.LatestSequence != 0 || len(replay.Frames) != 0 {
		t.Fatalf("unexpected empty-generation reset: %#v", replay)
	}
	_, _ = ring.Append([]byte("new generation"))
	replay = ring.After(99)
	if !replay.Gap || replay.EarliestSequence != 1 || replay.LatestSequence != 1 || len(replay.Frames) != 1 || replay.Frames[0].Sequence != 1 {
		t.Fatalf("unexpected populated-generation reset: %#v", replay)
	}
}

func TestLeaseRequiresExplicitTakeover(t *testing.T) {
	t.Parallel()
	m, _ := NewLeaseManager(30 * time.Second)
	now := time.Now()
	if _, err := m.Request("device-a", false, now); err != nil {
		t.Fatal(err)
	}
	denied, err := m.Request("device-b", false, now)
	if !errors.Is(err, ErrLeaseHeld) || denied.Lease.DeviceID != "device-a" {
		t.Fatalf("denied = %#v, %v", denied, err)
	}
	taken, err := m.Request("device-b", true, now)
	if err != nil || taken.Displaced != "device-a" || taken.Lease.DeviceID != "device-b" {
		t.Fatalf("taken = %#v, %v", taken, err)
	}
}

func TestLeaseExpires(t *testing.T) {
	t.Parallel()
	m, _ := NewLeaseManager(5 * time.Second)
	now := time.Now()
	_, _ = m.Request("device-a", false, now)
	granted, err := m.Request("device-b", false, now.Add(6*time.Second))
	if err != nil || granted.Lease.DeviceID != "device-b" {
		t.Fatalf("granted = %#v, %v", granted, err)
	}
}
