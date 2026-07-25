package terminal

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	Version                   = 1
	HeaderSize                = 36
	MaxPayload                = 1024 * 1024
	FlagTakeLease             = 1 << 0
	FlagIdempotentInput       = 1 << 1
	FlagInputReceipt          = 1 << 2
	FlagInputReceiptConfirmed = 1 << 3
)

type Kind uint8

const (
	KindOutput       Kind = 1
	KindInput        Kind = 2
	KindAck          Kind = 3
	KindResize       Kind = 4
	KindPing         Kind = 5
	KindPong         Kind = 6
	KindReplayGap    Kind = 7
	KindLeaseRequest Kind = 8
	KindLeaseGranted Kind = 9
	KindLeaseDenied  Kind = 10
	KindTabClosed    Kind = 11
	KindAttention    Kind = 12
)

func (k Kind) Valid() bool { return k >= KindOutput && k <= KindAttention }

type TabID [16]byte

func (id TabID) IsZero() bool { return id == TabID{} }

type Frame struct {
	Kind     Kind
	Flags    uint16
	Sequence uint64
	TabID    TabID
	Payload  []byte
}

func (f Frame) MarshalBinary() ([]byte, error) {
	if !f.Kind.Valid() {
		return nil, errors.New("invalid terminal frame kind")
	}
	if len(f.Payload) > MaxPayload {
		return nil, fmt.Errorf("terminal payload exceeds %d bytes", MaxPayload)
	}
	if f.TabID.IsZero() && f.Kind != KindPing && f.Kind != KindPong {
		return nil, errors.New("tab ID is required")
	}
	if f.Kind == KindAck && len(f.Payload) != 0 {
		return nil, errors.New("ack payload must be empty")
	}
	if f.Kind == KindResize && len(f.Payload) != 8 {
		return nil, errors.New("resize payload must be 8 bytes")
	}
	if err := validateFlagsAndSequence(f); err != nil {
		return nil, err
	}
	out := make([]byte, HeaderSize+len(f.Payload))
	out[0], out[1] = 'C', 'M'
	out[2] = Version
	out[3] = byte(f.Kind)
	binary.BigEndian.PutUint16(out[4:6], f.Flags)
	binary.BigEndian.PutUint16(out[6:8], HeaderSize)
	binary.BigEndian.PutUint64(out[8:16], f.Sequence)
	copy(out[16:32], f.TabID[:])
	binary.BigEndian.PutUint32(out[32:36], uint32(len(f.Payload)))
	copy(out[HeaderSize:], f.Payload)
	return out, nil
}

func ParseFrame(data []byte) (Frame, error) {
	if len(data) < HeaderSize || data[0] != 'C' || data[1] != 'M' {
		return Frame{}, errors.New("invalid terminal frame header")
	}
	if data[2] != Version {
		return Frame{}, fmt.Errorf("unsupported terminal protocol version %d", data[2])
	}
	if binary.BigEndian.Uint16(data[6:8]) != HeaderSize {
		return Frame{}, errors.New("unsupported terminal header size")
	}
	payloadLength := int(binary.BigEndian.Uint32(data[32:36]))
	if payloadLength > MaxPayload || len(data) != HeaderSize+payloadLength {
		return Frame{}, errors.New("invalid terminal payload length")
	}
	frame := Frame{
		Kind:     Kind(data[3]),
		Flags:    binary.BigEndian.Uint16(data[4:6]),
		Sequence: binary.BigEndian.Uint64(data[8:16]),
		Payload:  append([]byte(nil), data[HeaderSize:]...),
	}
	copy(frame.TabID[:], data[16:32])
	if !frame.Kind.Valid() || (frame.TabID.IsZero() && frame.Kind != KindPing && frame.Kind != KindPong) {
		return Frame{}, errors.New("invalid terminal frame")
	}
	if err := validateFlagsAndSequence(frame); err != nil {
		return Frame{}, err
	}
	if frame.Kind == KindAck && len(frame.Payload) != 0 {
		return Frame{}, errors.New("ack payload must be empty")
	}
	if frame.Kind == KindResize && len(frame.Payload) != 8 {
		return Frame{}, errors.New("resize payload must be 8 bytes")
	}
	if (frame.Kind == KindPing || frame.Kind == KindPong) && len(frame.Payload) > 64 {
		return Frame{}, errors.New("ping payload exceeds 64 bytes")
	}
	return frame, nil
}

func validateFlagsAndSequence(frame Frame) error {
	var allowedFlags uint16
	switch frame.Kind {
	case KindLeaseRequest:
		allowedFlags = FlagTakeLease
	case KindInput:
		allowedFlags = FlagIdempotentInput
	case KindAck:
		allowedFlags = FlagInputReceipt | FlagInputReceiptConfirmed
	}
	if frame.Flags&^allowedFlags != 0 {
		return errors.New("unknown or invalid terminal flags")
	}
	switch frame.Kind {
	case KindOutput:
		if frame.Sequence == 0 {
			return errors.New("output sequence must be non-zero")
		}
	case KindInput:
		if frame.Flags&FlagIdempotentInput != 0 {
			if frame.Sequence == 0 {
				return errors.New("idempotent input sequence must be non-zero")
			}
		} else if frame.Sequence != 0 {
			return errors.New("unacknowledged input sequence must be zero")
		}
	case KindAck:
		if frame.Flags != 0 && frame.Flags != FlagInputReceipt && frame.Flags != FlagInputReceiptConfirmed {
			return errors.New("acknowledgement flags cannot be combined")
		}
		if frame.Flags != 0 && frame.Sequence == 0 {
			return errors.New("input receipt sequence must be non-zero")
		}
	case KindResize, KindLeaseRequest, KindLeaseGranted, KindLeaseDenied:
		if frame.Sequence != 0 {
			return errors.New("terminal control sequence must be zero")
		}
	case KindReplayGap:
		if frame.Sequence == 0 {
			return errors.New("replay gap sequence must be non-zero")
		}
	}
	return nil
}

type Size struct {
	Rows, Columns, WidthPixels, HeightPixels uint16
}

func (s Size) MarshalBinary() ([]byte, error) {
	if s.Rows == 0 || s.Columns == 0 {
		return nil, errors.New("terminal rows and columns must be non-zero")
	}
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[0:2], s.Rows)
	binary.BigEndian.PutUint16(b[2:4], s.Columns)
	binary.BigEndian.PutUint16(b[4:6], s.WidthPixels)
	binary.BigEndian.PutUint16(b[6:8], s.HeightPixels)
	return b, nil
}

func ParseSize(b []byte) (Size, error) {
	if len(b) != 8 {
		return Size{}, errors.New("terminal size must be 8 bytes")
	}
	s := Size{
		Rows: binary.BigEndian.Uint16(b[0:2]), Columns: binary.BigEndian.Uint16(b[2:4]),
		WidthPixels: binary.BigEndian.Uint16(b[4:6]), HeightPixels: binary.BigEndian.Uint16(b[6:8]),
	}
	if s.Rows == 0 || s.Columns == 0 {
		return Size{}, errors.New("terminal rows and columns must be non-zero")
	}
	return s, nil
}
