package postgres

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/session"
)

func TestScanSessionRecord(t *testing.T) {
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	hash := bytes.Repeat([]byte{0x7a}, 32)
	record, err := scanSessionRecord(valuesRow{
		"token-1", "family-1", "owner-1", "device-1", "refresh", hash,
		now, now.Add(time.Hour), nil, nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	if record.Kind != session.Refresh || !bytes.Equal(record.Hash[:], hash) || record.FamilyID != "family-1" {
		t.Fatalf("unexpected session mapping: %#v", record)
	}
	if _, err := scanSessionRecord(valuesRow{
		"token-1", "family-1", "owner-1", "device-1", "refresh", []byte{1},
		now, now.Add(time.Hour), nil, nil,
	}); err == nil {
		t.Fatal("accepted an invalid stored token hash")
	}
}

func TestValidateSessionPairRejectsIdentityMismatch(t *testing.T) {
	now := time.Now().UTC()
	access := session.Record{ID: "a", FamilyID: "family", OwnerID: "owner", DeviceID: "device", Kind: session.Access, CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	refresh := session.Record{ID: "r", FamilyID: "family", OwnerID: "other", DeviceID: "device", Kind: session.Refresh, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := validateSessionPair(access, refresh); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("expected invalid pair, got %v", err)
	}
}
