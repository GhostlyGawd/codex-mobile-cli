//go:build integration

package postgres

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/vault"
)

func TestMasterKeyRotatorRefusesWhileServeLeaseExists(t *testing.T) {
	dsn := os.Getenv("POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_TEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := Open(ctx, PoolConfig{URL: dsn, ApplicationName: "codex-mobile-rotation-lock-test", MaxConns: 3})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	lease, err := AcquireServeLease(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	current, _ := vault.New(bytes.Repeat([]byte{0x61}, 32))
	rotator, err := NewMasterKeyRotator(pool, current)
	if err != nil {
		t.Fatal(err)
	}
	_, err = rotator.Rotate(ctx, bytes.Repeat([]byte{0x62}, 32), time.Now().UTC())
	if !errors.Is(err, ErrServeProcessesActive) {
		t.Fatalf("rotation with active serve lease = %v", err)
	}
}
