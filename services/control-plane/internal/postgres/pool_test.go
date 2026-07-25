package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestApplyPoolDefaultsIsBounded(t *testing.T) {
	config, err := pgxpool.ParseConfig("postgres://user:password@127.0.0.1/database")
	if err != nil {
		t.Fatal(err)
	}
	applyPoolDefaults(config, PoolConfig{SearchPath: "test_schema"})
	if config.MaxConns != 16 || config.MinConns != 0 {
		t.Fatalf("unexpected default pool bounds: min=%d max=%d", config.MinConns, config.MaxConns)
	}
	if config.MaxConnLifetime != 30*time.Minute || config.MaxConnIdleTime != 5*time.Minute {
		t.Fatalf("unexpected pool lifetimes: %#v", config)
	}
	if config.ConnConfig.RuntimeParams["search_path"] != "test_schema" {
		t.Fatal("search path was not installed")
	}
}

func TestOpenRejectsUnsafeSettingsBeforeConnecting(t *testing.T) {
	for _, settings := range []PoolConfig{
		{URL: "postgres://user:password@127.0.0.1/database", SearchPath: "public, attacker"},
		{URL: "postgres://user:password@127.0.0.1/database", ApplicationName: strings.Repeat("x", 64)},
		{URL: "postgres://user:password@127.0.0.1/database", MinConns: 3, MaxConns: 2},
	} {
		if pool, err := Open(context.Background(), settings); err == nil {
			pool.Close()
			t.Fatal("expected invalid pool settings to fail")
		}
	}
}

func TestMapErrorRedactsPostgresDetailsAndClassifies(t *testing.T) {
	err := mapError("insert", &pgconn.PgError{Code: "23505", ConstraintName: "secret_internal_name"})
	if !errors.Is(err, core.ErrConflict) || strings.Contains(err.Error(), "secret_internal_name") {
		t.Fatalf("unexpected mapped error: %v", err)
	}
	err = mapError("lookup", errors.New("network unavailable"))
	if err == nil || !strings.Contains(err.Error(), "network unavailable") {
		t.Fatalf("unexpected generic error: %v", err)
	}
}
