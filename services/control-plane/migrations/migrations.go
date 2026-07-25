package migrations

import (
	"context"
	"embed"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Files contains only forward migrations. Down migrations are deliberately not
// shipped because production rollback is restore-plus-forward-fix.
//
//go:embed *.up.sql
var Files embed.FS

// Apply applies all embedded migrations in version order.
func Apply(ctx context.Context, pool *pgxpool.Pool) error {
	return postgres.ApplyMigrations(ctx, pool, Files, ".")
}
