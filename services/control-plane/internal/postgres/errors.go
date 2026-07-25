package postgres

import (
	"errors"
	"fmt"

	"github.com/GhostlyGawd/codex-mobile-cli/services/control-plane/internal/core"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func mapError(operation string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%s: %w", operation, core.ErrNotFound)
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		switch postgresError.Code {
		case "23505":
			return fmt.Errorf("%s: %w", operation, core.ErrConflict)
		case "23503":
			return fmt.Errorf("%s: %w", operation, core.ErrPrecondition)
		case "22001", "22003", "22P02", "23502", "23514":
			return fmt.Errorf("%s: %w", operation, core.ErrInvalid)
		}
	}
	return fmt.Errorf("%s: %w", operation, err)
}
