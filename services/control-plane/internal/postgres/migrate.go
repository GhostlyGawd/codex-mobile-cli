package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const migrationLockKey int64 = 0x434d4f42494c45

const schemaMigrationsDDL = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version bigint PRIMARY KEY,
    name text NOT NULL UNIQUE,
    checksum bytea NOT NULL CHECK (octet_length(checksum) = 32),
    applied_at timestamptz NOT NULL DEFAULT now()
)`

var migrationNamePattern = regexp.MustCompile(`^(\d{6})_([a-z0-9_]+)\.up\.sql$`)

type migration struct {
	version  int64
	name     string
	sql      string
	checksum [32]byte
}

// ApplyMigrations applies immutable forward migrations from fsys. Applied
// versions are checksum-verified and concurrent runners are serialized.
func ApplyMigrations(ctx context.Context, pool *pgxpool.Pool, fsys fs.FS, directory string) error {
	if ctx == nil || pool == nil || fsys == nil {
		return errors.New("migration context, pool, and filesystem are required")
	}
	migrations, err := loadMigrations(fsys, directory)
	if err != nil {
		return err
	}
	connection, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}
	defer connection.Release()
	if _, err := connection.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationLockKey); err != nil {
		return fmt.Errorf("lock migrations: %w", err)
	}
	defer func() {
		_, _ = connection.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, migrationLockKey)
	}()
	if _, err := connection.Exec(ctx, schemaMigrationsDDL); err != nil {
		return fmt.Errorf("ensure migration versioning: %w", err)
	}
	for _, item := range migrations {
		if err := applyMigration(ctx, connection, item); err != nil {
			return err
		}
	}
	return nil
}

type migrationConnection interface {
	Begin(context.Context) (pgx.Tx, error)
}

func applyMigration(ctx context.Context, connection migrationConnection, item migration) error {
	tx, err := connection.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin migration %s: %w", item.name, err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var appliedName string
	var appliedChecksum []byte
	err = tx.QueryRow(ctx, `SELECT name, checksum FROM schema_migrations WHERE version = $1`, item.version).Scan(&appliedName, &appliedChecksum)
	switch {
	case err == nil:
		if appliedName != item.name {
			return fmt.Errorf("migration %06d name changed", item.version)
		}
		if !bytes.Equal(appliedChecksum, item.checksum[:]) {
			return fmt.Errorf("migration %06d checksum changed", item.version)
		}
		return nil
	case !errors.Is(err, pgx.ErrNoRows):
		return fmt.Errorf("read migration %06d: %w", item.version, err)
	}
	if _, err := tx.Exec(ctx, item.sql); err != nil {
		return fmt.Errorf("execute migration %s: %w", item.name, err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)`,
		item.version, item.name, item.checksum[:],
	); err != nil {
		return fmt.Errorf("record migration %s: %w", item.name, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit migration %s: %w", item.name, err)
	}
	return nil
}

func loadMigrations(fsys fs.FS, directory string) ([]migration, error) {
	if strings.TrimSpace(directory) == "" {
		directory = "."
	}
	entries, err := fs.ReadDir(fsys, directory)
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}
	items := make([]migration, 0)
	seen := make(map[int64]string)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.HasSuffix(entry.Name(), ".down.sql") {
			return nil, fmt.Errorf("down migration %q is not allowed", entry.Name())
		}
		if !strings.HasSuffix(entry.Name(), ".up.sql") {
			continue
		}
		matches := migrationNamePattern.FindStringSubmatch(entry.Name())
		if matches == nil {
			return nil, fmt.Errorf("invalid forward migration filename %q", entry.Name())
		}
		version, err := strconv.ParseInt(matches[1], 10, 64)
		if err != nil || version <= 0 {
			return nil, fmt.Errorf("invalid migration version in %q", entry.Name())
		}
		if previous, exists := seen[version]; exists {
			return nil, fmt.Errorf("migration version %06d used by %q and %q", version, previous, entry.Name())
		}
		path := entry.Name()
		if directory != "." {
			path = strings.TrimSuffix(directory, "/") + "/" + entry.Name()
		}
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return nil, fmt.Errorf("read migration %q: %w", entry.Name(), err)
		}
		if len(bytes.TrimSpace(data)) == 0 {
			return nil, fmt.Errorf("migration %q is empty", entry.Name())
		}
		seen[version] = entry.Name()
		items = append(items, migration{version: version, name: entry.Name(), sql: string(data), checksum: sha256.Sum256(data)})
	}
	if len(items) == 0 {
		return nil, errors.New("no forward migrations found")
	}
	sort.Slice(items, func(i, j int) bool { return items[i].version < items[j].version })
	return items, nil
}
