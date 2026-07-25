# PostgreSQL migrations

These migrations are forward-only. Each filename starts with a monotonically increasing version and ends in `.up.sql`. The migration runner applies files in version order, records their SHA-256 checksums in `schema_migrations`, rejects a changed checksum, and serializes concurrent runners with a PostgreSQL advisory lock.

Do not add down migrations. Roll back application code only when it remains compatible with the migrated schema; otherwise restore the database backup and deploy a new forward-fix migration.

## Apply

From `services/control-plane`:

```powershell
$env:DATABASE_URL = 'postgres://codex_app:REDACTED@127.0.0.1:5432/codex_app?sslmode=disable'
go run ./migrations/cmd/migrate
```

The command never prints the connection string. Production credentials should come from the root-readable secret file/environment arrangement documented by deployment operations, not from a committed `.env` file.

## Add a migration

1. Choose the next six-digit version.
2. Create only `NNNNNN_descriptive_name.up.sql`.
3. Make the migration safe to execute inside a transaction.
4. Never edit a migration whose checksum has reached any shared environment; add a new forward migration instead.
5. Run the unit and Docker-gated integration tests.

## Docker-gated integration test

Start a disposable local database:

```powershell
docker run --rm --name codex-mobile-postgres-test `
  -e POSTGRES_USER=codex_test `
  -e POSTGRES_PASSWORD=codex_test `
  -e POSTGRES_DB=codex_test `
  -p 55432:5432 postgres:17-alpine
```

In a second shell, from `services/control-plane`:

```powershell
$env:POSTGRES_TEST_DSN = 'postgres://codex_test:codex_test@127.0.0.1:55432/codex_test?sslmode=disable'
go test -tags=integration ./internal/postgres -run TestIntegrationPersistence -count=1
```

The integration test creates and drops an isolated schema. Stop the disposable container with `Ctrl+C` when the test completes.
