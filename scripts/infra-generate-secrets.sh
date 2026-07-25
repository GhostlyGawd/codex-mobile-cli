#!/bin/sh
set -eu

usage() {
  echo "usage: $0 --secrets-dir ABSOLUTE_PATH [--app-db-user USER] [--app-db-name NAME]" >&2
  exit 2
}

secrets_dir=
app_db_user=codex_app
app_db_name=codex_app
while [ "$#" -gt 0 ]; do
  case "$1" in
    --secrets-dir) [ "$#" -ge 2 ] || usage; secrets_dir=$2; shift 2 ;;
    --app-db-user) [ "$#" -ge 2 ] || usage; app_db_user=$2; shift 2 ;;
    --app-db-name) [ "$#" -ge 2 ] || usage; app_db_name=$2; shift 2 ;;
    *) usage ;;
  esac
done

case "$secrets_dir" in
  /*) ;;
  *) echo "--secrets-dir must be absolute" >&2; exit 1 ;;
esac
case "$secrets_dir" in
  *..*) echo "--secrets-dir cannot contain '..'" >&2; exit 1 ;;
esac
for identifier in "$app_db_user" "$app_db_name"; do
  if ! printf '%s' "$identifier" | grep -Eq '^[a-z][a-z0-9_]{0,62}$'; then
    echo "database identifiers must be lowercase letters, digits, and underscores" >&2
    exit 1
  fi
done
command -v openssl >/dev/null 2>&1 || { echo "openssl is required" >&2; exit 1; }

umask 077
mkdir -p "$secrets_dir"
chmod 0700 "$secrets_dir"

for name in postgres_admin_password app_db_password coder_db_password app_database_url control_plane_master_key session_pepper; do
  if [ -e "$secrets_dir/$name" ]; then
    echo "refusing to overwrite existing $secrets_dir/$name" >&2
    exit 1
  fi
done

postgres_admin_password=$(openssl rand -hex 32)
app_db_password=$(openssl rand -hex 32)
coder_db_password=$(openssl rand -hex 32)
# The Go service accepts exactly 32 raw bytes or their standard base64
# encoding. Text encoding avoids accidental trimming of random binary
# whitespace by Docker-secret readers.
control_plane_master_key=$(openssl rand -base64 32)
session_pepper=$(openssl rand -base64 32)

printf '%s\n' "$postgres_admin_password" > "$secrets_dir/postgres_admin_password"
printf '%s\n' "$app_db_password" > "$secrets_dir/app_db_password"
printf '%s\n' "$coder_db_password" > "$secrets_dir/coder_db_password"
printf 'postgresql://%s:%s@postgres:5432/%s?sslmode=disable\n' \
  "$app_db_user" "$app_db_password" "$app_db_name" > "$secrets_dir/app_database_url"
printf '%s\n' "$control_plane_master_key" > "$secrets_dir/control_plane_master_key"
printf '%s\n' "$session_pepper" > "$secrets_dir/session_pepper"
# Docker Compose implements local file-backed secrets as read-only bind mounts
# and does not remap their ownership for a non-root container.  Keep the
# containing directory root-owned/mode-0700 in production, while making each
# bind-mounted inode readable after Docker places it at /run/secrets.
chmod 0444 "$secrets_dir"/*

echo "Generated local database and control-plane secrets in $secrets_dir."
echo "Coder bootstrap is intentionally separate: create scoped Coder API and provisioner keys,"
echo "then write them as mode-0444 coder_api_token and coder_provisioner_key files."
echo "Owner-created GitHub/APNs credentials are never generated here; when enabled, add the"
echo "exact mode-0444 filenames documented in infra/env/production.env.example."
