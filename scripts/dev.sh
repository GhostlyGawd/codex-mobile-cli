#!/usr/bin/env sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
env_file=${ENV_FILE:-$repo_root/.codex-mobile-development.env}
secrets_dir=$repo_root/.secrets
data_root=$repo_root/.data

command -v docker >/dev/null 2>&1 || {
  echo "Docker with Compose v2 is required for the local integration stack." >&2
  exit 1
}
docker compose version >/dev/null 2>&1 || {
  echo "Docker Compose v2 is required." >&2
  exit 1
}

if [ ! -e "$env_file" ]; then
  cp "$repo_root/infra/env/development.env.example" "$env_file"
  echo "Created ignored local configuration: $env_file"
fi
case "$env_file" in "$repo_root"/*) ;; *) echo "ENV_FILE must stay beneath the repository for local development" >&2; exit 1 ;; esac

mkdir -p "$data_root/postgres" "$data_root/coder" "$data_root/caddy/data" "$data_root/caddy/config"
if [ ! -d "$secrets_dir" ]; then
  /bin/sh "$repo_root/scripts/infra-generate-secrets.sh" --secrets-dir "$secrets_dir"
fi

# Coder's initial owner and scoped token require a human browser ceremony. The
# first invocation safely starts only its private dependencies and stops here.
if [ ! -s "$secrets_dir/coder_api_token" ]; then
  : > "$secrets_dir/coder_api_token"
  chmod 0600 "$secrets_dir/coder_api_token"
  REPO_ROOT="$repo_root" ENV_FILE="$env_file" \
    /bin/sh "$repo_root/scripts/infra-compose.sh" up --detach postgres coder --wait --wait-timeout 180
  echo "Coder is available at http://127.0.0.1:7080 for its one-time local owner setup."
  echo "Create a least-privilege API token, write only that token to:"
  echo "  $secrets_dir/coder_api_token"
  echo "Then set CODER_ORGANIZATION_ID and CODER_TEMPLATE_ID in $env_file and rerun this command."
  echo "This browser ceremony cannot be automated without creating or disclosing a password."
  exit 3
fi

# Local Compose file secrets are bind-mounted without uid remapping. The
# mode-0700 parent remains the host-side confidentiality boundary.
chmod 0444 "$secrets_dir"/*

REPO_ROOT="$repo_root" ENV_FILE="$env_file" \
  /bin/sh "$repo_root/scripts/infra-compose.sh" up --detach --build --wait --wait-timeout 300
REPO_ROOT="$repo_root" ENV_FILE="$env_file" \
  /bin/sh "$repo_root/scripts/infra-health.sh"
echo "Codex Mobile local stack is ready at http://localhost."
