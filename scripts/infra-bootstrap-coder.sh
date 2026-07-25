#!/bin/sh
set -eu

repo_root=${REPO_ROOT:-$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)}
env_file=${ENV_FILE:-/etc/codex-mobile/production.env}

if [ ! -f "$env_file" ]; then
  echo "missing environment file: $env_file" >&2
  exit 1
fi

python3 "$repo_root/scripts/infra-preflight.py" \
  --env-file "$env_file" --repo-root "$repo_root" --skip-secret-files --coder-bootstrap || {
    echo "Static production settings must pass before Coder bootstrap." >&2
    exit 1
  }

github_enabled=$(awk -F= '$1 == "GITHUB_ENABLED" {sub(/^[^=]*=/, ""); print}' "$env_file")
apns_enabled=$(awk -F= '$1 == "APNS_ENABLED" {sub(/^[^=]*=/, ""); print}' "$env_file")
if [ "$github_enabled" != false ] || [ "$apns_enabled" != false ]; then
  echo "Coder bootstrap requires GITHUB_ENABLED=false and APNS_ENABLED=false." >&2
  echo "Enable owner integrations only after Coder bootstrap and secret installation." >&2
  exit 1
fi

# Only the local database and private Coder listener are started. The public
# control plane remains unavailable until its scoped token and master key pass
# the full deployment preflight. Optional integration overrides remain disabled.
REPO_ROOT="$repo_root" ENV_FILE="$env_file" \
  /bin/sh "$repo_root/scripts/infra-compose.sh" \
  up --detach postgres coder --wait --wait-timeout 180

echo "Coder bootstrap services are healthy on the configured private/loopback address."
echo "Use an SSH tunnel for the initial owner login. Create:"
echo "  1. a control-plane token limited to the required Coder API operations;"
echo "  2. an external provisioner key tagged runtime=private-podman."
echo "Write them to SECRETS_DIR/coder_api_token and SECRETS_DIR/coder_provisioner_key"
echo "with root:root ownership and mode 0444 beneath the root-only 0700 directory,"
echo "then run the normal deployment. No token is printed by this script."
