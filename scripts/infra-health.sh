#!/bin/sh
set -eu

usage() {
  echo "usage: $0 [--smoke]" >&2
  exit 2
}

run_smoke=false
case "$#:$*" in
  0:) ;;
  1:--smoke) run_smoke=true ;;
  *) usage ;;
esac

[ "$(id -u)" -eq 0 ] || { echo "production health verification requires root" >&2; exit 1; }
repo_root=${REPO_ROOT:-/opt/codex-mobile/current}
env_file=${ENV_FILE:-/etc/codex-mobile/production.env}
podman_url=${PODMAN_URL:-unix:///run/codex-mobile-podman/podman.sock}

env_value() {
  awk -F= -v key="$1" '$1 == key {sub(/^[^=]*=/, ""); print; found=1} END {if (!found) exit 1}' "$env_file"
}

compose() {
  REPO_ROOT="$repo_root" ENV_FILE="$env_file" \
    /bin/sh "$repo_root/scripts/infra-compose.sh" "$@"
}

[ -r "$env_file" ] || { echo "missing environment file: $env_file" >&2; exit 1; }
[ -r "$repo_root/infra/compose.yaml" ] || { echo "missing deployed compose file" >&2; exit 1; }
[ -r "$repo_root/infra/release-manifest.json" ] || { echo "missing release manifest" >&2; exit 1; }

release=$(realpath "$repo_root")
release_root=${RELEASE_ROOT:-/opt/codex-mobile}
releases=$(realpath "$release_root/releases")
case "$release" in "$releases"/*) ;; *) echo "active release escapes immutable release root" >&2; exit 1 ;; esac

python3 "$repo_root/scripts/infra_release_manifest.py" verify \
  --repo-root "$repo_root" --require-images --verify-installed

for unit in \
  docker.service \
  codex-mobile-docker-firewall.service \
  codex-mobile-workspace-runtime.service \
  codex-mobile.service \
  codex-mobile-provisioner.service; do
  systemctl is-active --quiet "$unit" || {
    echo "required unit is not active: $unit" >&2
    systemctl status --no-pager "$unit" >&2 || true
    exit 1
  }
done

/usr/local/libexec/codex-mobile/verify-workspace-storage
/usr/local/libexec/codex-mobile/ensure-workspace-control-network --check
socket=/run/codex-mobile-podman/podman.sock
[ -S "$socket" ] || { echo "private workspace runtime socket is missing" >&2; exit 1; }
[ "$(stat -c '%U:%G:%a' "$socket")" = "root:coder-provisioner:660" ] || {
  echo "private workspace runtime socket owner/group/mode is invalid" >&2
  exit 1
}
podman --url "$podman_url" info >/dev/null

running=$(compose ps --status running --services | sort)
expected=$(printf '%s\n' caddy coder control-plane postgres | sort)
if [ "$running" != "$expected" ]; then
  echo "not every control-stack service is running" >&2
  compose ps >&2
  exit 1
fi

compose exec -T postgres pg_isready --quiet
compose exec -T caddy caddy validate --config /etc/caddy/Caddyfile >/dev/null

verify_container() {
  service=$1
  expected_reference=$2
  container=$(compose ps -q "$service")
  [ -n "$container" ] || { echo "$service container is missing" >&2; exit 1; }
  expected_image_id=$(docker image inspect --format '{{.Id}}' "$expected_reference")
  [ "$(docker inspect --format '{{.Image}}' "$container")" = "$expected_image_id" ] || {
    echo "$service running image ID does not match reviewed Compose provenance" >&2
    exit 1
  }
  [ "$(docker inspect --format '{{.State.Health.Status}}' "$container")" = healthy ] || {
    echo "$service container health status is not healthy" >&2
    exit 1
  }
}

release_id=$(awk -F= '$1 == "RELEASE_ID" {print $2}' "$repo_root/infra/release.env")
verify_container postgres 'postgres:18.4-bookworm@sha256:1961f96e6029a02c3812d7cb329a3b03a3ac2bb067058dec17b0f5596aca9296'
verify_container coder 'ghcr.io/coder/coder:v2.34.6@sha256:0ac9c07e9ff18ea9fecb07c08da838a032352e2b95c5fcd3bf279297cff1808a'
verify_container caddy 'caddy:2.11.4-alpine@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648'
verify_container control-plane "localhost/codex-mobile/control-plane:$release_id"

control_container=$(compose ps -q control-plane)
running_control_image=$(docker inspect --format '{{.Image}}' "$control_container")
expected_control_image=$(python3 - "$repo_root/infra/release-manifest.json" <<'PY'
import json
import re
import sys

value = json.load(open(sys.argv[1], encoding="utf-8"))["images"]["control_plane"]["id"]
if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
    raise SystemExit("invalid control-plane image ID in release manifest")
print(value)
PY
)
[ "$running_control_image" = "$expected_control_image" ] || {
  echo "running control-plane image does not match active release manifest" >&2
  exit 1
}

provisioner_pid=$(systemctl show --property MainPID --value codex-mobile-provisioner.service)
case "$provisioner_pid" in ''|0|*[!0-9]*) echo "provisioner has no live main process" >&2; exit 1 ;; esac
[ -r "/proc/$provisioner_pid/status" ] || { echo "provisioner process disappeared" >&2; exit 1; }
provisioner_metrics=$(curl --fail --silent --show-error --max-time 10 \
  --max-filesize 1048576 http://127.0.0.1:2113/metrics)
printf '%s\n' "$provisioner_metrics" | grep -q '^go_build_info'
python3 "$repo_root/scripts/infra_check_provisioner.py" --env-file "$env_file"

public_health_url=$(env_value PUBLIC_HEALTH_URL)
coder_access_url=$(env_value CODER_ACCESS_URL)
app_env=$(env_value APP_ENV)
curl --fail --silent --show-error --max-time 10 "$coder_access_url/healthz" >/dev/null

if [ "$app_env" = production ]; then
  case "$public_health_url" in https://*) ;; *) echo "production health URL must use HTTPS" >&2; exit 1 ;; esac
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 --max-time 15 \
    "$public_health_url" >/dev/null
else
  curl --fail --silent --show-error --max-time 15 "$public_health_url" >/dev/null
fi

if [ "$run_smoke" = true ]; then
  REPO_ROOT="$repo_root" PODMAN_URL="$podman_url" \
    /bin/sh "$repo_root/scripts/infra-smoke.sh" \
      --confirm=CREATE-DISPOSABLE-RUNTIME-SMOKE
fi

echo "infrastructure health: PASS ($(basename "$release"))"
