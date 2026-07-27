#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
HOME=/root
export PATH HOME
unset CDPATH ENV BASH_ENV PYTHONHOME PYTHONPATH PYTHONSTARTUP LD_LIBRARY_PATH LD_PRELOAD
unset DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG COMPOSE_FILE
unset CONTAINER_HOST CONTAINER_CONNECTION CONTAINERS_CONF CONTAINERS_STORAGE_CONF
unset CONTAINERS_REGISTRIES_CONF CONTAINERS_POLICY REGISTRY_AUTH_FILE XDG_CONFIG_HOME

usage() {
  echo "usage: $0 --confirm=CREATE-DISPOSABLE-RUNTIME-SMOKE" >&2
  exit 2
}

[ "$#" -eq 1 ] && [ "$1" = "--confirm=CREATE-DISPOSABLE-RUNTIME-SMOKE" ] || usage
[ "$(id -u)" -eq 0 ] || { echo "runtime smoke check requires root" >&2; exit 1; }

repo_root=${REPO_ROOT:-/opt/codex-mobile/current}
podman_url=${PODMAN_URL:-unix:///run/codex-mobile-podman/podman.sock}
env_file=${ENV_FILE:-/etc/codex-mobile/production.env}
release_id=$(awk -F= '$1 == "RELEASE_ID" {print $2}' "$repo_root/infra/release.env")
workspace_image=$(awk -F= '$1 == "WORKSPACE_BASE_IMAGE" {print $2}' "$repo_root/infra/release.env")
deployment_profile=$(awk -F= '$1 == "DEPLOYMENT_PROFILE" {print $2}' "$env_file")
case "$release_id" in sha-[0-9a-f]*) ;; *) echo "invalid release identity" >&2; exit 1 ;; esac
[ "$workspace_image" = "localhost/codex-mobile/workspace-base:$release_id" ] || {
  echo "workspace smoke image does not match active release" >&2
  exit 1
}

/usr/bin/python3 -I "$repo_root/scripts/infra_release_manifest.py" verify \
  --repo-root "$repo_root" --require-images --require-image-audit \
  --podman-url "$podman_url"

expected_helper=$(/usr/bin/python3 -I - "$repo_root/infra/release-manifest.json" <<'PY'
import json
import re
import sys

value = json.load(open(sys.argv[1], encoding="utf-8"))["workspace_helper_sha256"]
if not re.fullmatch(r"[0-9a-f]{64}", value):
    raise SystemExit("invalid helper checksum in release manifest")
print(value)
PY
)

suffix=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
case "$suffix" in ''|*[!0-9a-f]*) echo "failed to create smoke identifier" >&2; exit 1 ;; esac
name="cm-release-smoke-$suffix"
volume="$name-data"
cleanup() {
  /usr/bin/podman --url "$podman_url" rm --force "$name" >/dev/null 2>&1 || true
  /usr/bin/podman --url "$podman_url" volume rm --force "$volume" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

case "$deployment_profile" in
  owner_pc_beta)
    userns_opt='--userns auto:size=65536'
    volume_quota_opt=
    ;;
  fixed_price_vps)
    userns_opt=
    volume_quota_opt='--opt o=size=8388608'
    ;;
  *) echo "unsupported deployment profile for runtime smoke" >&2; exit 1 ;;
esac

/usr/bin/podman --url "$podman_url" info >/dev/null
# Podman 4.9.3 on owner_pc_beta assigns the same project ID to a second
# quota-bearing named volume, which could change a real workspace's limit.
# This image/helper smoke therefore uses a non-quota volume there; the
# profile-specific runtime spike verifies the existing leased volume instead.
# volume_quota_opt is either empty or the fixed-price profile's trusted literal.
# shellcheck disable=SC2086
/usr/bin/podman --url "$podman_url" volume create \
  --label com.codex-mobile.volume-role=release-smoke \
  $volume_quota_opt "$volume" >/dev/null

# shellcheck disable=SC2016 # The quoted expression executes inside the container.
# userns_opt is either empty or the trusted owner-PC literal.
# shellcheck disable=SC2086
actual_helper=$(timeout 60s /usr/bin/podman --url "$podman_url" run --rm \
  --name "$name" \
  $userns_opt \
  --network none \
  --read-only \
  --cap-drop all \
  --security-opt no-new-privileges \
  --pids-limit 64 \
  --memory 256m \
  --cpus 0.5 \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m,uid=1000,gid=1000 \
  --volume "$volume:/workspaces:rw,nosuid,nodev" \
  "$workspace_image" /bin/sh -ec '
    test "$(id -u)" = 1000
    test -w /workspaces
    command -v git >/dev/null
    command -v tmux >/dev/null
    /opt/codex-mobile-helper/codex-real --version >/dev/null
    sha256sum /opt/codex-mobile-helper/codex-mobile-workspace-helper
  ' | awk '{print $1}')

[ "$actual_helper" = "$expected_helper" ] || {
  echo "disposable runtime used an unexpected workspace helper" >&2
  exit 1
}
echo "disposable runtime smoke: PASS ($release_id)"
