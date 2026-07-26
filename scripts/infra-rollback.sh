#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
HOME=/root
export PATH HOME
unset CDPATH ENV BASH_ENV PYTHONHOME PYTHONPATH PYTHONSTARTUP LD_LIBRARY_PATH LD_PRELOAD
unset DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG COMPOSE_FILE
unset CONTAINER_HOST CONTAINER_CONNECTION CONTAINERS_CONF CONTAINERS_STORAGE_CONF
unset CONTAINERS_REGISTRIES_CONF CONTAINERS_POLICY REGISTRY_AUTH_FILE XDG_CONFIG_HOME

[ "$#" -eq 0 ] || { echo "usage: $0" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "rollback requires root" >&2; exit 1; }
release_root=${RELEASE_ROOT:-/opt/codex-mobile}
env_file=${ENV_FILE:-/etc/codex-mobile/production.env}
podman_url=${PODMAN_URL:-unix:///run/codex-mobile-podman/podman.sock}
deployment_profile=$(awk -F= '$1 == "DEPLOYMENT_PROFILE" {sub(/^[^=]*=/, ""); print; found=1} END {if (!found) exit 1}' "$env_file")
current="$release_root/current"
previous="$release_root/previous"

exec 9>"$release_root/.deploy.lock"
flock -x 9

[ -L "$current" ] || { echo "current release link is missing" >&2; exit 1; }
[ -L "$previous" ] || { echo "previous release link is missing" >&2; exit 1; }
old=$(realpath "$current")
target=$(realpath "$previous")
releases=$(realpath "$release_root/releases")
case "$old" in "$releases"/*) ;; *) echo "current link escapes release root" >&2; exit 1 ;; esac
case "$target" in "$releases"/*) ;; *) echo "previous link escapes release root" >&2; exit 1 ;; esac
[ "$old" != "$target" ] || { echo "current and previous releases are identical" >&2; exit 1; }
manifest_verifier="$old/scripts/infra_release_manifest.py"

/usr/bin/python3 -I "$manifest_verifier" verify \
  --repo-root "$old" --require-images --require-image-audit --verify-installed \
  --podman-url "$podman_url"
/usr/bin/python3 -I "$manifest_verifier" verify \
  --repo-root "$target" --require-images --require-image-audit \
  --podman-url "$podman_url"
/usr/bin/python3 -I "$target/scripts/check-billing-policy.py" \
  --repo-root "$target" --deployment-profile "$deployment_profile"
/usr/bin/python3 -I "$target/scripts/infra-preflight.py" --env-file "$env_file" --repo-root "$target"
REPO_ROOT="$old" ENV_FILE="$env_file" \
  /bin/sh "$old/scripts/infra-checkpoint.sh" --database

activate_link() {
  destination=$1
  temporary="$release_root/.current.$$"
  rm -f "$temporary" || return
  ln -s "$destination" "$temporary" || return
  mv -Tf "$temporary" "$current"
}

install_and_start() {
  selected=$1
  /usr/bin/python3 -I "$manifest_verifier" verify \
    --repo-root "$selected" --require-images --require-image-audit \
    --podman-url "$podman_url" || return
  RELEASE_ROOT="$release_root" PODMAN_URL="$podman_url" \
    /bin/sh "$selected/scripts/infra-install-release-host-artifacts.sh" "$selected" || return
  activate_link "$selected" || return
  systemctl restart codex-mobile-docker-firewall.service || return
  systemctl restart codex-mobile-workspace-runtime.service || return
  systemctl restart codex-mobile.service || return
  systemctl restart codex-mobile-provisioner.service || return
  RELEASE_ROOT="$release_root" REPO_ROOT="$selected" ENV_FILE="$env_file" \
    PODMAN_URL="$podman_url" \
    /bin/sh "$selected/scripts/infra-import-coder-template.sh" \
      --receipt-directory "$release_root/activations" || return
  RELEASE_ROOT="$release_root" REPO_ROOT="$selected" ENV_FILE="$env_file" \
    PODMAN_URL="$podman_url" \
    /bin/sh "$selected/scripts/infra-health.sh" --smoke
}

if install_and_start "$target"; then
  temporary="$release_root/.previous.$$"
  rm -f "$temporary"
  ln -s "$old" "$temporary"
  mv -Tf "$temporary" "$previous"
  echo "rolled back to $(basename "$target") using its recorded image/template/runtime provenance"
  exit 0
fi

echo "rollback target failed activation; attempting one restoration of $(basename "$old")" >&2
if install_and_start "$old"; then
  echo "original release restored and verified" >&2
else
  echo "CRITICAL: original release restoration failed; preserve state and follow incident runbook" >&2
fi
exit 1
