#!/bin/sh
set -eu

[ "$#" -eq 0 ] || { echo "usage: $0" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "rollback requires root" >&2; exit 1; }
release_root=${RELEASE_ROOT:-/opt/codex-mobile}
env_file=${ENV_FILE:-/etc/codex-mobile/production.env}
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

python3 "$old/scripts/infra_release_manifest.py" verify \
  --repo-root "$old" --require-images --verify-installed
python3 "$target/scripts/check-billing-policy.py" --repo-root "$target"
python3 "$target/scripts/infra-preflight.py" --env-file "$env_file" --repo-root "$target"
python3 "$target/scripts/infra_release_manifest.py" verify \
  --repo-root "$target" --require-images
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
  RELEASE_ROOT="$release_root" \
    /bin/sh "$selected/scripts/infra-install-release-host-artifacts.sh" "$selected" || return
  activate_link "$selected" || return
  systemctl restart codex-mobile-docker-firewall.service || return
  systemctl restart codex-mobile-workspace-runtime.service || return
  systemctl restart codex-mobile.service || return
  systemctl restart codex-mobile-provisioner.service || return
  RELEASE_ROOT="$release_root" REPO_ROOT="$selected" ENV_FILE="$env_file" \
    /bin/sh "$selected/scripts/infra-import-coder-template.sh" \
      --receipt-directory "$release_root/activations" || return
  RELEASE_ROOT="$release_root" REPO_ROOT="$selected" ENV_FILE="$env_file" \
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
