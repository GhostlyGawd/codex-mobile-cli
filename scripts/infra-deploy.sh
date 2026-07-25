#!/bin/sh
set -eu

usage() {
  echo "usage: $0 RELEASE_DIRECTORY" >&2
  exit 2
}

[ "$#" -eq 1 ] || usage
[ "$(id -u)" -eq 0 ] || { echo "deployment requires root" >&2; exit 1; }

release_root=${RELEASE_ROOT:-/opt/codex-mobile}
env_file=${ENV_FILE:-/etc/codex-mobile/production.env}
release=$(realpath "$1")
staging=$(realpath "$release_root/staging")
releases=$(realpath "$release_root/releases")
case "$release" in "$staging"/*) ;; *) echo "release must be staged beneath $staging" >&2; exit 1 ;; esac

exec 9>"$release_root/.deploy.lock"
flock -x 9

for critical in \
  infra/compose.yaml infra/compose.github.yaml infra/compose.apns.yaml \
  infra/systemd/codex-mobile.service \
  infra/systemd/codex-mobile-workspace-runtime.service \
  infra/systemd/codex-mobile-provisioner.service \
  scripts/check-billing-policy.py scripts/infra-preflight.py \
  scripts/infra-compose.sh scripts/infra-health.sh scripts/infra-smoke.sh \
  scripts/infra-install-release-host-artifacts.sh scripts/infra_release_manifest.py; do
  [ -f "$release/$critical" ] && [ ! -L "$release/$critical" ] || {
    echo "staged release has a missing/symlinked critical file: $critical" >&2
    exit 1
  }
done
[ ! -e "$release/infra/release.env" ] && [ ! -e "$release/infra/release-manifest.json" ] || {
  echo "staged source must not contain a pre-generated release manifest/environment" >&2
  exit 1
}
[ -z "$(find "$release" -type l -print -quit)" ] || {
  echo "staged releases must not contain symbolic links" >&2
  exit 1
}
[ -z "$(find "$release" ! -type f ! -type d -print -quit)" ] || {
  echo "staged releases must contain only regular files and directories" >&2
  exit 1
}
[ ! -e "$release/infra/coder/templates/codex-mobile-envbuilder/.terraform" ] || {
  echo "staged Coder template must not contain a Terraform working directory" >&2
  exit 1
}

release_id=$(basename "$release")
printf '%s\n' "$release_id" | grep -Eq '^sha-[0-9a-f]{7,64}$' || {
  echo "release directory must be named sha-<lowercase commit>" >&2
  exit 1
}
configured_tag=$(awk -F= '$1 == "CONTROL_PLANE_IMAGE_TAG" {sub(/^[^=]*=/, ""); print}' "$env_file")
[ "$configured_tag" = "$release_id" ] || {
  echo "release directory name must equal owner-approved CONTROL_PLANE_IMAGE_TAG ($configured_tag)" >&2
  exit 1
}
target="$releases/$release_id"
[ ! -e "$target" ] || { echo "immutable release already exists: $target" >&2; exit 1; }

# Freeze the reviewed tree before executing or hashing it. Root alone can add
# the generated manifest and release environment after image construction.
chown -R --no-dereference root:root "$release"
chmod -R go-w "$release"
python3 "$release/scripts/check-billing-policy.py" --repo-root "$release"
python3 "$release/scripts/infra-preflight.py" --env-file "$env_file" --repo-root "$release"

current="$release_root/current"
previous="$release_root/previous"
old=
if [ -L "$current" ]; then
  old=$(realpath "$current")
  case "$old" in "$releases"/*) ;; *) echo "current release link escapes release root" >&2; exit 1 ;; esac
  python3 "$old/scripts/infra_release_manifest.py" verify \
    --repo-root "$old" --require-images --verify-installed
fi

systemctl restart codex-mobile-docker-firewall.service
systemctl start codex-mobile-workspace-runtime.service

# Build once, before promotion, under release-scoped tags. Activation and
# rollback are forbidden from rebuilding source.
CONTROL_PLANE_IMAGE_TAG="$release_id" REPO_ROOT="$release" ENV_FILE="$env_file" \
  /bin/sh "$release/scripts/infra-compose.sh" build --pull control-plane
REPO_ROOT="$release" \
  WORKSPACE_BASE_IMAGE="localhost/codex-mobile/workspace-base:$release_id" \
  ENVBUILDER_IMAGE="localhost/codex-mobile/envbuilder:$release_id" \
  /bin/sh "$release/scripts/infra-build-workspace-image.sh"
python3 "$release/scripts/infra_release_manifest.py" create \
  --repo-root "$release" --release-id "$release_id"
python3 "$release/scripts/infra_release_manifest.py" verify \
  --repo-root "$release" --require-images
chmod 0444 "$release/infra/release.env" "$release/infra/release-manifest.json"
chmod -R go-w "$release"
mv "$release" "$target"
release=$target

if [ -n "$old" ]; then
  REPO_ROOT="$old" ENV_FILE="$env_file" \
    /bin/sh "$old/scripts/infra-checkpoint.sh" --database
fi

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

if [ -n "$old" ] && [ "$old" != "$release" ]; then
  temporary="$release_root/.previous.$$"
  rm -f "$temporary"
  ln -s "$old" "$temporary"
  mv -Tf "$temporary" "$previous"
fi

if install_and_start "$release"; then
  echo "deployed $release_id from immutable local image IDs"
  exit 0
fi

echo "new release failed activation; restoring prior artifacts and release" >&2
if [ -n "$old" ]; then
  if install_and_start "$old"; then
    echo "prior release restored and verified: $(basename "$old")" >&2
  else
    echo "CRITICAL: prior release restoration also failed; preserve state and follow incident runbook" >&2
  fi
else
  echo "no prior release exists; public activation remains failed" >&2
fi
exit 1
