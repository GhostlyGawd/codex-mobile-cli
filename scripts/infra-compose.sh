#!/bin/sh
set -eu

repo_root=${REPO_ROOT:-/opt/codex-mobile/current}
env_file=${ENV_FILE:-/etc/codex-mobile/production.env}

[ "$#" -gt 0 ] || { echo "usage: $0 COMPOSE_ARGUMENT..." >&2; exit 2; }
[ -r "$env_file" ] || { echo "missing environment file: $env_file" >&2; exit 1; }
[ -r "$repo_root/infra/compose.yaml" ] || { echo "missing base Compose file" >&2; exit 1; }

# An activated immutable release owns its image selection.  The operator env
# continues to hold site configuration, but cannot make rollback rebuild or
# retag old source under the newest CONTROL_PLANE_IMAGE_TAG.
release_env="$repo_root/infra/release.env"
if [ -f "$release_env" ]; then
  [ ! -L "$release_env" ] || { echo "release environment must not be a symlink" >&2; exit 1; }
  release_id=$(awk -F= '$1 == "RELEASE_ID" {print $2}' "$release_env")
  release_control_tag=$(awk -F= '$1 == "CONTROL_PLANE_IMAGE_TAG" {print $2}' "$release_env")
  release_workspace_image=$(awk -F= '$1 == "WORKSPACE_BASE_IMAGE" {print $2}' "$release_env")
  release_envbuilder_image=$(awk -F= '$1 == "ENVBUILDER_IMAGE" {print $2}' "$release_env")
  case "$release_id" in sha-[0-9a-f]*) ;; *) echo "invalid immutable release ID" >&2; exit 1 ;; esac
  [ "$release_control_tag" = "$release_id" ] || { echo "release control-plane tag mismatch" >&2; exit 1; }
  [ "$release_workspace_image" = "localhost/codex-mobile/workspace-base:$release_id" ] || {
    echo "release workspace image mismatch" >&2
    exit 1
  }
  [ "$release_envbuilder_image" = "localhost/codex-mobile/envbuilder:$release_id" ] || {
    echo "release EnvBuilder image mismatch" >&2
    exit 1
  }
  CONTROL_PLANE_IMAGE_TAG=$release_control_tag
  WORKSPACE_BASE_IMAGE=$release_workspace_image
  ENVBUILDER_IMAGE=$release_envbuilder_image
  RELEASE_ID=$release_id
  export CONTROL_PLANE_IMAGE_TAG WORKSPACE_BASE_IMAGE ENVBUILDER_IMAGE RELEASE_ID
fi

env_value() {
  awk -F= -v key="$1" '$1 == key {sub(/^[^=]*=/, ""); print; found=1} END {if (!found) exit 1}' "$env_file"
}

github_enabled=$(env_value GITHUB_ENABLED)
apns_enabled=$(env_value APNS_ENABLED)
case "$github_enabled:$apns_enabled" in
  false:false)
    exec docker compose --env-file "$env_file" \
      --file "$repo_root/infra/compose.yaml" "$@"
    ;;
  true:false)
    exec docker compose --env-file "$env_file" \
      --file "$repo_root/infra/compose.yaml" \
      --file "$repo_root/infra/compose.github.yaml" "$@"
    ;;
  false:true)
    exec docker compose --env-file "$env_file" \
      --file "$repo_root/infra/compose.yaml" \
      --file "$repo_root/infra/compose.apns.yaml" "$@"
    ;;
  true:true)
    exec docker compose --env-file "$env_file" \
      --file "$repo_root/infra/compose.yaml" \
      --file "$repo_root/infra/compose.github.yaml" \
      --file "$repo_root/infra/compose.apns.yaml" "$@"
    ;;
  *)
    echo "GITHUB_ENABLED and APNS_ENABLED must each be exactly true or false" >&2
    exit 1
    ;;
esac
