#!/bin/sh
set -eu

credential="${CREDENTIALS_DIRECTORY:?systemd credentials directory is missing}/coder_provisioner_key"
if [ ! -s "$credential" ]; then
  echo "the scoped Coder provisioner key is missing or empty" >&2
  exit 1
fi

CODER_PROVISIONER_DAEMON_KEY=$(tr -d '\r\n' < "$credential")
export CODER_PROVISIONER_DAEMON_KEY
CODER_URL="${CODER_ACCESS_URL:-http://127.0.0.1:7080}"
export CODER_URL

if [ -n "${RELEASE_ID:-}" ]; then
  case "$RELEASE_ID" in sha-[0-9a-f]*) ;; *) echo "the active immutable release ID is invalid" >&2; exit 1 ;; esac
  [ "${WORKSPACE_BASE_IMAGE:-}" = "localhost/codex-mobile/workspace-base:$RELEASE_ID" ] || {
    echo "the release-scoped workspace image is invalid" >&2
    exit 1
  }
  [ "${ENVBUILDER_IMAGE:-}" = "localhost/codex-mobile/envbuilder:$RELEASE_ID" ] || {
    echo "the release-scoped EnvBuilder image is invalid" >&2
    exit 1
  }

  # Terraform variables are supplied only by the root-owned active release
  # environment. Every new Coder build therefore consumes the images whose
  # content IDs were recorded before promotion, including after rollback.
  TF_VAR_workspace_base_image=$WORKSPACE_BASE_IMAGE
  TF_VAR_envbuilder_image=$ENVBUILDER_IMAGE
  export TF_VAR_workspace_base_image TF_VAR_envbuilder_image
elif [ -e /opt/codex-mobile/current/infra/release-manifest.json ]; then
  echo "an activated release is missing its immutable runtime environment" >&2
  exit 1
fi

if [ -z "$CODER_PROVISIONER_DAEMON_KEY" ]; then
  echo "the scoped Coder provisioner key is empty" >&2
  exit 1
fi

exec /usr/local/bin/coder provisioner start \
  --tag runtime=private-podman \
  --prometheus-enable \
  --prometheus-address 127.0.0.1:2113
