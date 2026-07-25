#!/bin/sh
set -eu

repo_root=${REPO_ROOT:-/opt/codex-mobile/current}
podman_url=${PODMAN_URL:-unix:///run/codex-mobile-podman/podman.sock}
image=${WORKSPACE_BASE_IMAGE:-localhost/codex-mobile/workspace-base:2026-07-15}
envbuilder_base_image=${ENVBUILDER_BASE_IMAGE:-ghcr.io/coder/envbuilder:1.3.0@sha256:b34ade2fb90a8536df76e7a15c6dd8c6352d0ae835a187b13467fa0c8a71e280}
envbuilder_image=${ENVBUILDER_IMAGE:-localhost/codex-mobile/envbuilder:1.3.0-helper-2026-07-15}
helper_amd64_sha256=f6fc430a2200d13ee0ef04dd576875b4f9a7c95a04287cbdec2deec3b495493c
helper_arm64_sha256=c7e4577a465b55721043612f9b6919248806576816388b01898f6c2784dc163e

[ -f "$repo_root/infra/workspace/Dockerfile" ] || { echo "workspace Dockerfile is missing" >&2; exit 1; }
[ -f "$repo_root/infra/workspace/EnvBuilder.Dockerfile" ] || { echo "EnvBuilder Dockerfile is missing" >&2; exit 1; }
podman --url "$podman_url" info >/dev/null
podman --url "$podman_url" build \
  --file "$repo_root/infra/workspace/Dockerfile" \
  --ignorefile "$repo_root/infra/workspace/Dockerfile.dockerignore" \
  --tag "$image" \
  --pull=missing \
  "$repo_root"

user=$(podman --url "$podman_url" image inspect "$image" --format '{{.Config.User}}')
if [ "$user" != codex ] && [ "$user" != "1000:1000" ]; then
  echo "workspace image must default to the non-root codex user" >&2
  exit 1
fi
podman --url "$podman_url" run --rm --network none --read-only \
  --cap-drop all --security-opt no-new-privileges \
  "$image" /bin/sh -ec '
    test "$(id -u)" = 1000
    command -v git
    command -v tmux
    command -v codex
    command -v codex-mobile-workspace-helper
    test "$(readlink /usr/local/bin/codex)" = "/opt/codex-mobile-helper/codex"
    test "$(readlink /opt/codex-mobile-helper/codex)" = "codex-mobile-workspace-helper"
    test "$(readlink /usr/local/bin/codex-mobile-workspace-helper)" = "/opt/codex-mobile-helper/codex-mobile-workspace-helper"
    test "$(stat -c "%u:%g:%a" /opt/codex-mobile-helper/codex-mobile-workspace-helper)" = "0:0:755"
    test "$(stat -c "%u:%g:%a" /opt/codex-mobile-helper/codex-real)" = "0:0:755"
    test "$(stat -c "%u:%g:%a" /opt/codex-mobile-helper/codex-code-mode-host)" = "0:0:755"
    test "$(stat -c "%u:%g:%a" /opt/codex-mobile-helper/ca-certificates.crt)" = "0:0:444"
    test -s /opt/codex-mobile-helper/ca-certificates.crt
    /opt/codex-mobile-helper/codex-real --version | grep -F "codex-cli 0.144.5"
  '

case "$(podman --url "$podman_url" info --format '{{.Host.Arch}}')" in
  amd64|x86_64) helper_sha256=$helper_amd64_sha256 ;;
  arm64|aarch64) helper_sha256=$helper_arm64_sha256 ;;
  *) echo "unsupported workspace-helper architecture" >&2; exit 1 ;;
esac
actual_helper_sha256=$(podman --url "$podman_url" run --rm --network none --read-only \
  --cap-drop all --security-opt no-new-privileges \
  "$image" sha256sum /opt/codex-mobile-helper/codex-mobile-workspace-helper | awk '{print $1}')
[ "$actual_helper_sha256" = "$helper_sha256" ] || {
  echo "workspace-helper checksum mismatch: expected $helper_sha256, got $actual_helper_sha256" >&2
  exit 1
}

podman --url "$podman_url" build \
  --file "$repo_root/infra/workspace/EnvBuilder.Dockerfile" \
  --ignorefile "$repo_root/infra/workspace/Dockerfile.dockerignore" \
  --build-arg "WORKSPACE_BASE_IMAGE=$image" \
  --build-arg "ENVBUILDER_BASE_IMAGE=$envbuilder_base_image" \
  --build-arg "WORKSPACE_HELPER_AMD64_SHA256=$helper_amd64_sha256" \
  --build-arg "WORKSPACE_HELPER_ARM64_SHA256=$helper_arm64_sha256" \
  --tag "$envbuilder_image" \
  --pull=missing \
  "$repo_root"

# EnvBuilder's upstream image is intentionally scratch. Executing the bundled,
# pinned static Codex binary proves the derivative contains the complete
# trusted volume seed before a Dev Container replaces the root filesystem.
podman --url "$podman_url" run --rm --network none --read-only \
  --cap-drop all --security-opt no-new-privileges \
  --entrypoint /opt/codex-mobile-helper/codex-real \
  "$envbuilder_image" --version | grep -F "codex-cli 0.144.5"

echo "workspace images verified: $image and $envbuilder_image"
