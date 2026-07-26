#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
HOME=/root
export PATH HOME
unset CDPATH ENV BASH_ENV PYTHONHOME PYTHONPATH PYTHONSTARTUP LD_LIBRARY_PATH LD_PRELOAD
unset DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG COMPOSE_FILE
unset CONTAINER_HOST CONTAINER_CONNECTION CONTAINERS_CONF CONTAINERS_STORAGE_CONF
unset CONTAINERS_REGISTRIES_CONF CONTAINERS_POLICY REGISTRY_AUTH_FILE XDG_CONFIG_HOME

repo_root=${REPO_ROOT:-/opt/codex-mobile/current}
podman_url=${PODMAN_URL:-unix:///run/codex-mobile-podman/podman.sock}
image=${WORKSPACE_BASE_IMAGE:-localhost/codex-mobile/workspace-base:2026-07-15}
envbuilder_base_image=${ENVBUILDER_BASE_IMAGE:-ghcr.io/coder/envbuilder:1.3.0@sha256:b34ade2fb90a8536df76e7a15c6dd8c6352d0ae835a187b13467fa0c8a71e280}
envbuilder_image=${ENVBUILDER_IMAGE:-localhost/codex-mobile/envbuilder:1.3.0-helper-2026-07-15}
helper_amd64_sha256=11d1fb9c53549e98bb5a976c2958954ff6eb99fd9485dd09beac50f6157df924
helper_arm64_sha256=81a623dae961e640c18ac1df942baf9a797dbeb79b9f90312b62f241d36da1dd

[ -f "$repo_root/scripts/infra_release_manifest.py" ] \
  && [ ! -L "$repo_root/scripts/infra_release_manifest.py" ] || {
  echo "release manifest verifier is missing or symlinked" >&2
  exit 1
}
/usr/bin/python3 -I "$repo_root/scripts/infra_release_manifest.py" \
  validate-podman-url --podman-url "$podman_url" >/dev/null
[ -f "$repo_root/infra/workspace/Dockerfile" ] || { echo "workspace Dockerfile is missing" >&2; exit 1; }
[ -f "$repo_root/infra/workspace/EnvBuilder.Dockerfile" ] || { echo "EnvBuilder Dockerfile is missing" >&2; exit 1; }
/usr/bin/podman --url "$podman_url" info >/dev/null
/usr/bin/podman --url "$podman_url" build \
  --file "$repo_root/infra/workspace/Dockerfile" \
  --ignorefile "$repo_root/infra/workspace/Dockerfile.dockerignore" \
  --tag "$image" \
  --pull=missing \
  "$repo_root"

/usr/bin/python3 -I "$repo_root/scripts/infra_release_manifest.py" \
  verify-helper-pin --image-reference "$image" --podman-url "$podman_url"

user=$(/usr/bin/podman --url "$podman_url" image inspect "$image" --format '{{.Config.User}}')
if [ "$user" != codex ] && [ "$user" != "1000:1000" ]; then
  echo "workspace image must default to the non-root codex user" >&2
  exit 1
fi
/usr/bin/podman --url "$podman_url" run --rm --network none --read-only \
  --cap-drop all --security-opt no-new-privileges \
  --entrypoint /bin/sh \
  "$image" -ec '
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

/usr/bin/podman --url "$podman_url" build \
  --file "$repo_root/infra/workspace/EnvBuilder.Dockerfile" \
  --ignorefile "$repo_root/infra/workspace/Dockerfile.dockerignore" \
  --build-arg "WORKSPACE_BASE_IMAGE=$image" \
  --build-arg "ENVBUILDER_BASE_IMAGE=$envbuilder_base_image" \
  --build-arg "WORKSPACE_HELPER_AMD64_SHA256=$helper_amd64_sha256" \
  --build-arg "WORKSPACE_HELPER_ARM64_SHA256=$helper_arm64_sha256" \
  --tag "$envbuilder_image" \
  --pull=missing \
  "$repo_root"

/usr/bin/python3 -I "$repo_root/scripts/infra_release_manifest.py" \
  verify-helper-pin --image-reference "$envbuilder_image" --podman-url "$podman_url"

# EnvBuilder's upstream image is intentionally scratch. Executing the bundled,
# pinned static Codex binary proves the derivative contains the complete
# trusted volume seed before a Dev Container replaces the root filesystem.
/usr/bin/podman --url "$podman_url" run --rm --network none --read-only \
  --cap-drop all --security-opt no-new-privileges \
  --entrypoint /opt/codex-mobile-helper/codex-real \
  "$envbuilder_image" --version | grep -F "codex-cli 0.144.5"

echo "workspace images verified: $image and $envbuilder_image"
