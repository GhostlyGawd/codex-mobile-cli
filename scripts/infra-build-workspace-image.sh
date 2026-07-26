#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
HOME=/root
export PATH HOME
unset CDPATH ENV BASH_ENV PYTHONHOME PYTHONPATH PYTHONSTARTUP LD_LIBRARY_PATH LD_PRELOAD
unset DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG COMPOSE_FILE
unset CONTAINER_HOST CONTAINER_CONNECTION CONTAINERS_CONF CONTAINERS_STORAGE_CONF
unset CONTAINERS_REGISTRIES_CONF CONTAINERS_POLICY REGISTRY_AUTH_FILE
unset XDG_CONFIG_HOME XDG_RUNTIME_DIR

repo_root=${REPO_ROOT:-/opt/codex-mobile/current}
podman_url=${PODMAN_URL:-unix:///run/codex-mobile-podman/podman.sock}
image=${WORKSPACE_BASE_IMAGE:-localhost/codex-mobile/workspace-base:2026-07-15}
envbuilder_image=${ENVBUILDER_IMAGE:-localhost/codex-mobile/envbuilder:1.3.0-codex-mobile.1}
helper_amd64_sha256=ba7080f880206d90e05d751245c3635b9bdcbcbbc6152d61c3ec4221fd5bdf14
helper_arm64_sha256=3042240a601842f35233e383835a3e40aef6b05640b44f723bafefb133fdf9aa
workspace_dockerfile=$repo_root/infra/workspace/Dockerfile
workspace_ignorefile=$repo_root/infra/workspace/Dockerfile.dockerignore
envbuilder_dockerfile=$repo_root/infra/workspace/EnvBuilder.Dockerfile
envbuilder_ignorefile=$repo_root/infra/workspace/EnvBuilder.Dockerfile.dockerignore
envbuilder_lock=$repo_root/infra/workspace/envbuilder/source-lock.json
envbuilder_patch=$repo_root/infra/workspace/envbuilder/envbuilder-v1.3.0-codex-mobile.patch
envbuilder_verifier=$repo_root/scripts/verify-envbuilder-source.py

require_regular_file() {
  [ -f "$1" ] && [ ! -L "$1" ] || {
    echo "$2 is missing or symlinked" >&2
    exit 1
  }
}

normalize_local_image_id() {
  candidate=${1#sha256:}
  [ "${#candidate}" -eq 64 ] || return 1
  case "$candidate" in
    *[!0-9a-f]*) return 1 ;;
  esac
  printf 'sha256:%s\n' "$candidate"
}

require_regular_file \
  "$repo_root/scripts/infra_release_manifest.py" \
  "release manifest verifier"
require_regular_file "$workspace_dockerfile" "workspace Dockerfile"
require_regular_file "$workspace_ignorefile" "workspace Docker ignorefile"
require_regular_file "$envbuilder_dockerfile" "EnvBuilder Dockerfile"
require_regular_file "$envbuilder_ignorefile" "EnvBuilder Docker ignorefile"
require_regular_file "$envbuilder_lock" "EnvBuilder source lock"
require_regular_file "$envbuilder_patch" "EnvBuilder source patch"
require_regular_file "$envbuilder_verifier" "EnvBuilder source verifier"

/usr/bin/python3 -I "$repo_root/scripts/infra_release_manifest.py" \
  validate-podman-url --podman-url "$podman_url" >/dev/null
/usr/bin/python3 -I "$envbuilder_verifier" \
  --repo-root "$repo_root" --static-only >/dev/null
/usr/bin/podman --url "$podman_url" info >/dev/null
/usr/bin/podman --url "$podman_url" build \
  --format docker \
  --file "$workspace_dockerfile" \
  --ignorefile "$workspace_ignorefile" \
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
    /opt/codex-mobile-helper/codex-real --version | grep -F "codex-cli 0.145.0"
  '

workspace_base_raw_id=$(
  /usr/bin/podman --url "$podman_url" image inspect "$image" --format '{{.Id}}'
)
workspace_base_id=$(normalize_local_image_id "$workspace_base_raw_id") || {
  echo "workspace image ID is invalid" >&2
  exit 1
}

/usr/bin/podman --url "$podman_url" build \
  --format docker \
  --file "$envbuilder_dockerfile" \
  --ignorefile "$envbuilder_ignorefile" \
  --build-arg "WORKSPACE_BASE_IMAGE=$workspace_base_id" \
  --build-arg "WORKSPACE_HELPER_AMD64_SHA256=$helper_amd64_sha256" \
  --build-arg "WORKSPACE_HELPER_ARM64_SHA256=$helper_arm64_sha256" \
  --tag "$envbuilder_image" \
  --pull=missing \
  "$repo_root"

/usr/bin/python3 -I "$repo_root/scripts/infra_release_manifest.py" \
  verify-helper-pin --image-reference "$envbuilder_image" --podman-url "$podman_url"
/usr/bin/python3 -I "$repo_root/scripts/infra_release_manifest.py" \
  verify-helper-seed \
  --image-reference "$image" \
  --comparison-image-reference "$envbuilder_image" \
  --podman-url "$podman_url"

workspace_base_raw_id_after=$(
  /usr/bin/podman --url "$podman_url" image inspect "$image" --format '{{.Id}}'
)
workspace_base_id_after=$(normalize_local_image_id "$workspace_base_raw_id_after") || {
  echo "workspace image ID is invalid after the EnvBuilder build" >&2
  exit 1
}
[ "$workspace_base_id_after" = "$workspace_base_id" ] || {
  echo "workspace image tag changed during the EnvBuilder build" >&2
  exit 1
}

envbuilder_raw_id=$(
  /usr/bin/podman --url "$podman_url" image inspect "$envbuilder_image" --format '{{.Id}}'
)
envbuilder_id=$(normalize_local_image_id "$envbuilder_raw_id") || {
  echo "EnvBuilder image ID is invalid" >&2
  exit 1
}

/usr/bin/podman --url "$podman_url" image inspect "$envbuilder_id" |
  /usr/bin/jq --exit-status \
    --arg helper_amd64 "$helper_amd64_sha256" \
    --arg helper_arm64 "$helper_arm64_sha256" \
    '
      length == 1
      and .[0].Config.Entrypoint == ["/.envbuilder/bin/envbuilder"]
      and ((.[0].Config.Cmd // []) | length == 0)
      and (.[0].Config.User // "") == ""
      and .[0].Config.WorkingDir == "/"
      and (
        (.[0].Config.Env | sort)
        == [
          "KANIKO_DIR=/.envbuilder",
          "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        ]
      )
      and ((.[0].Config.ExposedPorts // {}) | length == 0)
      and ((.[0].Config.Volumes // {}) | length == 0)
      and ((.[0].Config.Healthcheck // {}) | length == 0)
      and .[0].Config.Labels["org.opencontainers.image.version"] == "1.3.0-codex-mobile.1"
      and .[0].Config.Labels["org.opencontainers.image.licenses"] == "LicenseRef-First-Party-No-License"
      and .[0].Config.Labels["com.codex-mobile.envbuilder-upstream-repository"] == "https://github.com/coder/envbuilder"
      and .[0].Config.Labels["com.codex-mobile.envbuilder-upstream-version"] == "1.3.0"
      and .[0].Config.Labels["com.codex-mobile.envbuilder-upstream-license"] == "Apache-2.0"
      and .[0].Config.Labels["com.codex-mobile.envbuilder-upstream-commit"] == "da95f80ea89fc615b85441da107c29004061df6a"
      and .[0].Config.Labels["com.codex-mobile.envbuilder-upstream-archive-sha256"] == "f1c6334ee08736dec2585d96ad0afacc1888994bf2a2cdcf86e982b229fb8a85"
      and .[0].Config.Labels["com.codex-mobile.envbuilder-patch-sha256"] == "aea2941874a27d4deac96a0efe3a006ca6ea56d7cff982caa3a36877fc1756c3"
      and .[0].Config.Labels["com.codex-mobile.envbuilder-source-lock-sha256"] == "5a1f27db2ed6226ccd401d5bd2a6c617a42ca4fe07071a9021f29af3a2b053a8"
      and .[0].Config.Labels["org.opencontainers.image.workspace-helper-amd64-sha256"] == $helper_amd64
      and .[0].Config.Labels["org.opencontainers.image.workspace-helper-arm64-sha256"] == $helper_arm64
    ' >/dev/null

# The final image is intentionally scratch. Execute only the two fixed,
# source-built binaries needed for version proof; the seed comparison above
# inspects filesystem bytes without executing image content.
/usr/bin/podman --url "$podman_url" run --rm --network none --read-only \
  --cap-drop all --security-opt no-new-privileges \
  --entrypoint /opt/codex-mobile-helper/codex-real \
  "$envbuilder_id" --version | grep -F "codex-cli 0.145.0"
/usr/bin/timeout 15 /usr/bin/podman --url "$podman_url" run --rm \
  --network none --read-only --cap-drop all \
  --security-opt no-new-privileges \
  --env ENVBUILDER_EXIT_ON_BUILD_FAILURE=true \
  "$envbuilder_id" 2>&1 |
  /usr/bin/grep -F "envbuilder v1.3.0-codex-mobile.1" >/dev/null

echo "workspace images verified: $image and $envbuilder_image"
