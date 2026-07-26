#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
HOME=/root
export PATH HOME
unset CDPATH ENV BASH_ENV PYTHONHOME PYTHONPATH PYTHONSTARTUP LD_LIBRARY_PATH LD_PRELOAD
unset DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG COMPOSE_FILE
unset CONTAINER_HOST CONTAINER_CONNECTION CONTAINERS_CONF CONTAINERS_STORAGE_CONF
unset CONTAINERS_REGISTRIES_CONF CONTAINERS_POLICY REGISTRY_AUTH_FILE XDG_CONFIG_HOME

[ "$#" -eq 1 ] || { echo "usage: $0 RELEASE_DIRECTORY" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "host artifact installation requires root" >&2; exit 1; }

release_root=${RELEASE_ROOT:-/opt/codex-mobile}
podman_url=${PODMAN_URL:-unix:///run/codex-mobile-podman/podman.sock}
release=$(realpath "$1")
releases=$(realpath "$release_root/releases")
case "$release" in
  "$releases"/*) ;;
  *) echo "release must resolve beneath $releases" >&2; exit 1 ;;
esac

/usr/bin/python3 -I "$release/scripts/infra_release_manifest.py" verify \
  --repo-root "$release" --require-images --require-image-audit \
  --podman-url "$podman_url"

install -d -o root -g root -m 0755 /usr/local/libexec/codex-mobile
for configuration in containers.conf containers-storage.conf; do
  source="$release/infra/$configuration"
  [ -f "$source" ] && [ ! -L "$source" ] || {
    echo "invalid release runtime configuration: $configuration" >&2
    exit 1
  }
  install -o root -g root -m 0644 "$source" "/etc/codex-mobile/$configuration"
done
for unit in \
  codex-mobile.service \
  codex-mobile-docker-firewall.service \
  codex-mobile-workspace-runtime.service \
  codex-mobile-provisioner.service; do
  source="$release/infra/systemd/$unit"
  [ -f "$source" ] && [ ! -L "$source" ] || {
    echo "invalid release unit: $unit" >&2
    exit 1
  }
  install -o root -g root -m 0644 "$source" "/etc/systemd/system/$unit"
done

for mapping in \
  'apply-docker-firewall.sh:apply-docker-firewall' \
  'start-provisioner.sh:start-provisioner' \
  'verify-workspace-storage.sh:verify-workspace-storage' \
  'ensure-workspace-control-network.py:ensure-workspace-control-network'; do
  source_name=${mapping%%:*}
  destination_name=${mapping#*:}
  source="$release/infra/systemd/$source_name"
  [ -f "$source" ] && [ ! -L "$source" ] || {
    echo "invalid release service wrapper: $source_name" >&2
    exit 1
  }
  install -o root -g root -m 0755 "$source" \
    "/usr/local/libexec/codex-mobile/$destination_name"
done

systemctl daemon-reload
/usr/bin/python3 -I "$release/scripts/infra_release_manifest.py" verify \
  --repo-root "$release" --require-images --require-image-audit --verify-installed \
  --podman-url "$podman_url"
echo "installed host artifacts for $(basename "$release")"
