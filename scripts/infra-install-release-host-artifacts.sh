#!/bin/sh
set -eu

[ "$#" -eq 1 ] || { echo "usage: $0 RELEASE_DIRECTORY" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "host artifact installation requires root" >&2; exit 1; }

release_root=${RELEASE_ROOT:-/opt/codex-mobile}
release=$(realpath "$1")
releases=$(realpath "$release_root/releases")
case "$release" in
  "$releases"/*) ;;
  *) echo "release must resolve beneath $releases" >&2; exit 1 ;;
esac

python3 "$release/scripts/infra_release_manifest.py" verify \
  --repo-root "$release" --require-images

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
python3 "$release/scripts/infra_release_manifest.py" verify \
  --repo-root "$release" --require-images --verify-installed
echo "installed host artifacts for $(basename "$release")"
