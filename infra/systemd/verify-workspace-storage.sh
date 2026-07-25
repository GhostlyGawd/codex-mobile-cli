#!/bin/sh
set -eu

storage_root=${WORKSPACE_STORAGE_ROOT:-/srv/codex-mobile/workspaces}
expected_mount=${WORKSPACE_STORAGE_MOUNT:-/srv/codex-mobile}
containers_conf=${CONTAINERS_CONF:-/etc/codex-mobile/containers.conf}
storage_conf=${CONTAINERS_STORAGE_CONF:-/etc/codex-mobile/containers-storage.conf}

[ "$(id -u)" -eq 0 ] || {
  echo "workspace storage verification must run as root" >&2
  exit 1
}
[ -d "$storage_root" ] && [ ! -L "$storage_root" ] || {
  echo "$storage_root must be an existing, non-symlink directory" >&2
  exit 1
}
[ -f "$containers_conf" ] && [ ! -L "$containers_conf" ] || {
  echo "$containers_conf must be an existing, non-symlink regular file" >&2
  exit 1
}
[ "$(stat -c '%u:%g:%a' "$containers_conf")" = 0:0:600 ] || {
  echo "$containers_conf must be root:root with exact mode 0600" >&2
  exit 1
}
[ "$(grep -Ec '^[[:space:]]*pids_limit[[:space:]]*=[[:space:]]*512[[:space:]]*$' "$containers_conf")" -eq 1 ] || {
  echo "$containers_conf must set exactly one pids_limit = 512 creation default" >&2
  exit 1
}
[ "$(grep -Ec '^[[:space:]]*pids_limit[[:space:]]*=' "$containers_conf")" -eq 1 ] || {
  echo "$containers_conf contains an ambiguous process-limit policy" >&2
  exit 1
}
for expected in 'size[[:space:]]*=[[:space:]]*"4G"' 'inodes[[:space:]]*=[[:space:]]*"262144"'; do
  [ -f "$storage_conf" ] && [ ! -L "$storage_conf" ] || {
    echo "$storage_conf must be an existing, non-symlink regular file" >&2
    exit 1
  }
  [ "$(stat -c '%u:%g:%a' "$storage_conf")" = 0:0:600 ] || {
    echo "$storage_conf must be root:root with exact mode 0600" >&2
    exit 1
  }
  [ "$(grep -Ec "^[[:space:]]*${expected}[[:space:]]*$" "$storage_conf")" -eq 1 ] || {
    echo "$storage_conf must contain the audited 4 GiB / 262144-inode overlay defaults" >&2
    exit 1
  }
done

mount_target=$(findmnt --noheadings --output TARGET --target "$storage_root" | tr -d '[:space:]')
filesystem=$(findmnt --noheadings --output FSTYPE --target "$storage_root" | tr -d '[:space:]')
options=$(findmnt --noheadings --output OPTIONS --target "$storage_root" | tr -d '[:space:]')
mount_source=$(findmnt --noheadings --output SOURCE --target "$storage_root" | tr -d '[:space:]')
workspace_io_device=${WORKSPACE_IO_DEVICE:-}

[ "$mount_target" = "$expected_mount" ] || {
  echo "$storage_root must reside on the dedicated $expected_mount mount (found $mount_target)" >&2
  exit 1
}
[ "$filesystem" = xfs ] || {
  echo "$expected_mount must be XFS for per-volume project quotas (found $filesystem)" >&2
  exit 1
}
case ",$options," in
  *,pquota,*|*,prjquota,*) ;;
  *)
    echo "$expected_mount must be mounted with pquota or prjquota" >&2
    exit 1
    ;;
esac

case "$workspace_io_device" in
  /dev/*) ;;
  *)
    echo "WORKSPACE_IO_DEVICE must be the explicit /dev source backing $expected_mount" >&2
    exit 1
    ;;
esac
[ "$workspace_io_device" = "$mount_source" ] || {
  echo "WORKSPACE_IO_DEVICE must exactly match findmnt SOURCE $mount_source" >&2
  exit 1
}
[ -b "$workspace_io_device" ] || {
  echo "WORKSPACE_IO_DEVICE must be an existing block device" >&2
  exit 1
}

# Refuse to expose the engine API when an older managed container could be
# restarted without the current resource policy. New containers receive the
# engine's creation default plus the trusted Terraform resource fields; this
# closes the upgrade/restart path for pre-policy containers before any
# untrusted workload can execute.
[ -x /usr/bin/podman ] && [ -x /usr/bin/jq ] || {
  echo "podman and jq are required to verify existing workspace admission" >&2
  exit 1
}
CONTAINERS_CONF=$containers_conf
CONTAINERS_STORAGE_CONF=$storage_conf
export CONTAINERS_CONF CONTAINERS_STORAGE_CONF
managed_containers=$(/usr/bin/podman ps --all \
  --filter label=com.codex-mobile.managed=true --format '{{.Names}}')
for managed_container in $managed_containers; do
  inspect_json=$(/usr/bin/podman inspect "$managed_container")
  printf '%s\n' "$inspect_json" | /usr/bin/jq --exit-status \
    --arg device "$workspace_io_device" '
      .[0] as $c |
      $c.Config.Labels["com.codex-mobile.pids-limit"] == "512" and
      $c.HostConfig.PidsLimit == 512 and
      $c.HostConfig.UsernsMode == "private" and
      $c.HostConfig.Memory >= 1610612736 and
      $c.HostConfig.Memory <= 19327352832 and
      $c.HostConfig.MemorySwap == $c.HostConfig.Memory and
      $c.HostConfig.CpuPeriod == 100000 and
      $c.HostConfig.CpuQuota >= 50000 and
      $c.HostConfig.CpuQuota <= 800000 and
      any($c.HostConfig.BlkioDeviceReadBps[]?; .Path == $device and .Rate == 67108864) and
      any($c.HostConfig.BlkioDeviceWriteBps[]?; .Path == $device and .Rate == 33554432) and
      any($c.HostConfig.BlkioDeviceReadIOps[]?; .Path == $device and .Rate == 2000) and
      any($c.HostConfig.BlkioDeviceWriteIOps[]?; .Path == $device and .Rate == 1000) and
      (if $c.Config.Labels["com.codex-mobile.envbuilder-version"] == "1.3.0"
       then $c.HostConfig.ReadonlyRootfs == false and
            $c.HostConfig.StorageOpt.size == "4G" and
            $c.HostConfig.StorageOpt.inodes == "262144"
       else $c.HostConfig.ReadonlyRootfs == true
       end)
    ' >/dev/null || {
      echo "managed workspace $managed_container violates the current runtime admission policy" >&2
      exit 1
    }
done

exit 0
