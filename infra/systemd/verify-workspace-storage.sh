#!/bin/sh
set -eu

storage_root=${WORKSPACE_STORAGE_ROOT:-/srv/codex-mobile/workspaces}
expected_mount=${WORKSPACE_STORAGE_MOUNT:-/srv/codex-mobile}
containers_conf=${CONTAINERS_CONF:-/etc/codex-mobile/containers.conf}
storage_conf=${CONTAINERS_STORAGE_CONF:-/etc/codex-mobile/containers-storage.conf}
deployment_profile=${DEPLOYMENT_PROFILE:-}

case "$deployment_profile" in
  owner_pc_beta|fixed_price_vps) ;;
  *) echo "DEPLOYMENT_PROFILE must explicitly select a supported storage verifier" >&2; exit 1 ;;
esac

[ "$(id -u)" -eq 0 ] || {
  echo "workspace storage verification must run as root" >&2
  exit 1
}
[ "$storage_root" = "$expected_mount/workspaces" ] || {
  echo "workspace storage must use the reviewed /workspaces subtree" >&2
  exit 1
}

# Direct WSL shells use a sibling mount namespace to systemd. Re-enter PID 1's
# namespace so operator-invoked preflight, template import, and health checks
# inspect the same persistent mount as the runtime service.
if [ "$deployment_profile" = owner_pc_beta ]; then
  if [ -z "${INVOCATION_ID:-}" ]; then
    current_mount_namespace=$(readlink /proc/self/ns/mnt)
    service_mount_namespace=$(readlink /proc/1/ns/mnt)
    if [ "$current_mount_namespace" != "$service_mount_namespace" ]; then
      [ "${CODEX_MOBILE_PID1_MOUNT_NAMESPACE:-}" != 1 ] || {
        echo "cannot enter the systemd mount namespace" >&2
        exit 1
      }
      export CODEX_MOBILE_PID1_MOUNT_NAMESPACE=1
      exec nsenter --target 1 --mount -- /bin/sh "$0" "$@"
    fi
  fi
fi

[ "$deployment_profile" != owner_pc_beta ] || {
  owner_host_env=/etc/codex-mobile/owner-pc-host.env
  [ -f "$owner_host_env" ] && [ ! -L "$owner_host_env" ] &&
    [ "$(stat -c '%u:%g:%a' "$owner_host_env")" = 0:0:600 ] || {
      echo "$owner_host_env must be root:root mode 0600" >&2
      exit 1
    }
  set -a
  . "$owner_host_env"
  set +a
  [ "${DEPLOYMENT_PROFILE:-}" = owner_pc_beta ] || {
    echo "$owner_host_env changed the selected deployment profile" >&2
    exit 1
  }
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
[ "$(grep -Ec '^[[:space:]]*tmp_dir[[:space:]]*=[[:space:]]*"/run/codex-mobile-podman/libpod"[[:space:]]*$' "$containers_conf")" -eq 1 ] || {
  echo "$containers_conf must keep libpod runtime state inside the private RuntimeDirectory" >&2
  exit 1
}
for expected in \
  'root-auto-userns-user[[:space:]]*=[[:space:]]*"containers"' \
  'auto-userns-min-size[[:space:]]*=[[:space:]]*1024' \
  'auto-userns-max-size[[:space:]]*=[[:space:]]*65536' \
  'size[[:space:]]*=[[:space:]]*"4G"' \
  'inodes[[:space:]]*=[[:space:]]*"262144"'; do
  [ -f "$storage_conf" ] && [ ! -L "$storage_conf" ] || {
    echo "$storage_conf must be an existing, non-symlink regular file" >&2
    exit 1
  }
  [ "$(stat -c '%u:%g:%a' "$storage_conf")" = 0:0:600 ] || {
    echo "$storage_conf must be root:root with exact mode 0600" >&2
    exit 1
  }
  [ "$(grep -Ec "^[[:space:]]*${expected}[[:space:]]*$" "$storage_conf")" -eq 1 ] || {
    echo "$storage_conf must contain the audited auto-userns and 4 GiB / 262144-inode overlay defaults" >&2
    exit 1
  }
done

mount_target=$(findmnt --noheadings --output TARGET --target "$storage_root" | tr -d '[:space:]')
filesystem=$(findmnt --noheadings --output FSTYPE --target "$storage_root" | tr -d '[:space:]')
options=$(findmnt --noheadings --output OPTIONS --target "$storage_root" | tr -d '[:space:]')
mount_source=$(findmnt --raw --noheadings --output SOURCES \
  --target "$storage_root" | tail -n 1 | tr -d '[:space:]')
# util-linux may render a systemd ReadWritePaths bind as
# /dev/loopN[/workspaces] even for SOURCES. Quota and loop verification must
# address the underlying block device, not the bind-mount subroot annotation.
mount_source=${mount_source%%[*}
mount_fsroot=$(findmnt --noheadings --output FSROOT --target "$storage_root" | tr -d '[:space:]')
workspace_io_device=${WORKSPACE_IO_DEVICE:-}
workspace_io_device_inspect=$workspace_io_device

case "$mount_target:$mount_fsroot" in
  "$expected_mount:/"|"$storage_root:/workspaces") ;;
  *)
    echo "$storage_root must resolve to the reviewed /workspaces subtree of $expected_mount" >&2
    exit 1
    ;;
esac
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
case ",$options," in
  *,nodev,*) ;;
  *) echo "$expected_mount must be mounted nodev" >&2; exit 1 ;;
esac
case ",$options," in
  *,nosuid,*) ;;
  *) echo "$expected_mount must be mounted nosuid" >&2; exit 1 ;;
esac

case "$workspace_io_device" in
  /dev/*) ;;
  *)
    echo "WORKSPACE_IO_DEVICE must be the explicit /dev source backing $expected_mount" >&2
    exit 1
    ;;
esac
[ -b "$workspace_io_device" ] || {
  echo "WORKSPACE_IO_DEVICE must be an existing block device" >&2
  exit 1
}
if [ "$deployment_profile" = owner_pc_beta ]; then
  workspace_io_device_inspect=$(readlink -f "$workspace_io_device")
  owner_image=${OWNER_PC_STORAGE_IMAGE:-}
  owner_gib=${OWNER_PC_STORAGE_GIB:-}
  [ "$owner_image" = /var/lib/codex-mobile-owner-pc/workspace-storage.xfs ] || {
    echo "OWNER_PC_STORAGE_IMAGE must use the reviewed Linux-native path" >&2
    exit 1
  }
  [ "$owner_gib" = 64 ] || {
    echo "OWNER_PC_STORAGE_GIB must be exactly 64" >&2
    exit 1
  }
  case "$mount_source" in
    /dev/loop[0-9]*) ;;
    *) echo "owner_pc_beta must mount the XFS image through an explicit loop device" >&2; exit 1 ;;
  esac
  [ -f "$owner_image" ] && [ ! -L "$owner_image" ] || {
    echo "$owner_image must be a non-symlink regular file" >&2
    exit 1
  }
  [ "$(stat -c '%u:%g:%a:%h:%s' "$owner_image")" = "0:0:600:1:68719476736" ] || {
    echo "$owner_image must be root:root mode 0600, single-linked, and exactly 64 GiB" >&2
    exit 1
  }
  allocated_bytes=$(( $(stat -c '%b' "$owner_image") * 512 ))
  [ "$allocated_bytes" -ge 68719476736 ] || {
    echo "$owner_image must be fully allocated rather than sparse" >&2
    exit 1
  }
  loop_backing=$(losetup --noheadings --output BACK-FILE "$mount_source" | sed -e 's/[[:space:]]*$//')
  [ "$(realpath "$loop_backing")" = "$owner_image" ] || {
    echo "$mount_source must use the exact owner-PC storage image" >&2
    exit 1
  }
  image_device=$(findmnt --noheadings --output SOURCE --target "$owner_image" | tr -d '[:space:]')
  [ -b "$image_device" ] || {
    echo "$owner_image must reside on a Linux-native block filesystem" >&2
    exit 1
  }
  [ "$(stat -L -c '%t:%T' "$workspace_io_device")" = "$(stat -L -c '%t:%T' "$image_device")" ] || {
    echo "WORKSPACE_IO_DEVICE must identify the block device backing $owner_image" >&2
    exit 1
  }
  [ -x /usr/sbin/xfs_quota ] || {
    echo "xfs_quota is required for owner-PC quota verification" >&2
    exit 1
  }
  quota_state=$(/usr/sbin/xfs_quota -x -c 'state -p' "$expected_mount")
  printf '%s\n' "$quota_state" | grep -Eq 'Accounting:[[:space:]]+ON' || {
    echo "$expected_mount project-quota accounting is not enabled" >&2
    exit 1
  }
  printf '%s\n' "$quota_state" | grep -Eq 'Enforcement:[[:space:]]+ON' || {
    echo "$expected_mount project-quota enforcement is not enabled" >&2
    exit 1
  }
  [ "$(awk -F: '$1 == "containers" {print}' /etc/subuid)" = containers:1000000:1048576 ] &&
    [ "$(awk -F: '$1 == "containers" {print}' /etc/subgid)" = containers:1000000:1048576 ] || {
      echo "owner_pc_beta requires the exact containers:1000000:1048576 subordinate-ID maps" >&2
      exit 1
    }
  default_inode_record=$(/usr/sbin/xfs_quota -x \
    -c 'quota -p -i -n -N -v 0' "$expected_mount")
  printf '%s\n' "$default_inode_record" | awk '
    NF >= 4 && $3 == 1048576 && $4 == 1048576 { found = 1 }
    END { exit(found ? 0 : 1) }
  ' || {
    echo "owner_pc_beta requires the 1048576-inode default project ceiling" >&2
    exit 1
  }
  volume_gate=/usr/local/libexec/codex-mobile/owner-pc-workspace-volume-gate
  [ -x "$volume_gate" ] || {
    echo "owner_pc_beta requires the singleton quota-volume gate" >&2
    exit 1
  }
  if [ "${CODEX_MOBILE_GATE_ROOT_VERIFIED:-}" != 1 ]; then
    "$volume_gate" verify
    # Root-local Podman inspection can release the two private dev-capable
    # self-binds. Restore them before this verifier performs another local
    # Podman operation or the long-lived API creates a container.
    /usr/local/libexec/codex-mobile/prepare-workspace-overlay-quota
  fi
else
  [ "$workspace_io_device" = "$mount_source" ] || {
    echo "WORKSPACE_IO_DEVICE must exactly match findmnt SOURCE $mount_source" >&2
    exit 1
  }
fi

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
owner_id_map_starts=
[ "$deployment_profile" != owner_pc_beta ] ||
  /usr/local/libexec/codex-mobile/prepare-workspace-overlay-quota
managed_containers=$(/usr/bin/podman ps --all \
  --filter label=com.codex-mobile.managed=true --format '{{.Names}}')
[ "$deployment_profile" != owner_pc_beta ] ||
  /usr/local/libexec/codex-mobile/prepare-workspace-overlay-quota
relay_containers=$(/usr/bin/podman ps --all \
  --filter label=com.codex-mobile.container-role=workspace-relay \
  --format '{{.Names}}')
if [ "$deployment_profile" = owner_pc_beta ]; then
  managed_count=$(printf '%s\n' "$managed_containers" | awk 'NF {count++} END {print count+0}')
  relay_count=$(printf '%s\n' "$relay_containers" | awk 'NF {count++} END {print count+0}')
  [ "$managed_count" -le 1 ] || {
    echo "owner_pc_beta permits at most one managed workspace container" >&2
    exit 1
  }
  [ "$relay_count" -le 1 ] || {
    echo "owner_pc_beta permits at most one workspace relay container" >&2
    exit 1
  }
fi
for relay_container in $relay_containers; do
  [ "$deployment_profile" != owner_pc_beta ] ||
    /usr/local/libexec/codex-mobile/prepare-workspace-overlay-quota
  relay_inspect_json=$(/usr/bin/podman inspect "$relay_container")
  printf '%s\n' "$relay_inspect_json" | /usr/bin/jq --exit-status \
    --arg profile "$deployment_profile" '
      def owner_id_map:
        length == 1 and
        (.[0] | split(":")) as $parts |
        $parts | length == 3 and
        $parts[0] == "0" and
        $parts[2] == "65536" and
        ($parts[1] | tonumber) >= 1000000 and
        (($parts[1] | tonumber) + 65536) <= 2048576;
      .[0] as $c |
      $c.Config.Labels["com.codex-mobile.container-role"] == "workspace-relay" and
      $c.Config.Labels["com.codex-mobile.control-relay-workspace-id"] ==
        $c.Config.Labels["com.codex-mobile.workspace-id"] and
      $c.Config.Labels["com.codex-mobile.pids-limit"] == "512" and
      $c.Config.Labels["com.codex-mobile.cpu-millis"] == "100" and
      $c.Config.Labels["com.codex-mobile.memory-mib"] == "64" and
      $c.Config.Labels["com.codex-mobile.profile"] == $profile and
      $c.HostConfig.PidsLimit == 512 and
      $c.HostConfig.Memory == 67108864 and
      $c.HostConfig.MemorySwap == 67108864 and
      $c.HostConfig.CpuPeriod == 100000 and
      $c.HostConfig.CpuQuota == 10000 and
      $c.HostConfig.ReadonlyRootfs == true and
      $c.HostConfig.UsernsMode == "private" and
      any($c.HostConfig.CapDrop[]?; ascii_upcase == "ALL") and
      all($c.HostConfig.CapAdd[]?; false) and
      any($c.HostConfig.SecurityOpt[]?; startswith("no-new-privileges")) and
      (if $profile == "owner_pc_beta"
       then ($c.HostConfig.IDMappings.UidMap | owner_id_map) and
            ($c.HostConfig.IDMappings.GidMap | owner_id_map) and
            $c.HostConfig.IDMappings.UidMap == $c.HostConfig.IDMappings.GidMap and
            all($c.HostConfig.SecurityOpt[]?; startswith("apparmor=") | not)
       else any($c.HostConfig.SecurityOpt[]?; . == "apparmor=container-default")
       end)
    ' >/dev/null || {
      echo "workspace relay $relay_container violates the current runtime policy" >&2
      exit 1
    }
  if [ "$deployment_profile" = owner_pc_beta ]; then
    relay_map_start=$(printf '%s\n' "$relay_inspect_json" |
      /usr/bin/jq -r '.[0].HostConfig.IDMappings.UidMap[0] | split(":")[1]')
    owner_id_map_starts="${owner_id_map_starts}${relay_map_start}
"
  fi
done
for managed_container in $managed_containers; do
  [ "$deployment_profile" != owner_pc_beta ] ||
    /usr/local/libexec/codex-mobile/prepare-workspace-overlay-quota
  inspect_json=$(/usr/bin/podman inspect "$managed_container")
  printf '%s\n' "$inspect_json" | /usr/bin/jq --exit-status \
    --arg device "$workspace_io_device_inspect" \
    --arg profile "$deployment_profile" '
      def owner_id_map:
        length == 1 and
        (.[0] | split(":")) as $parts |
        $parts | length == 3 and
        $parts[0] == "0" and
        $parts[2] == "65536" and
        ($parts[1] | tonumber) >= 1000000 and
        (($parts[1] | tonumber) + 65536) <= 2048576;
      .[0] as $c |
      $c.Config.Labels["com.codex-mobile.container-role"] == "workspace-workload" and
      $c.Config.Labels["com.codex-mobile.pids-limit"] == "512" and
      $c.Config.Labels["com.codex-mobile.profile"] == $profile and
      $c.HostConfig.PidsLimit == 512 and
      $c.HostConfig.UsernsMode == "private" and
      (if $profile == "owner_pc_beta"
       then $c.Config.Labels["com.codex-mobile.cpu-millis"] == "2000" and
            $c.Config.Labels["com.codex-mobile.memory-mib"] == "2048" and
            $c.HostConfig.Memory == 2147483648 and
            $c.HostConfig.CpuQuota == 200000 and
            ($c.HostConfig.IDMappings.UidMap | owner_id_map) and
            ($c.HostConfig.IDMappings.GidMap | owner_id_map) and
            $c.HostConfig.IDMappings.UidMap == $c.HostConfig.IDMappings.GidMap and
            all($c.HostConfig.SecurityOpt[]?; startswith("apparmor=") | not)
       else $c.HostConfig.Memory >= 1610612736 and
            $c.HostConfig.Memory <= 19327352832
       end) and
      $c.HostConfig.MemorySwap == $c.HostConfig.Memory and
      $c.HostConfig.CpuPeriod == 100000 and
      $c.HostConfig.CpuQuota >= 50000 and
      $c.HostConfig.CpuQuota <= 800000 and
      any($c.HostConfig.BlkioDeviceReadBps[]?; .Path == $device and .Rate == 67108864) and
      any($c.HostConfig.BlkioDeviceWriteBps[]?; .Path == $device and .Rate == 33554432) and
      any($c.HostConfig.BlkioDeviceReadIOps[]?; .Path == $device and .Rate == 2000) and
      any($c.HostConfig.BlkioDeviceWriteIOps[]?; .Path == $device and .Rate == 1000) and
      (if $c.Config.Labels["com.codex-mobile.envbuilder-version"] == "1.3.0-codex-mobile.1"
       then $c.HostConfig.ReadonlyRootfs == false and
            $c.HostConfig.StorageOpt.size == "4G" and
            $c.HostConfig.StorageOpt.inodes == "262144"
       else $c.HostConfig.ReadonlyRootfs == true
       end)
    ' >/dev/null || {
      echo "managed workspace $managed_container violates the current runtime admission policy" >&2
      exit 1
    }
  if [ "$deployment_profile" = owner_pc_beta ]; then
    managed_map_start=$(printf '%s\n' "$inspect_json" |
      /usr/bin/jq -r '.[0].HostConfig.IDMappings.UidMap[0] | split(":")[1]')
    owner_id_map_starts="${owner_id_map_starts}${managed_map_start}
"
  fi
done

if [ "$deployment_profile" = owner_pc_beta ]; then
  map_count=$(printf '%s' "$owner_id_map_starts" |
    awk 'NF {count++} END {print count+0}')
  unique_map_count=$(printf '%s' "$owner_id_map_starts" |
    awk 'NF {print}' | sort -u | awk 'NF {count++} END {print count+0}')
  [ "$map_count" -eq "$unique_map_count" ] || {
    echo "owner_pc_beta containers must have distinct subordinate-ID mappings" >&2
    exit 1
  }
fi

exit 0
