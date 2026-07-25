#!/bin/sh
set -eu

repo_root=${REPO_ROOT:-/opt/codex-mobile/current}
env_file=${ENV_FILE:-/etc/codex-mobile/production.env}
podman_url=${PODMAN_URL:-unix:///run/codex-mobile-podman/podman.sock}
containers_conf=${CONTAINERS_CONF:-/etc/codex-mobile/containers.conf}
base_image=${WORKSPACE_BASE_IMAGE:-localhost/codex-mobile/workspace-base:2026-07-15}
envbuilder_image=${ENVBUILDER_IMAGE:-localhost/codex-mobile/envbuilder:1.3.0-helper-2026-07-15}
prefix=cm-spike-$$
volume_a=$prefix-a
volume_b=$prefix-b
envbuilder_volume=$prefix-envbuilder
plain_helper_volume=$prefix-helper-plain
envbuilder_helper_volume=$prefix-helper-envbuilder
quota_volume=$prefix-quota

cleanup() {
  podman --url "$podman_url" rm --force \
    "$prefix-rootfs-quota" "$prefix-envbuilder" >/dev/null 2>&1 || true
  podman --url "$podman_url" volume rm --force \
    "$volume_a" "$volume_b" "$envbuilder_volume" \
    "$plain_helper_volume" "$envbuilder_helper_volume" "$quota_volume" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

env_value() {
  awk -F= -v key="$1" '$1 == key {sub(/^[^=]*=/, ""); print; found=1} END {if (!found) exit 1}' "$env_file"
}

[ "$(uname -s)" = Linux ] || { echo "SKIP: Linux host required"; exit 77; }
[ "$(id -u)" -eq 0 ] || { echo "run as root on the configured VPS" >&2; exit 1; }
[ -r "$containers_conf" ] || { echo "dedicated workspace containers.conf is missing" >&2; exit 1; }
CONTAINERS_CONF=$containers_conf
export CONTAINERS_CONF
grep -q '^ID=ubuntu$' /etc/os-release || { echo "Ubuntu host required" >&2; exit 1; }
grep -q '^VERSION_ID="24.04"$' /etc/os-release || { echo "Ubuntu 24.04 required" >&2; exit 1; }
[ "$(stat -fc %T /sys/fs/cgroup)" = cgroup2fs ] || { echo "cgroup v2 is required" >&2; exit 1; }
if ! { [ -r /sys/module/apparmor/parameters/enabled ] && grep -q '^Y' /sys/module/apparmor/parameters/enabled; }; then
  echo "enforcing AppArmor support is required" >&2
  exit 1
fi
podman --url "$podman_url" info >/dev/null
if [ "$(podman --url "$podman_url" info --format '{{.Host.Security.Rootless}}')" != false ]; then
  echo "workspace engine must be the dedicated rootful quota runtime" >&2
  exit 1
fi
workspace_io_device=$(env_value WORKSPACE_IO_DEVICE)
workspace_read_bps=67108864
workspace_write_bps=33554432
workspace_read_iops=2000
workspace_write_iops=1000
WORKSPACE_IO_DEVICE=$workspace_io_device \
WORKSPACE_STORAGE_ROOT=${WORKSPACE_STORAGE_ROOT:-/srv/codex-mobile/workspaces} \
  WORKSPACE_STORAGE_MOUNT=${WORKSPACE_STORAGE_MOUNT:-/srv/codex-mobile} \
  /bin/sh "$repo_root/infra/systemd/verify-workspace-storage.sh"

REPO_ROOT="$repo_root" PODMAN_URL="$podman_url" WORKSPACE_BASE_IMAGE="$base_image" \
  /bin/sh "$repo_root/scripts/infra-build-workspace-image.sh"

# Inspect the containers created by the imported Terraform template, not an
# unrelated hand-written limits container. At least one real workspace must be
# running so the kernel cgroup files can be checked in addition to HostConfig.
workspace_containers=$(podman --url "$podman_url" ps --all \
  --filter label=com.codex-mobile.managed=true --format '{{.Names}}')
[ -n "$workspace_containers" ] || {
  echo "create and start a disposable workspace from the imported template before running the Linux spike" >&2
  exit 1
}
running_workspace_seen=false
for workspace_container in $workspace_containers; do
  case "$workspace_container" in
    cm-ws-*) ;;
    *) echo "managed workspace has an unexpected container name: $workspace_container" >&2; exit 1 ;;
  esac
  inspect_json=$(podman --url "$podman_url" inspect "$workspace_container")
  printf '%s\n' "$inspect_json" | jq --exit-status \
    --arg device "$workspace_io_device" \
    --argjson read_bps "$workspace_read_bps" \
    --argjson write_bps "$workspace_write_bps" \
    --argjson read_iops "$workspace_read_iops" \
    --argjson write_iops "$workspace_write_iops" '
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
      any($c.HostConfig.BlkioDeviceReadBps[]?; .Path == $device and .Rate == $read_bps) and
      any($c.HostConfig.BlkioDeviceWriteBps[]?; .Path == $device and .Rate == $write_bps) and
      any($c.HostConfig.BlkioDeviceReadIOps[]?; .Path == $device and .Rate == $read_iops) and
      any($c.HostConfig.BlkioDeviceWriteIOps[]?; .Path == $device and .Rate == $write_iops) and
      (if $c.Config.Labels["com.codex-mobile.envbuilder-version"] == "1.3.0"
       then $c.HostConfig.ReadonlyRootfs == false and
            $c.HostConfig.StorageOpt.size == "4G" and
            $c.HostConfig.StorageOpt.inodes == "262144"
       else $c.HostConfig.ReadonlyRootfs == true
       end)
    ' >/dev/null || {
      echo "template-created workspace $workspace_container is missing a required runtime ceiling" >&2
      exit 1
    }

  if [ "$(printf '%s\n' "$inspect_json" | jq -r '.[0].State.Running')" = true ]; then
    running_workspace_seen=true
    workspace_pid=$(printf '%s\n' "$inspect_json" | jq -r '.[0].State.Pid')
    case "$workspace_pid" in
      ''|0|*[!0-9]*) echo "running workspace has no valid host PID" >&2; exit 1 ;;
    esac
    cgroup_path=$(awk -F: '$1 == "0" {print $3}' "/proc/$workspace_pid/cgroup")
    case "$cgroup_path" in
      /*) ;;
      *) echo "cannot resolve workspace cgroup v2 path" >&2; exit 1 ;;
    esac
    cgroup_directory="/sys/fs/cgroup$cgroup_path"
    case "$cgroup_directory" in
      /sys/fs/cgroup|/sys/fs/cgroup/*) ;;
      *) echo "workspace cgroup escaped the unified hierarchy" >&2; exit 1 ;;
    esac
    pids_policy_seen=false
    io_policy_seen=false
    while :; do
      if [ -r "$cgroup_directory/pids.max" ]; then
        pids_value=$(cat "$cgroup_directory/pids.max")
        [ "$pids_value" = 512 ] && pids_policy_seen=true
      fi
      if [ -r "$cgroup_directory/io.max" ]; then
        io_policy=$(cat "$cgroup_directory/io.max")
        if printf '%s\n' "$io_policy" | awk \
          -v rbps="$workspace_read_bps" -v wbps="$workspace_write_bps" \
          -v riops="$workspace_read_iops" -v wiops="$workspace_write_iops" '
            $0 ~ ("(^| )rbps=" rbps "( |$)") &&
            $0 ~ ("(^| )wbps=" wbps "( |$)") &&
            $0 ~ ("(^| )riops=" riops "( |$)") &&
            $0 ~ ("(^| )wiops=" wiops "( |$)") { found=1 }
            END { exit(found ? 0 : 1) }
          '; then
          io_policy_seen=true
        fi
      fi
      [ "$cgroup_directory" = /sys/fs/cgroup ] && break
      cgroup_directory=${cgroup_directory%/*}
    done
    [ "$pids_policy_seen" = true ] || {
      echo "template-created workspace $workspace_container lacks cgroup pids.max=512" >&2
      exit 1
    }
    [ "$io_policy_seen" = true ] || {
        echo "template-created workspace $workspace_container lacks the required cgroup I/O maxima" >&2
        exit 1
    }
  fi
done
[ "$running_workspace_seen" = true ] || {
  echo "at least one template-created workspace must be running for live cgroup inspection" >&2
  exit 1
}

# Prove that this exact engine enforces the XFS project quota, not merely that
# the mount advertises pquota. A small write first distinguishes a working
# private mount from an unrelated container failure. The larger write must then
# fail specifically with EDQUOT after filling the disposable bounded volume.
podman --url "$podman_url" volume create \
  --opt o=size=8M,inodes=1024 "$quota_volume" >/dev/null
podman --url "$podman_url" run --rm --network none --read-only --user 1000:1000 \
  --userns private --cap-drop all --security-opt no-new-privileges \
  --volume "$quota_volume:/workspaces" "$base_image" \
  /bin/sh -ec 'printf quota-ready > /workspaces/quota-probe'
if quota_error=$(podman --url "$podman_url" run --rm --network none --read-only --user 1000:1000 \
  --userns private --cap-drop all --security-opt no-new-privileges \
  --volume "$quota_volume:/workspaces" "$base_image" \
  /bin/sh -ec 'LC_ALL=C dd if=/dev/zero of=/workspaces/quota-fill bs=1M count=16 status=none' 2>&1); then
  echo "Podman accepted a write beyond the disposable volume quota" >&2
  exit 1
fi
printf '%s\n' "$quota_error" | grep -Eqi 'disk quota exceeded|quota exceeded' || {
  echo "quota fill failed for a reason other than XFS project enforcement: $quota_error" >&2
  exit 1
}

# EnvBuilder's root filesystem is writable, so separately prove this engine's
# overlay `size` option is an enforced XFS project quota. The production
# template uses 4 GiB; this disposable probe uses 8 MiB to fail quickly.
if rootfs_quota_error=$(podman --url "$podman_url" run --name "$prefix-rootfs-quota" \
  --network none --user 0:0 --userns private --cap-drop all \
  --security-opt no-new-privileges --storage-opt size=8M --storage-opt inodes=1024 \
  "$base_image" /bin/sh -ec \
  'LC_ALL=C dd if=/dev/zero of=/tmp/rootfs-quota-fill bs=1M count=16 status=none' 2>&1); then
  echo "Podman accepted a write beyond the disposable rootfs overlay quota" >&2
  exit 1
fi
printf '%s\n' "$rootfs_quota_error" | grep -Eqi 'disk quota exceeded|quota exceeded' || {
  echo "rootfs fill failed for a reason other than XFS project enforcement: $rootfs_quota_error" >&2
  exit 1
}
podman --url "$podman_url" rm --force "$prefix-rootfs-quota" >/dev/null

case "$(podman --url "$podman_url" info --format '{{.Host.Arch}}')" in
  amd64|x86_64) helper_sha256=f6fc430a2200d13ee0ef04dd576875b4f9a7c95a04287cbdec2deec3b495493c ;;
  arm64|aarch64) helper_sha256=c7e4577a465b55721043612f9b6919248806576816388b01898f6c2784dc163e ;;
  *) echo "unsupported workspace-helper architecture" >&2; exit 1 ;;
esac

# An empty named volume receives the trusted image contents on first mount and
# is immutable to the workspace, including a process running as container root.
podman --url "$podman_url" volume create "$plain_helper_volume" >/dev/null
podman --url "$podman_url" run --rm --network none --read-only --user 0:0 \
  --cap-drop all --security-opt no-new-privileges \
  --volume "$plain_helper_volume:/opt/codex-mobile-helper:ro" \
  "$base_image" /bin/sh -ec '
    test -x /opt/codex-mobile-helper/codex-mobile-workspace-helper
    test -x /opt/codex-mobile-helper/codex-real
    test -x /opt/codex-mobile-helper/codex-code-mode-host
    test -r /opt/codex-mobile-helper/ca-certificates.crt
    test "$(stat -c '%u:%g:%a' /opt/codex-mobile-helper/ca-certificates.crt)" = 0:0:444
    test "$(readlink /opt/codex-mobile-helper/codex)" = codex-mobile-workspace-helper
    /opt/codex-mobile-helper/codex-real --version | grep -F "codex-cli 0.144.5"
    ! rm -f /opt/codex-mobile-helper/codex-mobile-workspace-helper
    ! rm -f /opt/codex-mobile-helper/codex-real
  '
actual_helper_sha256=$(podman --url "$podman_url" run --rm --network none --read-only \
  --cap-drop all --security-opt no-new-privileges \
  --volume "$plain_helper_volume:/opt/codex-mobile-helper:ro" \
  "$base_image" sha256sum /opt/codex-mobile-helper/codex-mobile-workspace-helper | awk '{print $1}')
[ "$actual_helper_sha256" = "$helper_sha256" ] || {
  echo "protected plain helper volume has the wrong contents" >&2; exit 1;
}

# A private host bind is useful only if a workspace can reach it. This
# is the exact path the Coder agent uses; the public API never exposes Coder.
coder_access_url=$(env_value CODER_ACCESS_URL)
podman --url "$podman_url" run --rm --read-only --user 1000:1000 \
  --userns private \
  --cap-drop all --security-opt no-new-privileges --memory 256m --pids-limit 64 \
  "$base_image" curl --fail --silent --show-error --max-time 10 \
  "$coder_access_url/healthz" >/dev/null

podman --url "$podman_url" volume create "$volume_a" >/dev/null
podman --url "$podman_url" volume create "$volume_b" >/dev/null
marker=$(openssl rand -hex 24)
podman --url "$podman_url" run --rm --network none --read-only --user 1000:1000 \
  --userns private \
  --cap-drop all --security-opt no-new-privileges --security-opt apparmor=container-default \
  --memory 256m --cpus 0.5 --pids-limit 64 --volume "$volume_a:/workspaces" \
  "$base_image" /bin/sh -ec "printf '%s' '$marker' > /workspaces/isolation-marker"

podman --url "$podman_url" run --rm --network none --read-only --user 1000:1000 \
  --userns private \
  --cap-drop all --security-opt no-new-privileges --security-opt apparmor=container-default \
  --memory 256m --cpus 0.5 --pids-limit 64 --volume "$volume_b:/workspaces" \
  "$base_image" /bin/sh -ec '
    test "$(id -u)" = 1000
    test ! -e /workspaces/isolation-marker
    test ! -e /run/docker.sock
    ! cat /etc/shadow >/dev/null 2>&1
    ! touch /rootfs-write-test >/dev/null 2>&1
    ! curl --silent --max-time 2 http://1.1.1.1 >/dev/null 2>&1
  '

# EnvBuilder is intentionally exercised against a tiny local Dev Container.
# This test performs no privileged mount and receives no engine socket.
podman --url "$podman_url" volume create "$envbuilder_volume" >/dev/null
podman --url "$podman_url" volume create "$envbuilder_helper_volume" >/dev/null
podman --url "$podman_url" run --rm --network none --user 0:0 \
  --volume "$envbuilder_volume:/workspaces" --volume "$repo_root/infra/tests/fixtures/devcontainer:/fixture:ro" \
  "$base_image" /bin/sh -ec 'cp -R /fixture/. /workspaces/repository/'
podman --url "$podman_url" run --name "$prefix-envbuilder" \
  --memory 1536m --memory-swap 1536m --cpu-period 100000 --cpu-quota 50000 \
  --storage-opt size=4G --storage-opt inodes=262144 \
  --userns private --security-opt no-new-privileges \
  --device-read-bps "$workspace_io_device:$workspace_read_bps" \
  --device-write-bps "$workspace_io_device:$workspace_write_bps" \
  --device-read-iops "$workspace_io_device:$workspace_read_iops" \
  --device-write-iops "$workspace_io_device:$workspace_write_iops" \
  --security-opt apparmor=container-default --cap-drop all \
  --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER --cap-add FSETID \
  --cap-add SETFCAP --cap-add SETGID --cap-add SETUID --cap-add SYS_CHROOT \
  --volume "$envbuilder_volume:/workspaces" \
  --volume "$envbuilder_helper_volume:/opt/codex-mobile-helper:ro" \
  --env ENVBUILDER_WORKSPACE_FOLDER=/workspaces/repository \
  --env ENVBUILDER_DEVCONTAINER_DIR=/workspaces/repository/.devcontainer \
  --env ENVBUILDER_FALLBACK_IMAGE="$base_image" \
  --env ENVBUILDER_IGNORE_PATHS=/var/run,/product_uuid,/product_name,/opt/codex-mobile-helper \
  --env ENVBUILDER_EXIT_ON_BUILD_FAILURE=true \
  --env ENVBUILDER_PUSH_IMAGE=false \
  --env ENVBUILDER_INSECURE=false \
  --env 'ENVBUILDER_INIT_SCRIPT=touch /workspaces/repository/.agent-init-ok' \
  --env "ENVBUILDER_SETUP_SCRIPT=test \"\${TARGET_USER:-root}\" != root; printf '%s  %s\\n' '$helper_sha256' /opt/codex-mobile-helper/codex-mobile-workspace-helper | sha256sum -c -; /opt/codex-mobile-helper/codex-real --version | grep -F 'codex-cli 0.144.5'; ! rm -f /opt/codex-mobile-helper/codex-mobile-workspace-helper; ! rm -f /opt/codex-mobile-helper/codex-real" \
  "$envbuilder_image"
envbuilder_inspect=$(podman --url "$podman_url" inspect "$prefix-envbuilder")
printf '%s\n' "$envbuilder_inspect" | jq --exit-status \
  --arg device "$workspace_io_device" \
  --argjson read_bps "$workspace_read_bps" \
  --argjson write_bps "$workspace_write_bps" \
  --argjson read_iops "$workspace_read_iops" \
  --argjson write_iops "$workspace_write_iops" '
    .[0] as $c |
    $c.HostConfig.PidsLimit == 512 and
    $c.HostConfig.Memory == 1610612736 and
    $c.HostConfig.MemorySwap == $c.HostConfig.Memory and
    $c.HostConfig.CpuPeriod == 100000 and
    $c.HostConfig.CpuQuota == 50000 and
    $c.HostConfig.StorageOpt.size == "4G" and
    $c.HostConfig.StorageOpt.inodes == "262144" and
    any($c.HostConfig.BlkioDeviceReadBps[]?; .Path == $device and .Rate == $read_bps) and
    any($c.HostConfig.BlkioDeviceWriteBps[]?; .Path == $device and .Rate == $write_bps) and
    any($c.HostConfig.BlkioDeviceReadIOps[]?; .Path == $device and .Rate == $read_iops) and
    any($c.HostConfig.BlkioDeviceWriteIOps[]?; .Path == $device and .Rate == $write_iops)
  ' >/dev/null || {
    echo "representative EnvBuilder container did not receive the runtime default and template resource limits" >&2
    exit 1
  }
podman --url "$podman_url" rm --force "$prefix-envbuilder" >/dev/null
podman --url "$podman_url" run --rm --network none --user 1000:1000 \
  --volume "$envbuilder_volume:/workspaces" "$base_image" \
  test -f /workspaces/repository/.agent-init-ok

actual_helper_sha256=$(podman --url "$podman_url" run --rm --network none --read-only \
  --cap-drop all --security-opt no-new-privileges \
  --volume "$envbuilder_helper_volume:/opt/codex-mobile-helper:ro" \
  "$base_image" sha256sum /opt/codex-mobile-helper/codex-mobile-workspace-helper | awk '{print $1}')
[ "$actual_helper_sha256" = "$helper_sha256" ] || {
  echo "protected EnvBuilder helper volume was not seeded or was modified" >&2; exit 1;
}

echo "Linux template workspace cgroups/I/O, private Podman isolation, XFS volume/rootfs quotas, and EnvBuilder spike: PASS"
