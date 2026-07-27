#!/bin/sh
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset CDPATH ENV BASH_ENV PYTHONHOME PYTHONPATH PYTHONSTARTUP LD_LIBRARY_PATH LD_PRELOAD

usage() {
  echo "usage: $0 --initialize" >&2
  exit 2
}

[ "${1:-}" = --initialize ] && [ "$#" -eq 1 ] || usage
[ "$(id -u)" -eq 0 ] || {
  echo "owner-PC WSL setup must run as root" >&2
  exit 1
}
grep -qi microsoft /proc/sys/kernel/osrelease || {
  echo "owner_pc_beta requires WSL2" >&2
  exit 1
}
if ! grep -q '^ID=ubuntu$' /etc/os-release ||
  ! grep -q '^VERSION_ID="24.04"$' /etc/os-release; then
    echo "owner_pc_beta requires Ubuntu 24.04" >&2
    exit 1
fi
[ "$(stat -fc %T /sys/fs/cgroup)" = cgroup2fs ] || {
  echo "owner_pc_beta requires cgroup v2" >&2
  exit 1
}

repo_root=${REPO_ROOT:-$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)}
if [ -e /opt/codex-mobile/current ] || [ -L /opt/codex-mobile/current ]; then
  echo "owner-PC source bootstrap is forbidden after a release activation" >&2
  echo "use the manifest-verified update or rollback workflow instead" >&2
  exit 1
fi
for relative in \
  infra/containers.conf \
  infra/containers-storage.conf \
  infra/systemd/apply-docker-firewall.sh \
  infra/systemd/codex-mobile-docker-firewall.service \
  infra/systemd/codex-mobile-owner-pc-runtime.service \
  infra/systemd/codex-mobile-provisioner.service \
  infra/systemd/codex-mobile-workspace-runtime.service \
  infra/systemd/codex-mobile.service \
  infra/systemd/ensure-workspace-control-network.py \
  infra/systemd/finalize-workspace-runtime-socket.sh \
  infra/systemd/owner-pc-workspace-volume-gate.py \
  infra/systemd/prepare-owner-pc-runtime.sh \
  infra/systemd/prepare-workspace-overlay-quota.sh \
  infra/systemd/start-provisioner.sh \
  infra/systemd/start-workspace-runtime.sh \
  infra/systemd/verify-workspace-storage.sh; do
  [ -f "$repo_root/$relative" ] && [ ! -L "$repo_root/$relative" ] || {
    echo "REPO_ROOT has a missing or symlinked bootstrap artifact: $relative" >&2
    exit 1
  }
done

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates curl docker.io docker-compose-v2 iproute2 iptables jq \
  git gzip openssl podman python3-yaml tar uidmap util-linux xfsprogs
if [ ! -x /usr/bin/git ] || ! /usr/bin/git --version >/dev/null; then
  echo "owner_pc_beta requires Git for immutable source staging" >&2
  exit 1
fi
[ "$(/usr/bin/podman --version)" = "podman version 4.9.3" ] || {
  echo "owner_pc_beta requires the reviewed Podman 4.9.3 runtime" >&2
  exit 1
}

getent group containers >/dev/null || groupadd --system containers
if ! getent passwd containers >/dev/null; then
  useradd --system --gid containers --home-dir /nonexistent \
    --no-create-home --shell /usr/sbin/nologin containers
fi
[ "$(id -gn containers)" = containers ] &&
  [ "$(getent passwd containers | awk -F: '{print $6 ":" $7}')" = \
    /nonexistent:/usr/sbin/nologin ] || {
    echo "containers must use group containers, /nonexistent, and /usr/sbin/nologin" >&2
    exit 1
  }

configure_container_subid() {
  database=$1
  option=$2
  [ -f "$database" ] && [ ! -L "$database" ] || {
    echo "$database must be an existing non-symlink file" >&2
    exit 1
  }
  container_records=$(awk -F: '$1 == "containers" {print}' "$database")
  awk -F: '
    $1 != "containers" {
      first = $2 + 0
      last = first + $3 - 1
      if (first <= 2048575 && last >= 1000000) exit 1
    }
  ' "$database" || {
    echo "$database contains a subordinate-ID range overlapping 1000000-2048575" >&2
    exit 1
  }
  if [ -z "$container_records" ]; then
    usermod "$option" 1000000-2048575 containers
    container_records=$(awk -F: '$1 == "containers" {print}' "$database")
  fi
  [ "$container_records" = containers:1000000:1048576 ] || {
    echo "$database must contain exactly containers:1000000:1048576" >&2
    exit 1
  }
}
configure_container_subid /etc/subuid --add-subuids
configure_container_subid /etc/subgid --add-subgids

getent group codex-mobile >/dev/null || groupadd --system codex-mobile
if ! getent passwd codex-deploy >/dev/null; then
  useradd --system --gid codex-mobile --home-dir /var/lib/codex-mobile-deploy \
    --create-home --shell /bin/bash codex-deploy
fi
[ "$(id -gn codex-deploy)" = codex-mobile ] &&
  [ "$(getent passwd codex-deploy | awk -F: '{print $6 ":" $7}')" = \
    /var/lib/codex-mobile-deploy:/bin/bash ] || {
    echo "codex-deploy must use group codex-mobile, the reviewed home, and /bin/bash" >&2
    exit 1
  }
getent group coder-provisioner >/dev/null || groupadd --system coder-provisioner
if ! getent passwd coder-provisioner >/dev/null; then
  useradd --system --gid coder-provisioner \
    --home-dir /srv/codex-mobile/workspaces/.provisioner-home \
    --shell /usr/sbin/nologin coder-provisioner
fi
[ "$(id -gn coder-provisioner)" = coder-provisioner ] &&
  [ "$(getent passwd coder-provisioner | awk -F: '{print $6 ":" $7}')" = \
    /srv/codex-mobile/workspaces/.provisioner-home:/usr/sbin/nologin ] || {
    echo "coder-provisioner must use its isolated group, home, and nologin shell" >&2
    exit 1
  }

install -d -o root -g root -m 0750 /etc/codex-mobile
install -d -o root -g root -m 0700 /etc/codex-mobile/secrets
install -d -o root -g root -m 0755 /usr/local/libexec/codex-mobile
install -d -o root -g root -m 0700 /var/lib/codex-mobile-owner-pc
install -d -o codex-deploy -g codex-mobile -m 0750 /var/lib/codex-mobile-deploy
install -d -o root -g root -m 0755 /opt/codex-mobile
install -d -o root -g root -m 0755 /opt/codex-mobile/releases
install -d -o codex-deploy -g codex-mobile -m 02770 /opt/codex-mobile/staging
install -d -o root -g root -m 0700 /opt/codex-mobile/activations
install -d -o root -g root -m 0700 \
  /var/cache/codex-mobile \
  /var/cache/codex-mobile/downloads \
  /var/cache/codex-mobile/trivy
install -d -o root -g coder-provisioner -m 0710 /run/codex-mobile-podman
install_pinned_archive() (
  name=$1
  url=$2
  archive_sha256=$3
  executable_sha256=$4
  archive=/var/cache/codex-mobile/downloads/$name.tar.gz
  download=
  extraction=
  installed=
  # shellcheck disable=SC2329 # Invoked indirectly by trap.
  cleanup() {
    [ -z "$download" ] || rm -f -- "$download"
    [ -z "$installed" ] || rm -f -- "$installed"
    if [ -n "$extraction" ]; then
      rm -f -- "$extraction/$name"
      rmdir -- "$extraction" 2>/dev/null || true
    fi
  }
  trap cleanup EXIT HUP INT TERM

  if [ -e "$archive" ] || [ -L "$archive" ]; then
    if ! {
      [ -f "$archive" ] &&
        [ ! -L "$archive" ] &&
        [ "$(stat -c '%u:%g:%a:%h' "$archive")" = 0:0:600:1 ] &&
        printf '%s  %s\n' "$archive_sha256" "$archive" |
          sha256sum --check --status
    }; then
      echo "refusing unexpected cached $name archive" >&2
      exit 1
    fi
  else
    download=$(mktemp "/var/cache/codex-mobile/downloads/.$name.download.XXXXXX")
    curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
      --retry 3 --connect-timeout 15 --max-time 600 \
      --output "$download" "$url"
    printf '%s  %s\n' "$archive_sha256" "$download" |
      sha256sum --check --status || {
        echo "$name archive checksum does not match the reviewed pin" >&2
        exit 1
      }
    install -o root -g root -m 0600 "$download" "$archive"
    rm -f -- "$download"
    download=
  fi

  member=$(tar -tzf "$archive" |
    awk -v expected="$name" '$0 == expected || $0 == "./" expected {print}')
  [ "$member" = "$name" ] || [ "$member" = "./$name" ] || {
    echo "$name archive must contain exactly one top-level executable" >&2
    exit 1
  }
  extraction=$(mktemp -d "/var/cache/codex-mobile/downloads/.$name.extract.XXXXXX")
  tar -xzf "$archive" -C "$extraction" \
    --no-same-owner --no-same-permissions "$member"
  extracted="$extraction/${member#./}"
  [ -f "$extracted" ] && [ ! -L "$extracted" ] &&
    [ "$(stat -c '%h' "$extracted")" = 1 ] || {
      echo "$name archive did not yield a single-linked regular executable" >&2
      exit 1
    }
  if [ "$executable_sha256" != - ]; then
    printf '%s  %s\n' "$executable_sha256" "$extracted" |
      sha256sum --check --status || {
        echo "$name executable checksum does not match the reviewed pin" >&2
        exit 1
      }
  fi
  destination=/usr/local/bin/$name
  if [ -e "$destination" ] || [ -L "$destination" ]; then
    [ -f "$destination" ] && [ ! -L "$destination" ] || {
      echo "refusing unexpected installed path: $destination" >&2
      exit 1
    }
  fi
  installed=$(mktemp "/usr/local/bin/.$name.install.XXXXXX")
  install -o root -g root -m 0755 "$extracted" "$installed"
  mv -T -- "$installed" "$destination"
  installed=
)

case "$(uname -m)" in
  x86_64)
    coder_arch=amd64
    coder_archive_sha256=091acfd4356ab2f02bcaf561928841e9aecc630a28bc9678658d4ae47632df09
    trivy_arch=64bit
    trivy_archive_sha256=bbb64b9695866ce4a7a8f5c9592002c5961cab378577fa3f8a040df362b9b2ea
    trivy_executable_sha256=0e69edd134a3c338baa1a6806920773615d682b18cbc6a0cba2a3b658ef9b63e
    syft_arch=amd64
    syft_archive_sha256=d654f678b709eb53c393d38519d5ed7d2e57205529404018614cfefa0fb2b5ca
    syft_executable_sha256=574df1a0862ff88ad933be214e81069e35b17618a13e019f8f1c84fe063222a2
    ;;
  aarch64)
    coder_arch=arm64
    coder_archive_sha256=d16b0f9393404e1d85669ec620aa90d2a0c10b1977c11c95e11b2d6b9bb0917d
    trivy_arch=ARM64
    trivy_archive_sha256=2ca2c023109c2db6b2b77366b6717291452d4531167377d95c79547f0c8e3467
    trivy_executable_sha256=829aca12d32bc3cee0b01cbb76197e9377790c6b78eb67a703d8033bcf7b3c3d
    syft_arch=arm64
    syft_archive_sha256=9fafef4db4f032ce81008d3a1529985d41ceb6ccdf2b388c9ce2f1ed7d32082e
    syft_executable_sha256=9640d29da74a63de41d2cc2373ac2092462165ee99709f7d8dc3dea57a748b06
    ;;
  *) echo "owner_pc_beta supports only x86_64 or aarch64 WSL hosts" >&2; exit 1 ;;
esac

install_pinned_archive \
  coder \
  "https://github.com/coder/coder/releases/download/v2.34.6/coder_2.34.6_linux_${coder_arch}.tar.gz" \
  "$coder_archive_sha256" -
install_pinned_archive \
  trivy \
  "https://github.com/aquasecurity/trivy/releases/download/v0.72.0/trivy_0.72.0_Linux-${trivy_arch}.tar.gz" \
  "$trivy_archive_sha256" "$trivy_executable_sha256"
install_pinned_archive \
  syft \
  "https://github.com/anchore/syft/releases/download/v1.46.0/syft_1.46.0_linux_${syft_arch}.tar.gz" \
  "$syft_archive_sha256" "$syft_executable_sha256"

/usr/local/bin/coder version | grep -F 2.34.6 >/dev/null
/usr/local/bin/trivy --version --format json |
  /usr/bin/jq --exit-status '.Version == "0.72.0"' >/dev/null
/usr/local/bin/syft version --output json |
  /usr/bin/jq --exit-status \
    --arg platform "linux/$syft_arch" '
      .application == "syft" and
      .version == "1.46.0" and
      .gitCommit == "b15c5dbfe2bb21c9d73002c1056a829c8c411c75" and
      .platform == $platform
    ' >/dev/null
/usr/bin/docker compose version >/dev/null

for mapping in \
  'infra/containers.conf:/etc/codex-mobile/containers.conf:0600' \
  'infra/containers-storage.conf:/etc/codex-mobile/containers-storage.conf:0600' \
  'infra/systemd/apply-docker-firewall.sh:/usr/local/libexec/codex-mobile/apply-docker-firewall:0755' \
  'infra/systemd/ensure-workspace-control-network.py:/usr/local/libexec/codex-mobile/ensure-workspace-control-network:0755' \
  'infra/systemd/finalize-workspace-runtime-socket.sh:/usr/local/libexec/codex-mobile/finalize-workspace-runtime-socket:0755' \
  'infra/systemd/owner-pc-workspace-volume-gate.py:/usr/local/libexec/codex-mobile/owner-pc-workspace-volume-gate:0755' \
  'infra/systemd/prepare-owner-pc-runtime.sh:/usr/local/libexec/codex-mobile/prepare-owner-pc-runtime:0755' \
  'infra/systemd/prepare-workspace-overlay-quota.sh:/usr/local/libexec/codex-mobile/prepare-workspace-overlay-quota:0755' \
  'infra/systemd/start-provisioner.sh:/usr/local/libexec/codex-mobile/start-provisioner:0755' \
  'infra/systemd/start-workspace-runtime.sh:/usr/local/libexec/codex-mobile/start-workspace-runtime:0755' \
  'infra/systemd/verify-workspace-storage.sh:/usr/local/libexec/codex-mobile/verify-workspace-storage:0755' \
  'infra/systemd/codex-mobile-docker-firewall.service:/etc/systemd/system/codex-mobile-docker-firewall.service:0644' \
  'infra/systemd/codex-mobile-owner-pc-runtime.service:/etc/systemd/system/codex-mobile-owner-pc-runtime.service:0644' \
  'infra/systemd/codex-mobile-provisioner.service:/etc/systemd/system/codex-mobile-provisioner.service:0644' \
  'infra/systemd/codex-mobile-workspace-runtime.service:/etc/systemd/system/codex-mobile-workspace-runtime.service:0644' \
  'infra/systemd/codex-mobile.service:/etc/systemd/system/codex-mobile.service:0644'; do
  relative=${mapping%%:*}
  remainder=${mapping#*:}
  destination=${remainder%:*}
  mode=${mapping##*:}
  install -o root -g root -m "$mode" "$repo_root/$relative" "$destination"
done

image=/var/lib/codex-mobile-owner-pc/workspace-storage.xfs
expected_bytes=68719476736
if [ -e "$image" ] || [ -L "$image" ]; then
  [ -f "$image" ] && [ ! -L "$image" ] || {
    echo "refusing unexpected existing owner-PC storage path" >&2
    exit 1
  }
  [ "$(stat -c '%u:%g:%a:%h:%s' "$image")" = "0:0:600:1:$expected_bytes" ] || {
    echo "refusing to reuse owner-PC storage with unexpected metadata" >&2
    exit 1
  }
  [ "$(blkid -p -s TYPE -o value "$image")" = xfs ] || {
    echo "refusing to format or replace the existing non-XFS storage image" >&2
    exit 1
  }
else
  temporary="$image.creating.$$"
  cleanup() {
    rm -f -- "$temporary"
  }
  trap cleanup EXIT HUP INT TERM
  install -o root -g root -m 0600 /dev/null "$temporary"
  fallocate -l "$expected_bytes" "$temporary"
  allocated_bytes=$(( $(stat -c '%b' "$temporary") * 512 ))
  [ "$allocated_bytes" -ge "$expected_bytes" ] || {
    echo "storage allocation is sparse; refusing to continue" >&2
    exit 1
  }
  mkfs.xfs -f -L CODEXMOBILE "$temporary"
  mv -T -- "$temporary" "$image"
  trap - EXIT HUP INT TERM
fi

image_source=$(findmnt --noheadings --output SOURCE --target "$image" | tr -d '[:space:]')
[ -b "$image_source" ] || {
  echo "storage image must reside on the WSL Linux-native filesystem" >&2
  exit 1
}
root_uuid=$(blkid -s UUID -o value "$image_source")
case "$root_uuid" in
  ''|*[!A-Fa-f0-9-]*) echo "cannot resolve a stable UUID for the WSL root device" >&2; exit 1 ;;
esac
workspace_io_device="/dev/disk/by-uuid/$root_uuid"
[ -b "$workspace_io_device" ] || {
  echo "stable root-device UUID link is missing: $workspace_io_device" >&2
  exit 1
}

host_env=/etc/codex-mobile/owner-pc-host.env
temporary_env="$host_env.tmp.$$"
umask 077
{
  echo "DEPLOYMENT_PROFILE=owner_pc_beta"
  echo "DATA_ROOT=/srv/codex-mobile"
  echo "OWNER_PC_STORAGE_IMAGE=$image"
  echo "OWNER_PC_STORAGE_GIB=64"
  echo "WORKSPACE_IO_DEVICE=$workspace_io_device"
  echo "CODER_BIND_ADDRESS=10.86.0.1"
} >"$temporary_env"
chown root:root "$temporary_env"
chmod 0600 "$temporary_env"
mv -T -- "$temporary_env" "$host_env"

if [ -e /srv/codex-mobile ] || [ -L /srv/codex-mobile ]; then
  [ -d /srv/codex-mobile ] && [ ! -L /srv/codex-mobile ] || {
    echo "refusing unexpected existing /srv/codex-mobile path" >&2
    exit 1
  }
else
  install -d -o root -g root -m 0755 /srv/codex-mobile
fi
systemctl daemon-reload
systemctl enable --now docker.service
systemctl enable \
  codex-mobile-owner-pc-runtime.service \
  codex-mobile-docker-firewall.service \
  codex-mobile-workspace-runtime.service \
  codex-mobile.service \
  codex-mobile-provisioner.service
systemctl restart codex-mobile-owner-pc-runtime.service
# WSL interoperability shells use a sibling mount namespace to systemd's PID 1.
# Verify the mount from the same namespace that runs the product services.
nsenter --target 1 --mount -- \
  /usr/local/libexec/codex-mobile/prepare-owner-pc-runtime verify
nsenter --target 1 --mount -- \
  /usr/local/libexec/codex-mobile/owner-pc-workspace-volume-gate init
# Root-local Podman inspection can release the two dev-capable self-binds.
# Re-establish them before any later runtime initialization.
nsenter --target 1 --mount -- \
  /usr/local/libexec/codex-mobile/prepare-workspace-overlay-quota

echo "owner-PC WSL storage/runtime foundation: PASS"
echo "Use WORKSPACE_IO_DEVICE=$workspace_io_device in /etc/codex-mobile/production.env."
