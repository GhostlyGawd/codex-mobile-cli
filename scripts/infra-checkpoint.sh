#!/bin/sh
set -eu

repo_root=${REPO_ROOT:-/opt/codex-mobile/current}
env_file=${ENV_FILE:-/etc/codex-mobile/production.env}
checkpoint_root=${CHECKPOINT_ROOT:-/srv/codex-mobile/checkpoints}
mode=${1:---database}
checkpoint_reserve_bytes=${CHECKPOINT_RESERVE_BYTES:-42949672960}
database_max_bytes=${CHECKPOINT_DATABASE_MAX_BYTES:-4294967296}
workspace_max_bytes=${CHECKPOINT_WORKSPACE_MAX_BYTES:-17179869184}

for setting in "$checkpoint_reserve_bytes" "$database_max_bytes" "$workspace_max_bytes"; do
  case "$setting" in
    ''|*[!0-9]*) echo "checkpoint byte limits must be unsigned integers" >&2; exit 1 ;;
  esac
  [ "${#setting}" -le 18 ] || { echo "checkpoint byte limit is too large" >&2; exit 1; }
done
[ "$database_max_bytes" -ge 512 ] || { echo "database checkpoint cap must be at least 512 bytes" >&2; exit 1; }
[ "$workspace_max_bytes" -ge 512 ] || { echo "workspace checkpoint cap must be at least 512 bytes" >&2; exit 1; }

env_value() {
  awk -F= -v key="$1" '$1 == key {sub(/^[^=]*=/, ""); print; found=1} END {if (!found) exit 1}' "$env_file"
}

compose() {
  REPO_ROOT="$repo_root" ENV_FILE="$env_file" \
    /bin/sh "$repo_root/scripts/infra-compose.sh" "$@"
}

available_bytes() {
  blocks=$(df -Pk "$1" | awk 'NR == 2 {print $4; found=1} END {if (!found) exit 1}')
  case "$blocks" in ''|*[!0-9]*) return 1 ;; esac
  printf '%s\n' "$((blocks * 1024))"
}

require_capacity() {
  capacity_directory=$1
  capacity_max_bytes=$2
  capacity_available=$(available_bytes "$capacity_directory") || {
    echo "cannot determine checkpoint filesystem capacity" >&2
    return 1
  }
  capacity_required=$((checkpoint_reserve_bytes + capacity_max_bytes))
  if [ "$capacity_available" -lt "$capacity_required" ]; then
    echo "checkpoint refused: ${capacity_available} bytes free; ${capacity_required} required to preserve the host reserve" >&2
    return 1
  fi
}

temporary=
fifo=
producer_pid=
cleanup_checkpoint() {
  cleanup_status=$?
  trap - 0 HUP INT TERM
  if [ -n "$producer_pid" ]; then
    kill "$producer_pid" 2>/dev/null || true
    wait "$producer_pid" 2>/dev/null || true
  fi
  [ -z "$fifo" ] || rm -f -- "$fifo"
  [ -z "$temporary" ] || rm -f -- "$temporary"
  exit "$cleanup_status"
}
trap cleanup_checkpoint 0
trap 'exit 1' HUP INT TERM

# Stream a producer through gzip without relying on non-POSIX pipefail. The
# producer and compressor statuses are captured independently, the compressed
# size is kernel-capped, and only a verified file is atomically published.
write_compressed_checkpoint() {
  checkpoint_output=$1
  checkpoint_max_bytes=$2
  checkpoint_format=$3
  shift 3

  checkpoint_directory=$(dirname -- "$checkpoint_output")
  require_capacity "$checkpoint_directory" "$checkpoint_max_bytes"
  [ ! -e "$checkpoint_output" ] || {
    echo "checkpoint already exists: $checkpoint_output" >&2
    return 1
  }

  temporary="$checkpoint_output.partial.$$"
  fifo="$checkpoint_output.fifo.$$"
  [ ! -e "$temporary" ] && [ ! -e "$fifo" ] || {
    echo "checkpoint staging path already exists" >&2
    return 1
  }
  mkfifo -m 0600 "$fifo"

  "$@" > "$fifo" &
  producer_pid=$!
  checkpoint_blocks=$((checkpoint_max_bytes / 512))
  set +e
  (
    # shellcheck disable=SC3045 # dash and the target Ubuntu /bin/sh support these safety limits.
    ulimit -c 0 || exit 1
    ulimit -f "$checkpoint_blocks" || exit 1
    gzip -9 < "$fifo" > "$temporary"
  )
  compressor_status=$?
  wait "$producer_pid"
  producer_status=$?
  set -e
  producer_pid=
  rm -f -- "$fifo"
  fifo=

  if [ "$producer_status" -ne 0 ] || [ "$compressor_status" -ne 0 ]; then
    echo "checkpoint producer or compressor failed; no archive was published" >&2
    return 1
  fi
  [ -s "$temporary" ] || {
    echo "checkpoint producer returned an empty archive" >&2
    return 1
  }
  checkpoint_size=$(wc -c < "$temporary")
  case "$checkpoint_size" in ''|*[!0-9]*) echo "cannot measure checkpoint archive" >&2; return 1 ;; esac
  [ "$checkpoint_size" -le "$checkpoint_max_bytes" ] || {
    echo "checkpoint archive exceeded its configured size cap" >&2
    return 1
  }
  gzip -t "$temporary" || {
    echo "checkpoint gzip integrity validation failed" >&2
    return 1
  }
  if [ "$checkpoint_format" = tar ]; then
    # GNU tar treats input shorter than one complete 1,024-byte end marker as
    # an empty archive and exits successfully. Probe at most the first KiB so
    # truncated or plain-text producer output cannot pass that permissive case,
    # without expanding an attacker-controlled archive into memory or disk.
    tar_probe_bytes=$(
      gzip -dc "$temporary" 2>/dev/null |
        dd bs=1024 count=1 2>/dev/null |
        wc -c |
        awk '{print $1}'
    )
    case "$tar_probe_bytes" in
      ''|*[!0-9]*) tar_probe_bytes=0 ;;
    esac
    [ "$tar_probe_bytes" -eq 1024 ] || {
      echo "workspace checkpoint is not a valid tar archive" >&2
      return 1
    }
    tar -tzf "$temporary" >/dev/null || {
      echo "workspace checkpoint is not a valid tar archive" >&2
      return 1
    }
  fi

  remaining=$(available_bytes "$checkpoint_directory") || {
    echo "cannot recheck checkpoint filesystem capacity" >&2
    return 1
  }
  [ "$remaining" -ge "$checkpoint_reserve_bytes" ] || {
    echo "checkpoint refused after compression because the host reserve was consumed" >&2
    return 1
  }

  chmod 0600 "$temporary"
  sync -f "$temporary"
  mv -- "$temporary" "$checkpoint_output"
  temporary=
  sync -f "$checkpoint_directory"
}

umask 077
case "$checkpoint_root" in
  /*) ;;
  *) echo "CHECKPOINT_ROOT must be absolute" >&2; exit 1 ;;
esac
case "/$checkpoint_root/" in */../*) echo "CHECKPOINT_ROOT cannot contain '..'" >&2; exit 1 ;; esac
[ ! -L "$checkpoint_root" ] || { echo "CHECKPOINT_ROOT must not be a symbolic link" >&2; exit 1; }
mkdir -p "$checkpoint_root/database" "$checkpoint_root/workspaces"
for directory in "$checkpoint_root" "$checkpoint_root/database" "$checkpoint_root/workspaces"; do
  [ -d "$directory" ] && [ ! -L "$directory" ] || {
    echo "checkpoint directories must be real directories, not symbolic links" >&2
    exit 1
  }
done
chmod 0700 "$checkpoint_root" "$checkpoint_root/database" "$checkpoint_root/workspaces"
command -v flock >/dev/null 2>&1 || { echo "flock is required" >&2; exit 1; }
exec 9>"$checkpoint_root/.checkpoint.lock"
flock -x 9
# An uncatchable host/process failure may leave private staging inodes. They
# are never treated as backups and are removed only while the global writer
# lock proves no live checkpoint can own them.
find "$checkpoint_root/database" "$checkpoint_root/workspaces" -xdev \
  \( -type f -o -type p \) \
  \( -name '*.partial.*' -o -name '*.fifo.*' \) -delete
timestamp=$(date -u +%Y%m%dT%H%M%S.%NZ)

case "$mode" in
  --database)
    admin_user=$(env_value POSTGRES_ADMIN_USER)
    output="$checkpoint_root/database/postgres-$timestamp.sql.gz"
    write_compressed_checkpoint "$output" "$database_max_bytes" gzip \
      compose exec -T postgres pg_dumpall --clean --if-exists --username "$admin_user"
    find "$checkpoint_root/database" -type f -name 'postgres-*.sql.gz' -mtime +14 -delete
    echo "$output"
    ;;
  --workspace)
    [ "$#" -eq 2 ] || { echo "usage: $0 --workspace WORKSPACE_ID" >&2; exit 2; }
    workspace_id=$2
    case "$workspace_id" in *[!A-Za-z0-9-]*|'') echo "invalid workspace ID" >&2; exit 1 ;; esac
    podman_url=unix:///run/codex-mobile-podman/podman.sock
    running=$(podman --url "$podman_url" ps --filter "label=com.codex-mobile.workspace-id=$workspace_id" --format '{{.ID}}')
    if [ -n "$running" ]; then
      echo "workspace must be suspended/stopped before a filesystem checkpoint" >&2
      exit 1
    fi
    volumes=$(podman --url "$podman_url" volume ls \
      --filter "label=com.codex-mobile.workspace-id=$workspace_id" \
      --filter "label=com.codex-mobile.volume-role=workspace-data" --format '{{.Name}}')
    if [ "$(printf '%s\n' "$volumes" | sed '/^$/d' | wc -l)" -ne 1 ]; then
      echo "expected exactly one isolated volume for workspace $workspace_id" >&2
      exit 1
    fi
    output="$checkpoint_root/workspaces/$workspace_id-$timestamp.tar.gz"
    write_compressed_checkpoint "$output" "$workspace_max_bytes" tar \
      podman --url "$podman_url" volume export "$volumes"
    find "$checkpoint_root/workspaces" -type f -name "$workspace_id-*.tar.gz" -mtime +30 -delete
    echo "$output"
    ;;
  *) echo "usage: $0 --database | --workspace WORKSPACE_ID" >&2; exit 2 ;;
esac
