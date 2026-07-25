#!/bin/sh
set -eu

usage() {
  cat >&2 <<'EOF'
usage:
  infra-admin.sh recover-passkeys --confirm=REVOKE-ALL-PASSKEYS
  NEW_MASTER_KEY_FILE=/root/private/new-key infra-admin.sh rewrap-master-key --confirm=REWRAP-ALL-ENVELOPES
EOF
  exit 2
}

[ "$#" -eq 2 ] || usage
[ "$(id -u)" -eq 0 ] || { echo "administrative recovery requires root" >&2; exit 1; }

action=$1
confirmation=$2
repo_root=${REPO_ROOT:-/opt/codex-mobile/current}
env_file=${ENV_FILE:-/etc/codex-mobile/production.env}

case "$action:$confirmation" in
  recover-passkeys:--confirm=REVOKE-ALL-PASSKEYS) ;;
  rewrap-master-key:--confirm=REWRAP-ALL-ENVELOPES) ;;
  *) usage ;;
esac

compose() {
  REPO_ROOT="$repo_root" ENV_FILE="$env_file" \
    /bin/sh "$repo_root/scripts/infra-compose.sh" "$@"
}

python3 "$repo_root/scripts/infra_release_manifest.py" verify \
  --repo-root "$repo_root" --require-images --verify-installed

running=$(compose ps --status running --services)
printf '%s\n' "$running" | grep -qx postgres || {
  echo "PostgreSQL must already be running for administrative recovery" >&2
  exit 1
}

stage_directory=
staged_key=
cleanup() {
  if [ -n "$staged_key" ]; then
    rm -f -- "$staged_key"
  fi
  if [ -n "$stage_directory" ]; then
    rmdir -- "$stage_directory" 2>/dev/null || true
  fi
}
trap cleanup EXIT HUP INT TERM

if [ "$action" = rewrap-master-key ]; then
  new_key=${NEW_MASTER_KEY_FILE:-}
  [ -n "$new_key" ] || {
    echo "NEW_MASTER_KEY_FILE must name the private root-owned new key file" >&2
    exit 1
  }
  case "$new_key" in /*) ;; *) echo "NEW_MASTER_KEY_FILE must be absolute" >&2; exit 1 ;; esac

  stage_directory=$(mktemp -d /run/codex-mobile-admin-key.XXXXXXXX)
  chmod 0700 "$stage_directory"
  staged_key="$stage_directory/new-master-key"

# Open with O_NOFOLLOW, bind validation to the opened inode, validate the key
# shape, and create a container-readable copy beneath a root-only directory.
# Key bytes are never placed in an environment variable, command argument, or
# log record.
  python3 - "$new_key" "$staged_key" <<'PY'
import base64
import os
import pathlib
import stat
import sys

source, destination = sys.argv[1:]
source_path = pathlib.Path(source)
parent = source_path.parent
parent_info = os.lstat(parent)
if parent.is_symlink() or parent_info.st_uid != 0 or stat.S_IMODE(parent_info.st_mode) != 0o700:
    raise SystemExit("new master key parent must be a root-owned mode-0700 directory")
before = os.lstat(source)
if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
    raise SystemExit("new master key must be a regular non-symlink")
if before.st_uid != 0 or stat.S_IMODE(before.st_mode) not in (0o400, 0o600):
    raise SystemExit("new master key must be root-owned with mode 0400 or 0600")
if before.st_nlink != 1 or not 1 <= before.st_size <= 4096:
    raise SystemExit("new master key must have one link and a bounded size")
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(source, flags)
try:
    opened = os.fstat(descriptor)
    if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
        raise SystemExit("new master key changed while being opened")
    content = os.read(descriptor, 4097)
finally:
    os.close(descriptor)
trimmed = content.strip()
valid = len(content) == 32 or len(trimmed) == 32
if not valid:
    try:
        valid = len(base64.b64decode(trimmed, validate=True)) == 32
    except Exception:
        valid = False
if not valid:
    raise SystemExit("new master key must contain 32 raw bytes or base64")
output = os.open(
    destination,
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
    0o444,
)
try:
    view = memoryview(content)
    while view:
        written = os.write(output, view)
        view = view[written:]
    os.fsync(output)
finally:
    os.close(output)
os.chmod(destination, 0o444)
PY

  [ "$(stat -c '%u:%g:%a:%h' "$staged_key")" = "0:0:444:1" ] || {
    echo "staged master-key mount failed ownership/mode validation" >&2
    exit 1
  }
fi

# Stop the public edge and serving process only after every non-mutating input
# and mount check has passed. A failed administrative command deliberately
# leaves public traffic stopped, while PostgreSQL remains available.
compose stop --timeout 60 caddy control-plane
if compose ps --status running --services | grep -qx control-plane; then
  echo "control-plane is still running; refusing administrative mutation" >&2
  exit 1
fi

if [ "$action" = recover-passkeys ]; then
  compose run --rm --no-deps control-plane \
    recover-passkeys --confirm=REVOKE-ALL-PASSKEYS
  compose up --detach --no-build --wait --wait-timeout 180 control-plane caddy
  REPO_ROOT="$repo_root" ENV_FILE="$env_file" \
    /bin/sh "$repo_root/scripts/infra-health.sh"
  echo "passkey recovery completed; public service restored"
  exit 0
fi

compose run --rm --no-deps \
  --volume "$staged_key:/run/codex-mobile-admin/new-master-key:ro" \
  control-plane rewrap-master-key \
  /run/codex-mobile-admin/new-master-key \
  --confirm=REWRAP-ALL-ENVELOPES

echo "master-key envelopes rewrapped; public service remains stopped"
echo "Atomically switch MASTER_KEY_FILE to the new key, then start and verify the stack."
