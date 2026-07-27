#!/bin/sh
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset CDPATH ENV BASH_ENV PYTHONHOME PYTHONPATH PYTHONSTARTUP LD_LIBRARY_PATH LD_PRELOAD

socket=/run/codex-mobile-podman/podman.sock
attempt=0
while [ ! -S "$socket" ]; do
  attempt=$((attempt + 1))
  [ "$attempt" -le 500 ] || {
    echo "workspace runtime socket did not appear within 50 seconds" >&2
    exit 1
  }
  sleep 0.1
done

chgrp coder-provisioner "$socket"
chmod 0660 "$socket"
[ "$(stat -c '%U:%G:%a' "$socket")" = root:coder-provisioner:660 ] || {
  echo "workspace runtime socket has unexpected ownership or mode" >&2
  exit 1
}
