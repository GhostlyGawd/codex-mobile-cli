#!/bin/sh
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset CDPATH ENV BASH_ENV PYTHONHOME PYTHONPATH PYTHONSTARTUP LD_LIBRARY_PATH LD_PRELOAD

# systemd creates a fresh mount namespace for each ExecStartPre command when
# filesystem protections are enabled. Keep preparation, verification, and the
# long-lived engine in one process chain so the exact dev-capable, root-only
# quota self-binds survive until Podman has initialized containers/storage.
case "${DEPLOYMENT_PROFILE:-}" in
  owner_pc_beta)
    /usr/local/libexec/codex-mobile/prepare-workspace-overlay-quota
    /usr/local/libexec/codex-mobile/owner-pc-workspace-volume-gate init
    /usr/local/libexec/codex-mobile/prepare-workspace-overlay-quota
    CODEX_MOBILE_GATE_ROOT_VERIFIED=1
    export CODEX_MOBILE_GATE_ROOT_VERIFIED
    /usr/local/libexec/codex-mobile/verify-workspace-storage
    /usr/local/libexec/codex-mobile/ensure-workspace-control-network
    /usr/local/libexec/codex-mobile/prepare-workspace-overlay-quota
    ;;
  fixed_price_vps)
    /usr/local/libexec/codex-mobile/verify-workspace-storage
    /usr/local/libexec/codex-mobile/ensure-workspace-control-network
    ;;
  *) echo "workspace runtime requires an explicit supported deployment profile" >&2; exit 1 ;;
esac

exec /usr/bin/podman \
  --network-config-dir=/srv/codex-mobile/workspaces/.networks \
  system service --time=0 unix:///run/codex-mobile-podman/podman.sock
