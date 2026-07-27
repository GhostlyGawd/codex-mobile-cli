# Codex Mobile Coder template

The template pins Terraform 1.14.5 because that is the exact version embedded
by Coder 2.34.6; the same Coder release rejects Terraform 1.15 and newer.

This template has two explicit modes:

- `plain` is the safe default. It uses the locally built workspace image as UID
  1000, a read-only root filesystem, a private per-workspace network and volume,
  no devices, no host paths, and no Linux capabilities.
- `approved-envbuilder` uses the source-built `1.3.0-codex-mobile.1`
  EnvBuilder derivative only after the control plane passes an opaque
  setup-approval receipt. Repository lifecycle commands are therefore never
  executed merely because a Dev Container file exists.

Both modes receive the same statically linked control-plane helper, pinned real
Codex CLI, and code-mode host through a
checksum-versioned, per-workspace named volume mounted read-only at
`/opt/codex-mobile-helper`. The local EnvBuilder derivative is rebuilt from the
exact upstream Apache-2.0 source archive plus the manifest-bound local patch,
then adds the trusted runtime bundle seed. The Coder agent prepends this
directory to `PATH`, so normal `codex` calls use the helper wrapper; terminal
creation also uses the fixed helper path, and the wrapper executes only the
fixed `codex-real` path. EnvBuilder ignores
that mount during filesystem transformation, and the Linux spike verifies that
even a Dev Container image attempting to shadow the path cannot modify or
replace the helper. Updating the helper checksum creates a fresh volume.

Codex and configured environment plaintext are materialized only beneath
`/tmp/codex-mobile-runtime`, backed by the template's tmpfs mount. The
persistent workspace volume contains only the authenticated-encrypted Codex
auth envelope. The control plane must re-run trusted configuration after every
start because the tmpfs key and runtime state intentionally disappear on stop.

The control plane first detects either `.devcontainer.json` (directory `.`) or
`.devcontainer/devcontainer.json` (directory `.devcontainer`) with a
repository-scoped, read-only GitHub App token and persists that exact choice.
It then admits and starts a plain workspace, performs the short-lived
authenticated clone through the trusted helper into the persistent volume,
stops the container, and only then asks for structured trust. On approval it
restarts the same volume with the persisted directory and an opaque receipt.
Queueing, denial, process restart, and retry do not re-detect a moving upstream
branch. Secrets and GitHub tokens are never template parameters.

The external provisioner must use a scoped provisioner key tagged
`runtime=private-podman`. It remains an unprivileged account and inherits
`DOCKER_HOST` from its host systemd unit. The dedicated root-owned engine is
needed because Podman's local-volume byte-quota option applies XFS project
quotas only in rootful mode. Its Unix socket is restricted to the provisioner
group and is not mounted into Coder or either workspace mode.

Every workspace volume is created once with an immutable exact-byte 8–16 GiB
quota (12 GiB default) and is never resized during equal-share rebalancing. The
host must provide XFS mounted with `pquota` or `prjquota`. Podman 4.9.3
misclassifies its named-volume `inodes` value as a mount option, so the
root-owned runtime establishes a fixed XFS default project hard and soft limit
of 1,048,576 inodes before volume creation; the template intentionally passes
only `o=size=<bytes>`.

For `owner_pc_beta`, the host admits one managed workload and one persistent
quota-bearing named volume total, including stopped or orphaned volumes.
Podman 4.9.3 can reuse one XFS project ID across multiple quota volumes and let
a later volume mutate the first limit, so creation is serialized behind the
host's singleton lease and physical volume scan. A Linux spike must prove the
existing quota and rejected second-volume path without creating an
uncontrolled second quota volume.

The pinned Docker provider exposes memory/CPU, block-device I/O, and rootfs
storage options, but it does not expose `HostConfig.PidsLimit`. The dedicated
Podman service therefore loads a private `containers.conf` with an exact
creation-time `pids_limit = 512`; the template fixes its process parameter and
label to that same value. This is a real cgroup limit, not the per-UID `nproc`
ulimit. The target-host spike must inspect `pids.max` on a running container
created by this template before production acceptance.

The template administrator supplies `workspace_io_device` during template
push. Import, preflight, Ansible, and runtime startup require it to equal the
exact `findmnt` source backing `/srv/codex-mobile`; no `/dev/sdX` or mapper name
is guessed. Both modes receive fixed maxima of 64 MiB/s read, 32 MiB/s write,
2,000 read IOPS, and 1,000 write IOPS on that device. EnvBuilder additionally
has a 4 GiB / 262,144-inode writable-overlay quota; plain mode's root
filesystem is read-only.
Oversized Dev Container builds fail closed and must use the plain fallback.

The active owner profile fixes the workload at 2 CPU, 2 GiB memory with no
additional swap, and 512 processes. Its relay and workload each request
`auto:size=65536`, receiving non-overlapping mappings from the dedicated
`containers:1000000:1048576` subordinate UID and GID pools.

Every running workspace has an internal per-workspace bridge. Its Coder agent
reaches the private listener only through a non-root, read-only `socat` relay
with no token, volume, host path, device, capability, or engine socket. The
relay alone joins the fixed root-owned `codex-mobile-control` uplink, and host
firewall rules allow that interface to reach only the configured Coder address
and port. Safe Mode receives no other network. Balanced and Full Access add a
separate per-workspace egress bridge only while mutable `allow_egress` is true;
the control plane resends that value on every start so a Safe Mode transition
cannot inherit an older outbound policy. Repository code never joins the
shared control uplink directly.

The relay narrows reachability; it is not a credential or protocol-authentication
boundary. The workspace still contains its own Coder agent token with
`api_key_scope = "no_user_data"`, and repository code shares the private
workspace bridge and process authority, so it may be able to observe/use that
token. Helper-launched shell/Codex/Git processes exclude it from their inherited
environments, but that is not a secrecy claim against hostile workspace code.
The privileged control-plane Coder token and provisioner key never enter either
workspace or relay. Static validation therefore cannot establish
the production boundary. Keep `CODER_WORKSPACE_CONNECTIVITY_CONFIRMED=false`
until a target-host template workspace proves agent registration/PTY through
the relay, no direct/alternate Coder route, no other host/control/general
egress in Safe Mode, no privileged/user-data/cross-workspace authority from the
agent token, and only the separate expected egress attachment in Balanced/Full
Access.

EnvBuilder cannot implement every Dev Container feature. Compose, privileged
or root containers, added security capabilities, repository-declared mounts or
run arguments, host initialization commands, and nested Docker remain
unsupported here. Detection marks these configurations unsupported; an owner
may explicitly approve the safe plain fallback, but that decision never issues
an EnvBuilder receipt or relaxes the boundary.

The exact runtime behavior of `userns_mode`, cgroup limits, I/O throttling,
rootfs quota enforcement, internal relay networking to the Coder agent
endpoint, optional egress attachment, and EnvBuilder's minimal build-time
capabilities is deliberately gated on the Ubuntu 24.04 Linux-host spike. The
selected WSL host does not provide AppArmor, so `owner_pc_beta` omits that one
security option and must record it as unavailable while retaining seccomp and
the other controls. A future fixed-price VPS profile still requires its managed
AppArmor profile. Any need for privileged mode, a host engine socket mount, or
`seccomp=unconfined` is a hard failure.
