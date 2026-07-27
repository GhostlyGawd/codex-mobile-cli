# ADR 0010: XFS workspace quotas and a private Podman runtime

- Status: historical accepted design for the deferred VPS/XFS profile; its
  quota-option and inode-allocation details are superseded for the active beta
  by [ADR 0026](0026-owner-pc-wsl-runtime.md) and must be revalidated before a
  future VPS activation
- Date: 2026-07-16

The private-Podman isolation principles remain design input for the owner-PC
beta selected by [ADR 0025](0025-owner-pc-private-beta-hosting.md). That beta
now has its own loop-backed XFS storage/isolation profile under ADR 0026. It may
claim only its separately executed WSL evidence, never this
record's VPS disk layout, AppArmor, ten-session, provider-backup, reboot, or
load evidence.

## Context

A volume label is metadata, not enforcement. The previous template labeled an
8 GiB budget while allowing a workspace to consume all free host storage.
Container writable-layer limits do not bound the separate persistent named
volume. Dynamic volume resizing is also unsafe because provider or driver
changes can replace persistent data.

Podman's built-in named-volume quota support uses XFS project quotas and
requires the volume storage directory to be on XFS mounted with `pquota` (also
reported as `prjquota` by current kernels). Subsequent owner-host testing found
that Podman 4.9.3 misclassifies the named-volume `inodes` value as a mount
option and reuses one project ID across multiple quota volumes. See the official
[Podman volume quota documentation](https://docs.podman.io/en/latest/markdown/podman-volume-create.1.html).
The Podman API grants all authority of the account running it, so a root-owned
API socket is a root-equivalent trust boundary. See the official
[Podman system service security notes](https://docs.podman.io/en/latest/markdown/podman-system-service.1.html).

## Deferred VPS decision as originally accepted

The operator must mount the encrypted production data device at
`/srv/codex-mobile` as XFS with `pquota` or `prjquota`. Ansible validates the
exact mount, filesystem, and option but never partitions, formats, or remounts
storage. The Podman unit repeats that validation on every start. The original
Coder-template design supplied local-volume options in this form:

```text
o=size=<allocated GiB>G,inodes=<allocated GiB * 65536>
```

That combined option string is not the current implementation contract. The
repository now supplies only `o=size=<exact bytes>` and requires the root-owned
runtime to establish the XFS default project inode limit before volume
creation. For `owner_pc_beta`, that fixed hard and soft limit is 1,048,576
inodes, and exactly one persistent quota-bearing named volume may exist because
Podman 4.9.3 can reuse its project ID. Any future VPS profile must revalidate
the installed Podman release and explicitly choose its inode and multi-volume
policy rather than reviving the historical proportional formula.

Podman fails volume creation when project-quota enforcement is not available.
A versioned workspace volume is created once and Terraform ignores later
volume changes, preventing quota updates from replacing persistent data.

The public and persistence contract permits 8–16 GiB with a 12 GiB default.
The admission layer independently caps every allocation at 16 GiB. At the
maximum of ten running workspaces, `10 * 16 GiB = 160 GiB`, leaving the
configured 40 GiB host reserve from the 200 GiB disk budget. Requested disk is
only a downward cap and never buys priority.

Apply the quota through a dedicated root-owned Podman service. Its Unix socket
is mode `0660`, owned by `root:coder-provisioner`, and reachable only through
the private runtime directory. The Coder provisioner process remains an
unprivileged account, but possession of this socket is explicitly treated as
root-equivalent host authority. The socket is never mounted into Coder or a
workspace.

Workspace containers retain the separate runtime controls: private user
namespaces, a non-root interactive user, capability drops, no-new-privileges,
AppArmor/seccomp, bounded cgroups, no host paths or devices, and no privileged
mode. The template administrator must supply the exact `findmnt` source backing
`/srv/codex-mobile`; Ansible, preflight, template import, and runtime startup
all reject a mismatch. The template applies fixed per-container BPS/IOPS
maxima to that verified device and gives EnvBuilder's otherwise-writable
overlay a separate 4 GiB / 262,144-inode XFS quota. Plain root filesystems
remain read-only.

kreuzwerker/docker 4.5.0 exposes the I/O and rootfs fields but not
`HostConfig.PidsLimit`. The private Podman service therefore loads a dedicated
`containers.conf` whose creation-time default is exactly 512. The template
fixes its process parameter and label to the same number. This is not accepted
on static evidence alone: the target spike must inspect HostConfig and the
kernel's `pids.max`/`io.max` for a running container created by the imported
template. EnvBuilder's narrowly scoped capability exception remains
approval-gated and receives neither the engine socket nor host root paths.
The engine service keeps device-node metadata visible so Podman can resolve
the verified throttle path to major/minor numbers, while a parent systemd
`DevicePolicy=closed` denies arbitrary device opens. Children receive no
device mounts and cannot relax that parent restriction.

## Consequences

- The deferred VPS profile needs an operator-provisioned encrypted XFS data
  mount with project quotas before automation can run, plus a fresh Podman
  quota/version decision; the historical combined `size,inodes` option is not
  reusable authority.
- Compromise of the provisioner or an approved malicious template can control
  the dedicated root-owned engine. Template import, provisioner credentials,
  and socket membership are therefore host-root security boundaries.
- Existing unversioned workspace volumes are not silently adopted. Any future
  migration must checkpoint and explicitly restore data rather than resize or
  replace a live volume.
- Static checks prove configuration and allocation invariants only. Release
  remains blocked until the Ubuntu 24.04 spike creates disposable volume and
  rootfs quota probes, demonstrates writes beyond both limits fail, inspects a
  running template-created container's PID/I/O cgroups and private user
  namespace, and confirms workspaces cannot access the engine socket.

## Rejected alternatives

- Keep the rootless engine and rely on labels or free-space admission checks:
  these do not constrain a single hostile workspace.
- Resize persistent volumes whenever equal shares change: this can trigger
  destructive replacement and makes rollback ambiguous.
- Add a paid storage/quota service: this violates the fixed-price single-VPS
  boundary.
- Automatically create or format an XFS loop device for a future VPS:
  destructive disk mutation remains outside application deployment. ADR 0026
  separately authorizes an explicit, idempotent owner-PC setup helper to create
  or validate one fixed WSL image after host/path/capacity checks.
- Guess a conventional host block device such as `/dev/sda`: device names vary
  across providers and a plausible wrong path can throttle an unrelated disk
  while leaving workspace I/O unbounded.
- Set only `ulimit nproc`: that is a per-UID limit rather than the required
  container-wide cgroup ceiling.
