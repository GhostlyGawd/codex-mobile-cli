# ADR 0026: Enforce the owner-PC WSL runtime profile

- Status: accepted
- Date: 2026-07-27

## Context

[ADR 0025](0025-owner-pc-private-beta-hosting.md) selected the owner's
D-backed Ubuntu WSL environment for the first usable private beta. The
fixed-price VPS remains deferred and unauthorized unless the owner makes a new
hosting decision. That selection needs a concrete, fail-closed runtime profile;
reusing the VPS checks or weakening them for WSL would misstate both storage
enforcement and isolation.

The active beta has no recurring infrastructure charge, but it must share the
owner PC safely and predictably. A hostile workspace must not consume all WSL
memory, processes, or storage, and a plausible-looking directory or block
device must not substitute for the reviewed storage boundary.

WSL also differs materially from the deferred Ubuntu VPS design:

- its Linux root filesystem is held in a dynamically growing host VHD on
  `D:`;
- interoperability shells can use a sibling mount namespace to systemd PID 1;
- AppArmor is not available in the selected WSL environment; and
- Podman 4.9.3 cannot use its named-volume `inodes` driver option as intended
  because it misclassifies that quota-only value as a mount option.

## Decision

Implement the active deployment as the explicit `owner_pc_beta` profile. The
production control plane accepts this profile with
`MAX_RUNNING_WORKSPACES=1`. The fixed-price VPS profile remains a future
availability option only: current policy and preflight reject it, and neither
documentation nor configuration may treat it as a launch requirement without
a new explicit owner decision.

### Host and storage boundary

Use Ubuntu 24.04 under WSL2, stored beneath `D:\Codex\WSL`, with systemd and
the unified cgroup v2 controllers. Repositories and runtime data remain on the
Linux-native filesystem, not under `/mnt/c` or `/mnt/d`.

The owner-PC setup creates a root-owned, mode-`0600`, single-linked, 64 GiB XFS
image at
`/var/lib/codex-mobile-owner-pc/workspace-storage.xfs`. The guest file is fully
allocated and mounted through one loop device at `/srv/codex-mobile` with
project-quota accounting and enforcement, `nodev`, `nosuid`, and `noatime`.
The enabled `codex-mobile-owner-pc-runtime.service` recreates that mount and
the fixed private Coder address in systemd's mount namespace when the WSL
distribution starts.

The first-release initializer is also the bounded source-bootstrap boundary.
Only while no `/opt/codex-mobile/current` activation exists, it may install
the free Ubuntu Docker/Podman prerequisites, checksum-pinned Coder 2.34.6,
Trivy 0.72.0, and Syft 1.46.0, and the root-owned runtime/firewall/provisioner
artifacts needed to build and audit the first manifest. The first immutable
release replaces those artifacts with manifest-recorded copies. A later setup
rerun refuses to overwrite an activated release's installed artifacts from a
working checkout.

The Docker firewall, workspace engine, and Compose control unit have hard
ordered requirements on the owner runtime. If its loop mount or quota
verification fails, those units do not start and Docker cannot silently create
the expected bind-source directories on the WSL root filesystem. The owner
runtime unit is condition-skipped when its root-only host-facts file is absent;
therefore the shared unit definitions retain the separately governed
fixed-host behavior without selecting or authorizing that deferred profile.

The 64 GiB image is a logical guest storage ceiling, not a promise that Windows
has preallocated 64 GiB of physical host storage. The WSL `ext4.vhdx` remains
dynamically sized on `D:`. Setup therefore refuses initialization below 192 GiB
free on `D:`, and ongoing owner-profile preflight refuses operation below
128 GiB free there. Within the XFS image, admission reserves 24 GiB and requires
room for a maximum 16 GiB workspace before a start, so a new start is refused
below 40 GiB XFS free.

The beta permits one managed workspace and one corresponding writable
workspace-data quota volume in total. Its immutable disk request is 8–16 GiB,
with a 12 GiB default. Podman receives the exact byte quota at volume creation.
Because Podman 4.9.3 mishandles the volume `inodes` option, the root-owned
runtime first establishes an XFS default project hard and soft limit of
1,048,576 inodes. Each new workspace-data volume inherits that fixed
maximum-workspace inode ceiling when Podman assigns its project ID. This is not
a disk-size-proportional inode allocation.

Podman 4.9 may expose an uppercase `SIZE` field in its local-volume option map.
The singleton gate accepts it only when it is an exact mirror of the canonical
`o=size=<bytes>` value. Root initialization/verification also queries
`xfs_quota` for the physical project ID and requires active block soft/hard
limits equal to those exact bytes plus inode soft/hard limits equal to
1,048,576; labels or API metadata alone are not quota evidence.

Podman's project-quota implementation must resolve an internal backing block
device. Keep the parent XFS mount and every workspace-visible mount `nodev`.
Create only two exact root-owned, mode-`0700` self-bind exceptions,
`workspaces/.containers/overlay` and
`workspaces/.containers/volumes`, remounted `dev,nosuid`. Startup verifies that
each exception is the expected path, XFS filesystem root, and device. These
private Podman internals are never mounted into a workspace. The writable
EnvBuilder overlay retains its separate 4 GiB / 262,144-inode quota; plain
workspace root filesystems remain read-only.

### Capacity and isolation

The sole workspace workload receives exactly:

- 2,000 millicores;
- 2,048 MiB memory with no additional swap;
- 512 processes;
- 64 MiB/s read and 32 MiB/s write throughput; and
- 2,000 read IOPS and 1,000 write IOPS on the verified WSL backing device.

The runtime uses a dedicated `containers` subordinate UID and GID pool of
`1000000:1048576`. Each workspace or relay container requests
`auto:size=65536`, so Podman assigns non-overlapping 65,536-ID mappings from
that pool. The larger pool is for the cooperating containers needed by the
single workspace, not permission to admit more workspaces.

Owner-PC containers retain private user namespaces, a non-root interactive
user, seccomp, no-new-privileges, capability drops, cgroup limits, no host
paths or devices, and no engine socket. The owner profile deliberately omits
an AppArmor security option because AppArmor is unavailable in this WSL
environment. This is an accepted beta isolation limitation, not evidence
equivalent to the deferred VPS profile. The provisioner's private Podman socket
remains root-equivalent host authority and is restricted to the
`coder-provisioner` group.

### Availability and publication boundary

The owner PC must remain powered on, awake, connected, and running WSL and the
product services. Enabling the systemd unit restores the Linux foundation when
the distribution starts; it does not guarantee that Windows automatically
starts WSL after boot or resumes an external HTTPS ingress.

This runtime decision does not authorize opening Coder, PostgreSQL, Podman,
SSH, or workspace ports. It also does not configure public ingress, DNS,
Apple associated domains, production credentials, or a TestFlight upload.
Those are separate reviewed external actions. Until a stable HTTPS route and
the remaining release gates have actually passed, the local runtime
foundation is not a live TestFlight beta.

## Consequences

- The first private beta can use already-owned hardware with zero new recurring
  infrastructure cost.
- Availability is intentionally lower than an always-on host and ends whenever
  the PC, WSL, network, ingress, or required services stop.
- Host free-space checks and the XFS project quotas protect different
  boundaries; both must pass. Deleting guest files does not necessarily shrink
  the dynamic WSL VHD on Windows.
- The fixed inode ceiling is intentionally conservative for all allowed
  workspace disk sizes until a tested Podman upgrade removes the 4.9.3 parser
  limitation.
- WSL mount-namespace handling, the two internal `dev` self-binds, and the
  subordinate-ID pool are privileged host configuration and are installed only
  by root-owned helpers.
- The absence of AppArmor is documented and compensated only by the remaining
  controls; it is not silently reported as passing.
- A future VPS migration requires a new owner decision and fresh host-specific
  storage, AppArmor, backup, reboot, and load evidence. It is not implied by
  this ADR.

## Alternatives rejected

- Purchase or require a fixed-price VPS now: the owner selected the zero-cost
  local beta and has not authorized a purchase.
- Store runtime data under a Windows-mounted `/mnt/*` path: this does not
  provide the required Linux-native XFS and project-quota boundary.
- Rely on WSL/VHD free space or volume labels alone: neither constrains one
  hostile workspace.
- Pass `inodes=` in the Podman 4.9.3 named-volume options: the observed parser
  path attempts an invalid mount instead of applying only the project quota.
- Remove `nodev` from the full data mount: Podman needs the backing-device
  exception only for its two private internal roots.
- Reuse one 65,536-entry subordinate-ID range: the relay and workload can
  coexist, so they require distinct mappings from a larger dedicated pool.
- Claim the VPS AppArmor posture on WSL: the selected environment cannot
  enforce or prove that control.
