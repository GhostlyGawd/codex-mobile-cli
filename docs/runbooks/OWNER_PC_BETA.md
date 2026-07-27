# Owner-PC WSL private-beta host

This is the active zero-recurring-cost host path selected by
[ADR 0025](../adr/0025-owner-pc-private-beta-hosting.md) and implemented by
[ADR 0026](../adr/0026-owner-pc-wsl-runtime.md). It prepares the owner's
D-backed Ubuntu WSL environment. It does not purchase a VPS, open public
ports, change DNS, create credentials, or upload an app to TestFlight.

The fixed-price VPS path is deferred and unauthorized. Do not substitute it
when an owner-PC check fails. Stop, preserve the failure evidence, and repair
the local profile. Reconsidering a VPS requires a new explicit owner decision.

## Operating envelope

| Boundary | Owner-PC beta contract |
| --- | --- |
| Host | D-backed Ubuntu 24.04 under WSL2, systemd, cgroup v2 |
| Availability | PC awake, powered, online; WSL and product services running |
| Recurring infrastructure cost | $0; already-owned PC, GitHub, Apple, ChatGPT, and domain access only |
| Workspaces | One managed workspace and one writable workspace-data quota volume total |
| Workspace compute | 2 CPU, 2 GiB memory, no additional swap, 512 processes |
| Workspace disk | Immutable 8–16 GiB quota, 12 GiB default |
| Workspace inodes | Fixed XFS default project ceiling of 1,048,576 |
| Workspace I/O | 64 MiB/s read, 32 MiB/s write, 2,000/1,000 read/write IOPS |
| Guest data filesystem | 64 GiB loop-backed XFS with project quotas at `/srv/codex-mobile` |
| Windows storage | Dynamic WSL VHD on `D:`; 192 GiB free before initialization and 128 GiB during preflight |
| User namespace | `containers:1000000:1048576`; each container uses `auto:size=65536` |
| LSM | AppArmor unavailable on WSL; seccomp and the other container controls remain required |
| Public reachability | No public ingress, DNS, or TestFlight go-live is established by this runbook |

The setup fully allocates the 64 GiB image from the Linux guest's perspective,
but the enclosing Windows `ext4.vhdx` is dynamically sized. Do not report the
guest allocation as a 64 GiB physical reservation on `D:`. The control-plane
admission check separately keeps 24 GiB free inside XFS and requires room for
the maximum 16 GiB workspace before starting it.

## Prerequisites

Before changing the host, confirm:

1. The registered WSL distribution is named `Ubuntu` and its registry
   `BasePath` resolves beneath `D:\Codex\WSL`.
2. Ubuntu is version 24.04, WSL2 uses systemd and cgroup v2, and the Linux
   runtime has at least 6 CPUs and 5,632 MiB memory.
3. Windows has at least 11 GiB physical memory and `D:` has at least 192 GiB
   free before the first image initialization.
4. A current Linux-native checkout exists inside the D-backed distribution,
   for example `/home/rhenm/src/codex-mobile-cli`. Do not use a checkout under
   `/mnt/c` or `/mnt/d`.
5. No unreviewed process uses `/srv/codex-mobile`,
   `/var/lib/codex-mobile-owner-pc/workspace-storage.xfs`, or
   `10.86.0.1`.

The setup installs only free Ubuntu packages and checksum-pinned upstream
tools. The package set is `ca-certificates`, `curl`, `docker.io`,
`docker-compose-v2`, `git`, `gzip`, `iproute2`, `iptables`, `jq`, `openssl`,
Podman 4.9.3, `python3-yaml`, `tar`, `uidmap`, `util-linux`, and `xfsprogs`.
The upstream pins are Coder CLI 2.34.6, Trivy 0.72.0, and Syft 1.46.0. This
downloads software but does not create a paid or metered service.

The initializer refuses to replace an existing storage path whose type,
ownership, mode, link count, size, or filesystem does not match the contract.

## Initialize the WSL foundation

From the trusted Windows checkout, run:

```powershell
pwsh -File .\scripts\infra-setup-owner-pc.ps1 `
  -Distribution Ubuntu `
  -LinuxRepository /home/rhenm/src/codex-mobile-cli
```

The Windows wrapper verifies the D-backed distribution and host capacity, then
runs the Linux initializer as root. The initializer:

- installs and verifies Docker/Compose, the reviewed Podman version, and the
  checksum-pinned Coder and image-audit tools;
- creates the non-Docker `codex-deploy` staging account, release roots,
  root-only secrets/cache roots, and the isolated provisioner account;
- installs the trusted source-bootstrap units and wrappers required to reach
  the first manifest-bound release without weakening the manifest gate;
- creates or validates the exact 64 GiB XFS image;
- creates the `containers` subordinate UID/GID pool
  `1000000:1048576`;
- installs and enables `codex-mobile-owner-pc-runtime.service`;
- writes root-only measured host facts to
  `/etc/codex-mobile/owner-pc-host.env`;
- mounts XFS at `/srv/codex-mobile` in systemd PID 1's mount namespace;
- enables project-quota accounting and enforcement;
- establishes the fixed default inode ceiling; and
- adds `10.86.0.1/32` to loopback for the private Coder listener.

Before the first release activation, the initializer is intentionally
idempotent for the exact accepted state. It fails rather than formatting,
replacing, or adopting an unexpected file or mount. Once
`/opt/codex-mobile/current` exists, it refuses to copy any working-checkout
artifact. Use the manifest-verified update or rollback workflow after that
point; this prevents a setup rerun from downgrading installed privileged
artifacts outside release provenance.

## Verify the foundation

Run these commands inside the `Ubuntu` distribution:

```shell
sudo systemctl is-active docker.service
sudo systemctl is-enabled codex-mobile-owner-pc-runtime.service
sudo systemctl is-active codex-mobile-owner-pc-runtime.service
podman --version
docker compose version
/usr/local/bin/coder version
/usr/local/bin/trivy --version --format json
/usr/local/bin/syft version --output json
sudo /usr/local/libexec/codex-mobile/prepare-owner-pc-runtime verify
sudo nsenter --target 1 --mount -- \
  findmnt --mountpoint --output TARGET,SOURCE,FSTYPE,OPTIONS /srv/codex-mobile
sudo nsenter --target 1 --mount -- \
  xfs_quota -x -c 'state -p' /srv/codex-mobile
sudo nsenter --target 1 --mount -- \
  xfs_quota -x -c 'quota -p -i -n -N -v 0' /srv/codex-mobile
sudo awk -F: '$1 == "containers" {print}' /etc/subuid /etc/subgid
```

Accept only:

- active Docker, Podman 4.9.3, and the exact Coder 2.34.6, Trivy 0.72.0,
  and Syft 1.46.0 pins;
- an enabled and active owner-PC unit;
- the exact loop-backed XFS mount with `pquota` or `prjquota`, `nodev`, and
  `nosuid`;
- project-quota accounting and enforcement both `ON`;
- default project inode soft and hard limits both `1048576`; and
- exactly `containers:1000000:1048576` in both subordinate-ID databases.

WSL interoperability shells can see a sibling mount namespace. Use the
root-owned helper or the shown `nsenter` commands when inspecting the product
mount; a plain `findmnt` from an interoperability shell is not authoritative.

Before the workspace Podman service starts, the release-installed preparation
helper must also prove two exact self-binds:

```shell
sudo nsenter --target 1 --mount -- \
  /usr/local/libexec/codex-mobile/prepare-workspace-overlay-quota
sudo nsenter --target 1 --mount -- \
  findmnt --mountpoint --output TARGET,FSROOT,FSTYPE,OPTIONS \
  /srv/codex-mobile/workspaces/.containers/overlay
sudo nsenter --target 1 --mount -- \
  findmnt --mountpoint --output TARGET,FSROOT,FSTYPE,OPTIONS \
  /srv/codex-mobile/workspaces/.containers/volumes
```

These two root-only, mode-`0700` Podman internal paths must be on the same XFS
device and may be `dev,nosuid`. The parent mount remains `nodev,nosuid`, and no
workspace receives either path or a host device.

## Stage the exact first-release candidate

Run from a clean Linux-native checkout at the exact reviewed commit. This
creates a source-only tree: no `.git`, local secret, pre-generated manifest, or
image-audit evidence is copied.

```shell
commit=$(git rev-parse --verify HEAD)
printf '%s\n' "$commit" | grep -Eq '^[0-9a-f]{40}$'
stage="/opt/codex-mobile/staging/sha-$commit"
sudo test ! -e "$stage"
sudo test ! -L "$stage"
sudo install -d -o codex-deploy -g codex-mobile -m 0750 "$stage"
git archive --format=tar "$commit" |
  sudo -u codex-deploy tar -xf - -C "$stage"
sudo test -z "$(sudo find "$stage" -type l -print -quit)"
```

Keep that exact `stage` value for every first-release command below. Set
`CONTROL_PLANE_IMAGE_TAG=sha-<the same commit>` in the operator configuration.
Do not stage the dirty working tree or change the staged files in place.

## Prepare the operator configuration

Create `/etc/codex-mobile/production.env` as root-owned mode `0600` from
`infra/env/production.env.example` only if no operator file already exists.
Do not overwrite a working file:

```shell
sudo test ! -e /etc/codex-mobile/production.env
sudo install -o root -g root -m 0600 \
  "$stage/infra/env/production.env.example" /etc/codex-mobile/production.env
sudoedit /etc/codex-mobile/production.env
```

Keep `DEPLOYMENT_PROFILE=owner_pc_beta`,
`DATA_ROOT=/srv/codex-mobile`, `OWNER_PC_STORAGE_GIB=64`,
`MAX_RUNNING_WORKSPACES=1`, and `CODER_BIND_ADDRESS=10.86.0.1`.
Copy the generated `WORKSPACE_IO_DEVICE` value from
`/etc/codex-mobile/owner-pc-host.env`; do not guess a `/dev/sd*` or loop path.
Leave the seven `VPS_*` values absent.

Replace every remaining placeholder before full preflight. Keep GitHub and
APNs disabled until their complete, separately approved credential sets exist.
Generate and install secrets only through the repository's root-owned secret
workflow; never paste secret values into commands, logs, or this runbook.

Generate the local database/control-plane secrets once from the staged tree:

```shell
sudo /bin/sh "$stage/scripts/infra-generate-secrets.sh" \
  --secrets-dir /etc/codex-mobile/secrets
```

The owner profile's static billing guard is:

```shell
sudo python3 -I "$stage/scripts/check-billing-policy.py" --repo-root "$stage" \
  --deployment-profile owner_pc_beta
```

## Bootstrap Coder and the private workspace runtime

This is the only pre-manifest ceremony. The initializer installed the exact
source-bootstrap units needed here because the immutable deploy must start the
private runtime before it can build, scan, and record the first release image
IDs. First run the bounded bootstrap preflight, then start the firewall and
workspace engine:

```shell
sudo python3 -I "$stage/scripts/infra-preflight.py" \
  --env-file /etc/codex-mobile/production.env \
  --repo-root "$stage" \
  --coder-bootstrap
sudo systemctl restart codex-mobile-docker-firewall.service
sudo systemctl start codex-mobile-workspace-runtime.service
sudo env DEPLOYMENT_PROFILE=owner_pc_beta \
  /usr/local/libexec/codex-mobile/verify-workspace-storage
sudo systemctl is-active codex-mobile-workspace-runtime.service
sudo test -S /run/codex-mobile-podman/podman.sock
sudo test "$(stat -c '%U:%G:%a' \
  /run/codex-mobile-podman/podman.sock)" = root:coder-provisioner:660
```

The socket is root-equivalent host authority. It must remain
`root:coder-provisioner` mode `660` and must never be mounted into Coder or a
workspace.

Start only PostgreSQL and private Coder for the owner ceremony:

```shell
sudo env REPO_ROOT="$stage" ENV_FILE=/etc/codex-mobile/production.env \
  /bin/sh "$stage/scripts/infra-bootstrap-coder.sh"
```

Complete the private Coder owner login. Create the scoped control-plane token
and the external provisioner key tagged `runtime=private-podman`; write them as
`coder_api_token` and `coder_provisioner_key` beneath
`/etc/codex-mobile/secrets`, root-owned mode `0444`. Record the real
organization UUID in `CODER_ORGANIZATION_ID`. Never print either credential.

Build the pinned bootstrap images, import the reviewed template once with the
explicit bootstrap flag, and record the returned template UUID:

```shell
sudo env REPO_ROOT="$stage" \
  PODMAN_URL=unix:///run/codex-mobile-podman/podman.sock \
  /bin/sh "$stage/scripts/infra-build-workspace-image.sh"
sudo env REPO_ROOT="$stage" \
  ENV_FILE=/etc/codex-mobile/production.env \
  PODMAN_URL=unix:///run/codex-mobile-podman/podman.sock \
  /bin/sh "$stage/scripts/infra-import-coder-template.sh" --bootstrap
```

The hard systemd dependencies make the firewall, workspace runtime, and
control stack require the owner storage service. A failed owner mount or quota
verification therefore blocks them instead of letting Docker create bind
sources on the WSL root filesystem. The owner unit is condition-skipped when
its root-only owner host file is absent, so this dependency does not convert
the deferred fixed-host profile into an owner-PC path.

Never bypass any failure by selecting `fixed_price_vps`.

After the Coder bootstrap has imported the reviewed template, start one
disposable template-created Safe Mode workspace. The spike requires that real
managed workspace so it can inspect the container and live kernel cgroups;
do not substitute a hand-written limits container. Then run:

```shell
sudo nsenter --target 1 --mount -- \
  env REPO_ROOT="$stage" ENV_FILE=/etc/codex-mobile/production.env \
  "$stage/scripts/infra-linux-runtime-spike.sh"
```

Accept only live evidence that the disposable probe:

- uses a non-overlapping 65,536-ID private user namespace from the dedicated
  pool;
- enforces 2 CPU, 2 GiB memory, no additional swap, 512 processes, and the
  configured I/O throttles;
- allows a small named-volume write and rejects an over-quota write;
- inherits the 1,048,576-inode XFS project ceiling;
- enforces the 4 GiB / 262,144-inode EnvBuilder overlay quota; and
- cannot reach the engine socket or unapproved networks.

For the persistent workspace-data volume, accept Podman 4.9's uppercase
`SIZE` metadata only when it exactly mirrors canonical `o=size=<bytes>`.
Root gate verification must independently show the physical XFS project has
block soft/hard limits equal to those bytes and inode soft/hard limits equal to
1,048,576.

Static Terraform, labels, or a successful container start are not substitutes
for those kernel, cgroup, namespace, network, and filesystem checks.

## Activate the first immutable release

After the real organization/template IDs exist and the runtime spike has
proved private Coder connectivity, set
`CODER_WORKSPACE_CONNECTIVITY_CONFIRMED=true`. Run the full guard without the
bootstrap exception:

```shell
sudo python3 -I "$stage/scripts/infra-preflight.py" \
  --env-file /etc/codex-mobile/production.env \
  --repo-root "$stage"
```

Then activate the exact staged commit:

```shell
sudo /bin/sh "$stage/scripts/infra-deploy.sh" "$stage"
```

The deploy freezes the staged source, rebuilds and audits the exact
commit-tagged images, creates the release manifest, moves the tree beneath
`/opt/codex-mobile/releases`, replaces the source-bootstrap host artifacts
with manifest-recorded copies, activates the release, imports its template,
and runs health plus smoke checks. A failure before activation leaves no
unreviewed release promoted; a later activation failure follows the existing
manifest-eligible rollback path.

## Current go-live boundary

As of 2026-07-27, this work establishes and verifies the local host runtime
foundation. It does not by itself make the app reachable from TestFlight. The
remaining publication path still requires separately reviewed and actually
verified:

1. a stable HTTPS ingress to Caddy while every internal service port remains
   private;
2. matching DNS, TLS, passkey relying-party, and Apple associated-domain
   values;
3. the required root-only production secrets and any explicitly enabled
   GitHub/APNs integration credentials;
4. an immutable release build, audit, deployment, health check, runtime spike,
   and application acceptance pass; and
5. an owner-approved signed archive and TestFlight upload from hosted macOS or
   an available Mac.

The PC must remain awake, online, and running WSL and the ingress for the beta
to work. The enabled systemd service does not make Windows start WSL after
every boot or keep a tunnel alive by itself.

## Restart and persistence check

Before admitting real workspace data, perform a controlled restart while no
workspace is active. Create, inspect, and remove the marker through
`nsenter --target 1 --mount` so every operation reaches the product mount:

1. Write a non-secret marker under `/srv/codex-mobile`.
2. Stop dependent product services, then restart
   `codex-mobile-owner-pc-runtime.service`.
3. Repeat the foundation verification and confirm the marker remains.
4. Terminate and restart the `Ubuntu` distribution from Windows.
5. Confirm the enabled unit remounts the exact image, restores `10.86.0.1/32`,
   retains the marker, and passes quota and subordinate-ID verification.
6. Remove the marker after recording the result.

Record the commands and redacted results in
`docs/verification/ACCEPTANCE.md`. A restart proves persistent files, not
survival of running workspaces or terminal processes.

## Rollback

For an application release rollback, follow [ROLLBACK.md](ROLLBACK.md). Use
only a manifest-eligible previous release and create a current checkpoint
first; rollback does not reverse a forward-only database migration.

To deactivate only the owner-PC foundation, first stop every dependent service
and confirm no workspace is active:

```shell
sudo systemctl stop codex-mobile.service
sudo systemctl stop codex-mobile-provisioner.service
sudo systemctl stop codex-mobile-workspace-runtime.service
sudo systemctl stop codex-mobile-docker-firewall.service
sudo systemctl disable --now codex-mobile-owner-pc-runtime.service
```

The owner-PC unit removes the private address, unmounts the two internal
self-binds and `/srv/codex-mobile`, and detaches the loop device. If it refuses
to stop, inspect the active workspace runtime or mount users; do not force an
unmount.

Deactivation deliberately preserves:

- `/var/lib/codex-mobile-owner-pc/workspace-storage.xfs`;
- `/etc/codex-mobile/production.env`,
  `/etc/codex-mobile/owner-pc-host.env`, and secrets; and
- immutable releases, checkpoints, and acceptance evidence.

Re-enable the unchanged foundation with:

```shell
sudo systemctl enable --now codex-mobile-owner-pc-runtime.service
sudo /usr/local/libexec/codex-mobile/prepare-owner-pc-runtime verify
```

Deleting the XFS image or WSL distribution is destructive decommissioning, not
rollback. It requires a separate owner decision, verified backup/checkpoint,
and explicit deletion plan. Removing guest data also does not guarantee that
Windows immediately compacts the dynamic WSL VHD.

## Known limitations

- The app is unavailable while the PC sleeps, is off, is disconnected, or WSL,
  ingress, or product services are stopped.
- No provider backup exists. Local checkpoints do not survive loss of the PC,
  `D:` volume, WSL VHD, or colocated recovery material.
- AppArmor is unavailable in this WSL environment. The owner profile keeps
  seccomp, user namespaces, no-new-privileges, capability drops, cgroups,
  read-only plain root filesystems, and the host-path/device/socket bans, but
  it must not be represented as the VPS AppArmor posture.
- Podman 4.9.3 requires a fixed inherited project inode ceiling for named
  volumes. Changing Podman requires the full quota and parser regression proof.
- Only one managed workspace and one writable workspace-data quota volume are
  supported. The larger subordinate-ID pool supports that workspace's relay
  and workload containers; it does not increase admission capacity.
- Windows boot does not itself prove WSL or external ingress startup. That
  availability automation remains a separate reviewed operational change.
