# Infrastructure runbook

The default stack is intentionally local and integration-free. Keep
`GITHUB_ENABLED=false` and `APNS_ENABLED=false` to use only
`infra/compose.yaml`; no GitHub or Apple secret file is required in that mode.
Production scripts invoke `scripts/infra-compose.sh`, which adds the reviewed
GitHub and APNs override files only when the corresponding flag is exactly
`true`.

The active beta host is the owner PC and D-backed Ubuntu WSL. Its fail-closed
deployment/storage profile is the next implementation step: the current XFS,
AppArmor, SSH/UFW, Ansible, systemd, and ten-session path is retained only for
the deferred VPS profile. Do not use that path or fictitious VPS metadata to
bypass the missing local storage boundary.

## Owner-provided integrations

Copy `infra/env/production.env.example` to
`/etc/codex-mobile/production.env`, keep it mode `0600`, and install secrets
beneath the separate mode-`0700` `SECRETS_DIR`. The exact identifiers, runtime
`*_FILE` paths, and filenames are documented in that example. GitHub App and
Apple keys are external credentials: `infra-generate-secrets.sh` never creates
or replaces them. Run `infra-preflight.py` without `--skip-secret-files` before
deployment; enabled integrations fail closed when an identifier, file, file
permission, or expected private-key format is missing.

Production `SECRETS_DIR` and every secret are `root:root`; the directory is
exactly mode `0700`, its ancestors are not writable by group/other, and each
secret is an unsymlinked, single-link regular file with exact mode `0444`.
Compose's local file-secret implementation does not remap uid/gid, so that
read bit is required by the intended non-root container after Docker mounts
the file directly at `/run/secrets`. Host users still cannot traverse the
root-only directory, and each service receives only its declared mounts.

Coder bootstrap must run with both integrations disabled. Enable them only
after the scoped Coder token and external-provisioner key have been installed.

## Deferred VPS/XFS workspace storage and engine boundary

The XFS capacity profile in this section is not an active private-beta launch
gate. The local WSL profile must provide an equally hard, measured storage and
inode boundary for hostile workspaces before admission is enabled; simply
skipping these checks is forbidden.

Before running Ansible, mount the operator-managed encrypted data device at
`/srv/codex-mobile` as XFS with `pquota` or `prjquota`. The playbook never
partitions, formats, or remounts a device. It and the workspace runtime both
fail closed if the mount target, filesystem, or project-quota option is wrong.

Workspace volumes are immutable 8–16 GiB XFS project quotas (12 GiB by
default), with 65,536 inodes per GiB. Ten maximum-size workspaces consume the
160 GiB workspace pool while 40 GiB remains reserved for the host and control
stack. Quotas are fixed when a volume is created and are not resized during
equal-share rebalancing.

Set `WORKSPACE_IO_DEVICE` to the exact output of `findmnt -n -o SOURCE
--target /srv/codex-mobile`. Host hardening, preflight, template import, and
runtime startup reject a mismatch; automation never guesses a host device.
The Coder template limits each workspace on that verified device to 64 MiB/s
read, 32 MiB/s write, 2,000 read IOPS, and 1,000 write IOPS. Approved
EnvBuilder containers also receive a 4 GiB / 262,144-inode writable-rootfs XFS
quota; plain containers keep a read-only rootfs.

Because kreuzwerker/docker 4.5.0 has no `PidsLimit` field, the dedicated
Podman engine applies `pids_limit = 512` from its private `containers.conf`
during container creation. This is the production cgroup ceiling; `nproc` is
not used as a substitute. Before setting workspace connectivity confirmed,
create and start a disposable workspace from the imported template and run
`scripts/infra-linux-runtime-spike.sh`. It fails unless it can inspect that
real container's HostConfig plus live `pids.max` and `io.max` kernel files.

Podman requires a root-owned engine to apply these local-volume quota options.
Only root and the unprivileged external provisioner group can traverse the
private Unix socket; the socket is never mounted into Coder or a workspace. Workspace containers
remain non-root for interactive use, use private user namespaces, drop
capabilities, block privilege escalation, and receive no host path or device.
Treat provisioner/template control as root-equivalent host authority and keep
it within the single-owner administrative boundary.

The engine service can see host device-node metadata so it can translate the
verified I/O path to cgroup major/minor values, but its parent systemd cgroup
uses `DevicePolicy=closed`; it cannot open arbitrary block devices. Workspace
containers receive no device mounts and cannot relax the parent's policy.

## Workspace Coder control relay

Production Coder binds only the literal RFC1918 `CODER_BIND_ADDRESS` and
`CODER_BIND_PORT`; never use loopback, a wildcard or a public address. The
root-owned workspace runtime creates and validates a fixed
`codex-mobile-control` bridge on `WORKSPACE_CONTROL_SUBNET`, which must be a
canonical collision-free RFC1918 `/24` through `/28` disjoint from the Coder
address. Its host interface is `cm-control0`.

Every workspace has an internal per-workspace bridge. A separate immutable
`cm-relay-<workspace>` container shares that bridge and alone joins
`codex-mobile-control`; the workspace resolves `cm-coder-control:7080` and does
not join the shared uplink. The relay is a non-root, private-userns, read-only
application-level `socat` forwarder with dropped capabilities,
`no-new-privileges`, AppArmor, bounded memory/CPU/tmpfs/logs, and no token,
volume, host path, device or engine socket. `INPUT` and `DOCKER-USER` rules
permit `cm-control0` only to the exact private Coder address/port and drop every
other destination. Balanced/Full Access uses a separate per-workspace egress
bridge; Safe Mode has none.

Coder's standard bootstrap necessarily places `CODER_AGENT_TOKEN` in the agent
container with `api_key_scope=no_user_data`. Helper-launched shell/Codex/Git
processes do not inherit it, but repository code has the same workspace
authority and may still observe/use the agent process token. Do not describe it
as hidden from hostile code. The privileged control-plane Coder token,
provisioner key and root-equivalent Podman socket never enter a workspace or
relay.

Keep `CODER_WORKSPACE_CONNECTIVITY_CONFIRMED=false` through bootstrap. For the
deferred VPS profile, create a template workspace on its selected Ubuntu host
and prove its Coder agent
registers and a real PTY works through the relay while the workspace cannot
reach Coder directly, any other host/control port, another workspace, the engine
socket or the general network. Inspect the relay/network attachments and prove
Balanced/Full Access receives only the expected separate egress bridge. Prove
that hostile workspace use of the standard agent token cannot obtain privileged
Coder API/user-data or cross-workspace authority. Record the target-host
evidence before changing the flag to `true`; static tests,
labels or container startup are not substitutes. See
[`ADR 0014`](../docs/adr/0014-workspace-coder-control-relay.md).

## Wildcard preview DNS and certificate gate

The signed private beta needs a stable HTTPS origin for the API through a
reviewed ingress serving the owner-PC/WSL host. Do not expose PostgreSQL, Coder,
Podman, SSH, runtime sockets, or workspace ports. If wildcard previews are
enabled for the beta, point only the approved public API and preview names at
that ingress while keeping `PREVIEW_DOMAIN` itself non-wildcard (for example,
`preview.codex.owner.example`). The Caddy site address is the corresponding
wildcard, such as `*.preview.codex.owner.example`.

The pinned stock Caddy image can validate and route this configuration, but it
cannot obtain a public wildcard certificate with HTTP-01 or TLS-ALPN-01.
Wildcard issuance requires DNS-01. Before enabling wildcard previews, the
owner must choose and approve one of these reviewed approaches:

- build and digest-pin a Caddy image containing the DNS module for the owner's
  DNS provider, then supply a least-privilege DNS credential through a file
  secret; or
- provision and renew the wildcard certificate outside Caddy, then add reviewed
  read-only certificate mounts and an explicit `tls` configuration.

Do not enable unrestricted on-demand TLS for attacker-selected preview hosts.
The preview gate is complete only after authoritative DNS resolves, the
running Caddy build/config proves DNS-01 or externally managed renewal, the
served certificate covers `*.PREVIEW_DOMAIN`, and an HTTPS preview route passes
the live authorization test.

## Evidence boundary

Static tests validate Compose isolation, exact image pins, Caddy syntax, the
Coder template/relay, managed control-network and firewall contracts, secret
contracts, host-hardening files, billing policy, manifest-bound image-audit
ordering/tamper policy, and checkpoint/rollback scripts. A Linux build-and-scan
run is still required to prove the exact candidate IDs. Private Podman workspace
isolation, live relay/Coder-agent/Safe Mode
route enforcement, active-host restart/recovery, database restore, reviewed
public ingress, DNS, and TLS must still be exercised on the D-backed Ubuntu WSL
beta host. VPS-specific XFS/AppArmor hardening, provider-backup restore,
ten-session capacity, and target-host reboot/update evidence are deferred unless
the owner explicitly reopens the always-on VPS design.
