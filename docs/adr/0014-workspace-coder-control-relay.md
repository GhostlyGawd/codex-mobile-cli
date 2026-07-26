# ADR 0014: Per-workspace relay for Coder control connectivity

- Status: accepted; active-host verification required
- Date: 2026-07-16

Under [ADR 0025](0025-owner-pc-private-beta-hosting.md), private-beta
target-host verification means the actual D-backed Ubuntu WSL and Windows
networking boundary. Historical VPS evidence cannot satisfy it.

## Context

A Safe Mode workspace must have no general egress, but its Coder agent still
needs a durable control connection for registration, metadata and PTY access.
Attaching repository-controlled workspace containers directly to the control
stack network would expose Coder and any accidentally adjacent service. Giving
Safe Mode a general outbound bridge, host networking, an engine socket or a
host-side tunnel would defeat the isolation boundary.

The selected host uses a rootful Podman engine for quota enforcement. Its actual
bridge, firewall and host-listener behavior cannot be inferred completely from
Terraform or labels and must be proven on the active Linux kernel/runtime.

## Decision

The root-owned runtime creates and validates one fixed
`codex-mobile-control` bridge on an operator-selected canonical RFC1918 `/24`
through `/28`. Its stable host interface is `cm-control0`; the subnet must be
disjoint from the literal RFC1918 address on which Coder publishes its private
port.

Each running workspace gets an internal per-workspace bridge and an immutable
`cm-relay-<workspace>` container. The workspace and relay share only that
private bridge. The Coder agent is configured to use
`http://cm-coder-control:7080`; the relay forwards TCP to the exact configured
Coder address and port. Only the relay joins `codex-mobile-control`. The
workspace itself never joins the shared uplink.

The relay runs as UID/GID 1000 in a private user namespace with a read-only root
filesystem, all capabilities dropped, `no-new-privileges`, the managed AppArmor
profile, bounded memory/CPU/tmpfs/file descriptors/logging, and no token, volume, host
path, device or engine socket. Host `INPUT` and `DOCKER-USER` chains allow
traffic from `cm-control0` and the configured source subnet only to the exact
Coder address/port and drop all other paths. Balanced and Full Access add a
separate per-workspace egress bridge only while the authoritative mutable
parameter allows it; Safe Mode has no egress bridge.

`CODER_WORKSPACE_CONNECTIVITY_CONFIRMED` remains `false` through bootstrap. It
may be changed to `true` only after the target-host spike proves all of the
following with a template-created workspace:

- the Coder agent registers and a real PTY works through the relay;
- the workspace cannot reach the Coder listener except through the relay;
- Safe Mode cannot reach any other host/control-stack port or general network;
- the relay cannot route traffic beyond its fixed application-level TCP target;
- another workspace, the root-owned engine socket and the control/data networks
  remain unreachable;
- hostile same-authority use of the standard `CODER_AGENT_TOKEN` cannot obtain
  privileged Coder API/user-data or cross-workspace authority; and
- Balanced/Full Access receives only its separate expected egress attachment.

## Consequences

Safe Mode can retain Coder control without granting a shared control-network
attachment or general egress. Relays are per-workspace and carry no credential,
so one relay does not intentionally share writable state or authority with
another.

The relay is an application-level TCP forwarder, not a router, protocol
authenticator, VM boundary or cryptographic separation. Repository code shares
the private workspace bridge with its relay and the workspace contains its own
Coder agent token (`api_key_scope = "no_user_data"`). A same-authority
workspace compromise may observe that process credential and can attempt to use
the scoped path; helper environment filtering is not a secrecy boundary. The
privileged control-plane Coder token and provisioner key/socket never enter the
workspace or relay. Coder's agent-token scope, exact route and host firewall
bound the exposure. Shared-kernel, Podman/firewall defects and the correctness
of Coder's private listener remain residual risks.

Static template/preflight/firewall/network tests are contract evidence only.
Until the Ubuntu spike above is recorded, workspace creation, Coder-agent
registration and PTY persistence remain owner/platform-gated and this ADR must
not be cited as live isolation evidence.

## Rejected alternatives

- Attach each workspace directly to the control or Compose data network.
- Give Safe Mode a normal egress bridge solely so its Coder agent can connect.
- Use host networking, a mounted host path/socket, a privileged sidecar or an
  engine socket in the workspace.
- Publish Coder on a public or wildcard address.
