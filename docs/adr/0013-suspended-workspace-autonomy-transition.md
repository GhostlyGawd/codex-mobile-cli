# ADR 0013: Change workspace autonomy only while suspended

- Status: Accepted
- Date: 2026-07-16

## Context

A workspace autonomy mode controls two independent enforcement surfaces: the
managed Codex CLI configuration and the provider's network-egress parameter.
Updating only the database or rewriting a live config could leave a reachable
workspace in a mixed-policy state. Full Access also removes Codex approval
prompts inside the existing host isolation boundary, so its selection needs a
clear owner confirmation.

## Decision

Expose a dedicated `update_autonomy` workspace action and accept it only when
the owner-scoped workspace is suspended. Persist the mode with a state-guarded
store operation serialized against resume by the single-process admission
gate. A live, queued, provisioning, failed, deleting, or approval-waiting
workspace returns a conflict and is not mutated.

The workspace service records `suspended` only after Coder confirms the stop
build completed. Submitting an asynchronous stop request is not sufficient for
this policy boundary.

On the next resume, the control plane passes the stored safety mode to Coder's
start build. Coder applies `allow_egress` together with the mutable runtime
quota before the container is reachable. The trusted initializer then rewrites
the managed Codex configuration with the same mode. Only after both steps
succeed does the workspace become running; initialization failure stops the
provider and records a failed workspace. Approved Dev Container starts already
carry the same mode through their structured setup request.

The iOS client disables autonomy changes outside the suspended state, explains
the resume boundary, and requires a destructive confirmation before selecting
Full Access. The API remains authoritative and rejects malformed or stale
clients independently of the UI.

## Consequences

- Owners use an explicit suspend, change, resume sequence instead of a live
  mutation.
- No terminal or preview can observe a partially applied autonomy mode.
- Persistent disk parameters remain immutable; resume resends only egress and
  mutable runtime resource parameters.
- The serialization argument relies on the supported one-control-plane-process
  deployment invariant documented in ADR 0005.
