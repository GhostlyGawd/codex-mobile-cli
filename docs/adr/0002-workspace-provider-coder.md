# ADR 0002: Coder behind WorkspaceProvider

- Status: accepted, live feasibility pending target-host spike
- Date: 2026-07-15

## Decision

Use Coder Community as the first `WorkspaceProvider`, never as the public API. The control plane owns product state/policy and calls Coder through a narrow adapter. Workspaces are separate non-root OCI containers with isolated volumes, networks, branches, worktrees, credentials, and quotas.

## Consequences

Coder remains privileged because it provisions containers and must stay private. Features requiring privileged containers, the host Docker socket, arbitrary mounts, or shared writable caches are rejected. A later VM-grade provider can implement the same interface.
