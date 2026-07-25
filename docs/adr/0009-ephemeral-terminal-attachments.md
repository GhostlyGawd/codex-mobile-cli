# ADR 0009: Ephemeral terminal attachment staging

- Status: accepted
- Date: 2026-07-16

## Context

The native composer must let the owner select Photos and files and make them available to the real Codex CLI/TUI. The product may not replace that TUI with an API-key chat implementation, persist hostile uploads in a repository or backup, add a metered blob service, or expose arbitrary filesystem and shell operations through the control plane. Repository contents, filenames, media declarations, and attachment bytes are hostile input.

The TUI ultimately needs a workspace-local path. That path is visible to all code running with the same workspace authority, so attachment staging cannot provide secrecy from the repository once the owner deliberately sends it. It can, however, constrain lifetime, location, executable behavior, names, and service-side exposure.

## Decision

Attachment upload is an authenticated owner/workspace/terminal-tab operation. Both the iOS client and control plane enforce at most four files, five MiB per file, eight MiB total, an allowlist of PNG, JPEG, HEIC, PDF, JSON, Markdown, CSV, and plain UTF-8 text, and content signatures or structural validation. The client rejects sensitive filenames and sends no original filename. The service treats the declaration as untrusted and validates the bytes again.

Bytes exist only transiently in bounded process memory while the control plane passes a fixed `attachment_stage` request to the trusted workspace helper. The service never writes them to PostgreSQL, audit records, the repository, the offline cache, notifications, diagnostics, or backups, and it scrubs mutable helper request buffers after serialization. Audits record count and total bytes only.

The Coder template mounts `/codex-mobile-attachments` as a dedicated mode-`0700`, `nosuid,nodev,noexec`, size-bounded tmpfs outside the repository and persistent workspace volume. The helper uses an OS-root-confined handle, cryptographic random batch and file identifiers, exclusive creation, mode `0600`, canonical extensions, synchronous writes, and whole-batch rollback on failure. Returned metadata is validated by the application and client before a path is inserted into bracketed-paste terminal input.

Each batch name encodes a 30-minute expiry. Staging first removes expired batches, and a periodic control-plane janitor invokes only the fixed cleanup operation for active workspace runtimes. Workspace stop or restart destroys the tmpfs. Cleanup is idempotent; failure is reported without exposing a path or payload.

The native composer keeps selections only in bounded memory and wipes them on removal, dismissal, or successful send. Drafts and history are a separate target-scoped AES-GCM store backed by a this-device-only Keychain key. Upload occurs only after explicit Send, and the socket/lease is rechecked before the authoritative TUI input. A failed send retains the draft and volatile selection for deliberate retry. Offline mode remains read-only and cannot stage or persist attachments.

## Consequences

- Attachments are available to the unchanged real Codex TUI using ordinary workspace paths without another paid service or direct iOS-to-workspace channel.
- Random names, a non-persistent no-exec mount, strict bounds, short expiry, and metadata-only observability reduce persistence and execution risk.
- Same-authority workspace code can read a staged file during its lifetime and can deliberately feed a non-executable file to an interpreter. This is an explicit residual risk, not an isolation claim.
- Expiry is enforced by opportunistic and periodic cleanup, so an active file can remain briefly beyond its nominal timestamp if the runtime or provider is unavailable. Stop/restart remains the hard lifetime boundary.
- Linux mount flags and real TUI consumption require target-Coder verification; Swift picker, file-protection, dictation, and accessibility behavior require the pinned Mac/device verification gates.

## Alternatives rejected

- Repository or persistent-volume staging: contaminates Git/workspace state and backups and makes deletion semantics unreliable.
- Database or third-party object storage: expands secret/retention obligations and adds unnecessary storage cost or a metered dependency.
- Direct SSH, SFTP, or an arbitrary helper command API: bypasses the authenticated control-plane policy and enlarges the command-execution boundary.
- Embedding uploads in terminal escape sequences or base64 commands: risks logs, scrollback, shell interpretation, and size amplification.
- Replacing the TUI with an API-key-backed chat composer: violates the product boundary that the real Codex CLI/TUI remains authoritative.
