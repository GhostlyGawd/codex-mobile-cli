# ADR 0003: Persistent tmux PTY with optional Codex app-server events

- Status: accepted
- Date: 2026-07-15

## Decision

Keep the genuine Codex TUI in a named tmux window attached to a persistent PTY. The control plane exposes its own authenticated, binary, sequenced WebSocket protocol and the iOS app renders bytes through SwiftTerm 1.14.0. Codex app-server is a separate, local-only `CodexEventProvider` adapter for richer structured events.

PTY output must cross a mandatory stateful redactor built from the current
active workspace grants before it is sequenced, replayed, broadcast, or cached.
Reconnect gaps carry the earliest retained sequence and are followed by the
complete retained window; clients clear renderer/cache and rebuild from it.
Composer-sized sends use a per-device/tab idempotency key and receive a
reliable response targeted to the originating connection only after the PTY
write. A retry reuses the same key. Interactive keystrokes remain best-effort.

## Rationale

Current official docs label the interactive TUI and `codex resume` stable, while `codex app-server` and WebSocket transport remain experimental. The product cannot make session persistence or terminal access depend on that experimental surface.

## Consequences

Generic OSC-based attention remains the stable fallback. Structured approval metadata is shown only when a pinned app-server schema provides it; the client never scrapes ANSI output to invent context.

The redactor covers exact active values and bounded common encodings across PTY
chunk boundaries. It does not claim to identify unrelated sensitive output.
Input receipt/dedupe state is bounded and process-local: it prevents duplicate
retries after a lost response while the gateway generation remains alive, but
does not provide durable exactly-once delivery if the gateway crashes after a
PTY write and before the receipt. The app's pending delivery key is also
memory-only; termination after a receipt but before encrypted draft clearing
can leave a stale resendable draft. Attachment retries reuse their exact staged
payload only until its expiry.

An optional initial prompt is never interpolated into a command or written at
socket attachment time. The PTY waits for actual output from the trusted Codex
child and requires the same connection to remain stable through a short settle
interval before the one-shot write. This is a content-agnostic readiness gate,
not ANSI-screen scraping; live Linux verification still must prove behavior
against the pinned TUI.
