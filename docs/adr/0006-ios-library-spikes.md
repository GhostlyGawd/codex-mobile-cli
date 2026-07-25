# ADR 0006: Replaceable SwiftTerm and Runestone adapters

- Status: accepted for implementation; macOS compatibility tests pending
- Date: 2026-07-15

## Decision

Pin SwiftTerm 1.14.0 behind `TerminalRendering` and Runestone 0.5.2 behind `TextEditing`. Generate the Xcode project with XcodeGen 2.45.4. Use Apple frameworks directly for passkeys, Keychain, CryptoKit, networking, notifications, and previews.

## Consequences

The terminal must override link activation, block remote clipboard writes in the transport/parser boundary, and pass terminal corpus/accessibility tests. Runestone handles focused text editing only; server APIs remain authoritative for root confinement, file size, sensitivity, and ETag conflicts.
