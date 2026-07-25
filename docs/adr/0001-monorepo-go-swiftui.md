# ADR 0001: Go control plane and native SwiftUI client

- Status: accepted
- Date: 2026-07-15

## Decision

Use a monorepo, a single Go 1.26.5 control-plane binary, PostgreSQL, and a native SwiftUI iOS/iPadOS app. Keep API types in a versioned OpenAPI contract and generate the Swift client.

## Rationale

Go provides predictable memory use, simple static deployment, strong concurrency primitives, and mature WebAuthn/PostgreSQL/WebSocket support. SwiftUI and AuthenticationServices provide the required native passkey, accessibility, Keychain, scene, and iPad behavior. A browser wrapper would not satisfy the native terminal/accessibility/security requirements.

## Consequences

The backend compiles cross-platform, but all UIKit/SwiftUI compilation, simulator testing, accessibility validation, signing, and TestFlight work require macOS/Xcode.
