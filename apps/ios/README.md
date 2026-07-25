# Codex Mobile iOS client

The app is native SwiftUI for iPhone and iPad. It targets iOS/iPadOS 17 and is generated with XcodeGen 2.45.4 for Xcode 26.6 (Swift compiler 6.3). SwiftTerm 1.14.0, Runestone 0.5.2, and TreeSitterLanguages 0.1.10 are exact Swift Package Manager pins behind app-owned adapters. The native target also runs Swift OpenAPI Generator 1.11.1 at build time against the synchronized control-plane contract and compiles its typed models/client with OpenAPI Runtime 1.11.0. The handwritten `CodexMobileAPI` facade remains the production transport boundary because it owns session rotation, bounded decoding, and app-specific retry policy; static route checks require that facade and the generated contract to cover the same operations.

## Configure

Copy `Config/Local.xcconfig.example` to `Config/Local.xcconfig` and set the owner-controlled identifiers. The checked-in `.invalid` hosts are deliberate: production network, passkey, GitHub, preview, and push registration paths remain unavailable until the real domain and signed capabilities are configured.

Associated Domains requires a public AASA file for the final application identifier, and APNs requires an App ID with Push Notifications enabled. Those Apple portal actions remain owner-gated.

## Generate and test on macOS

```sh
DEVELOPER_DIR=/Applications/Xcode_26.6.app/Contents/Developer ./scripts/generate-ios-project.sh
DEVELOPER_DIR=/Applications/Xcode_26.6.app/Contents/Developer \
  xcodebuild -resolvePackageDependencies \
  -project apps/ios/CodexMobile.xcodeproj \
  -scheme CodexMobile
DEVELOPER_DIR=/Applications/Xcode_26.6.app/Contents/Developer \
  xcodebuild -showdestinations \
  -project apps/ios/CodexMobile.xcodeproj \
  -scheme CodexMobile
DEVELOPER_DIR=/Applications/Xcode_26.6.app/Contents/Developer \
  xcodebuild -project apps/ios/CodexMobile.xcodeproj \
  -scheme CodexMobile \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' \
  test
DEVELOPER_DIR=/Applications/Xcode_26.6.app/Contents/Developer \
  xcodebuild -project apps/ios/CodexMobile.xcodeproj \
  -scheme CodexMobile \
  -destination 'platform=iOS Simulator,name=iPad Pro 13-inch (M5)' \
  test
```

Use the exact device names printed by `-showdestinations` if the local simulator set differs. Project generation synchronizes `packages/api-contract/openapi.yaml` into the app target before Xcode invokes the pinned OpenAPI build plugin. Before a private TestFlight archive, configure `Local.xcconfig`, then enable Associated Domains plus Push Notifications for the final App ID. Those signing and domain steps cannot be completed with checked-in example identifiers.

The app uses real HTTP and WebSocket clients in normal builds. `--ui-testing` selects deterministic local fixtures only in `DEBUG` builds.
