# Owner-only TestFlight build and upload

Routine Xcode compilation and simulator testing run on GitHub's standard hosted
macOS runner. TestFlight remains a separate owner-only release operation using
the owner's existing Apple Developer membership. App registration, signing
changes, credential installation, upload, tester changes, and release notes are
external actions; pause for explicit approval at each gate.

## Reproducible unsigned gate

1. Require a successful `ios-simulator` check for the exact reviewed commit.
   The workflow selects Xcode 26.6, checksum-verifies XcodeGen 2.45.4,
   regenerates the project, and tests with signing disabled.
2. For optional local device work, use a clean clone on an owner-controlled Mac
   with those exact tool versions and confirm `git status --porcelain` is empty.
3. Copy `apps/ios/Config/Local.xcconfig.example` to ignored
   `apps/ios/Config/Local.xcconfig`. Fill the approved display name, explicit
   bundle ID, Apple team, exact HTTPS API URL, stable passkey RP ID and preview
   suffix. Set Release APNs to production. Put no key/secret in xcconfig.
4. Generate and test:

   ```shell
   bash ./scripts/generate-ios-project.sh
   xcodebuild -project apps/ios/CodexMobile.xcodeproj \
     -scheme CodexMobile \
     -destination 'platform=iOS Simulator,name=iPhone 17 Pro' \
     -onlyUsePackageVersionsFromResolvedFile \
     -skipPackagePluginValidation \
     CODE_SIGNING_ALLOWED=NO test
   ```

5. On physical iPhone and iPad, execute passkey, reconnect/TUI, approval deep
   link, Git/file/preview/offline, VoiceOver, largest Dynamic Type, rotation,
   background/notification and privacy checks. Capture screenshots only after
   flows work and redact repository/path/content.

## Archive gate

After all portable, hosted simulator, and required device tests pass, ask the
owner to approve signing the exact commit/version/build with the displayed
Team, bundle ID and entitlements.

A future hosted archive workflow may perform this step without a recurring
physical Mac, but only after a separately approved `testflight` environment is
restricted to `main` and receives the minimum signing and App Store Connect
credentials. Those credentials must be environment-scoped, unavailable to pull
requests, and erased from temporary keychains and provisioning locations at job
end. Until that workflow exists and passes, prefer the owner-controlled local
managed-signing flow. Do not export a signing private key merely to bypass this
gate.

## Upload and private beta gate

Uploading changes App Store Connect and may notify testers. Show the owner the
archive identity, export-compliance/privacy answers, tester group, release
notes and APNs production setting, then obtain a separate explicit upload
approval. Upload from Xcode Organizer or the separately approved protected
environment workflow. Keep distribution private TestFlight; do not submit
public App Store review or enable external testers without a new decision.

After processing, install the TestFlight build, verify production APNs generic
delivery and every key flow against production, then record build number and
redacted evidence. If a serious issue appears, expire/remove tester access in
App Store Connect only after owner approval and deploy a higher fixed build;
installed iOS binaries cannot be remotely rolled back.

The public CI environment provides unsigned Xcode compilation and simulator
testing. Apple credentials, a registered App ID, signing, archive, APNs
production delivery, TestFlight upload, and physical-device acceptance remain
`GATED` and must not be reported as passing.
