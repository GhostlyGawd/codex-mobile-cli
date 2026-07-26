# Project agent instructions

These rules apply to the entire repository.

## Product boundaries

- Preserve the real Codex CLI/TUI as the authoritative experience. Never replace it with an API-key-backed chat implementation.
- Keep `WorkspaceProvider`, `CodexEventProvider`, GitHub, APNs, clock, random source, and persistence behind interfaces so external boundaries are testable.
- Treat repositories, terminal output, devcontainers, previews, archives, filenames, symlinks, and Codex project configuration as hostile input.
- Do not add a paid or metered service. Deployment must remain one fixed-price VPS plus already-owned GitHub, Apple, ChatGPT, and domain access.
- Do not push, purchase, deploy, register apps, change DNS, or mutate production accounts without explicit owner approval.

## Required commands

Run from the repository root:

```shell
go work sync
go fmt ./services/control-plane/...
go vet ./services/control-plane/...
go test -race ./services/control-plane/...
go test ./services/control-plane/... -coverprofile=coverage/control-plane.out
```

On macOS with the pinned Xcode/XcodeGen versions:

```shell
./scripts/generate-ios-project.sh
xcodebuild -project apps/ios/CodexMobile.xcodeproj -scheme CodexMobile -destination 'platform=iOS Simulator,name=iPhone 17 Pro' -onlyUsePackageVersionsFromResolvedFile -skipPackagePluginValidation CODE_SIGNING_ALLOWED=NO test
```

Run `pwsh ./scripts/verify.ps1` or `./scripts/verify.sh` before handoff. If a platform tool is unavailable, record the exact skipped check in `docs/verification/ACCEPTANCE.md`; do not report it as passing.

## Code and security conventions

- Go packages should be cohesive, dependency-injected, and free of global mutable state.
- HTTP handlers must set bounded body sizes, reject unknown fields for security-sensitive requests, return stable problem details, and never echo secrets.
- All filesystem access must resolve beneath the workspace root, reject symlink escapes, cap sizes, and use atomic writes with an expected ETag.
- All subprocesses use argv arrays, fixed executable names, bounded output, explicit working directories, and inherited-environment allowlists. Never assemble shell command strings from user input.
- Access and refresh credentials are random opaque values; persist only keyed hashes. Refresh rotation must reject replay and revoke the token family.
- Audit metadata only. Never log prompts, full commands, terminal streams, file contents, GitHub/Codex tokens, passkey challenges, APNs device tokens, or secret values.
- Keep generated files reproducible. Edit OpenAPI first, then regenerate clients.
- Add tests for success, authorization failure, malformed input, replay, path traversal/symlink escape, resource limits, and cancellation for every security-sensitive feature.

## Documentation discipline

Update `IMPLEMENTATION_PLAN.md` and `docs/verification/ACCEPTANCE.md` when milestone state changes. Consequential architecture changes require an ADR in `docs/adr/`. Update `SECURITY.md`, `COST_MODEL.md`, and `CAPABILITY_MATRIX.md` when their assumptions change.
