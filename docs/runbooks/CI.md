# Public hosted CI

Routine validation runs on standard GitHub-hosted Linux and macOS runners. No
workflow may target a persistent owner PC, a larger runner, or a paid external
CI service.

## Activation and billing boundary

Every runner job has this fail-closed condition:

```text
github.event.repository.private == false &&
vars.PUBLIC_CI_ENABLED == 'true'
```

The variable is an explicit operational enable switch. The visibility check is
the billing invariant: if the repository becomes private, hosted jobs skip
before runner allocation even if the variable remains set.

GitHub documents [standard hosted runners as free for public
repositories](https://docs.github.com/en/actions/concepts/billing-and-usage).
Larger runners are not included and remain prohibited. Do not replace
`ubuntu-24.04` or `macos-26` with a larger, GPU, custom-image, or other billed
runner. If GitHub changes that contract, clear `PUBLIC_CI_ENABLED` before
continuing.

## Portable Linux workflow

`.github/workflows/ci.yml` runs on pull requests, pushes to `main`, and manual
dispatch. Its `backend-and-policy` job uses `ubuntu-24.04`, read-only
permissions, disabled checkout credential persistence, immutable Action SHAs,
bounded concurrency and a 45-minute timeout. Before the portable repository
suite, it runs the full Linux EnvBuilder source verifier:

```shell
python3 -I ./scripts/verify-envbuilder-source.py
```

That verifier checks the exact source lock and local patch, downloads and
safely extracts the bounded commit-addressed upstream archive, applies the
expected changed-file set, and runs module verification, vet, unit/race tests,
and compile-only checks for the registry-dependent `devcontainer` and
`integration` packages. It then performs two clean static builds for each of
Linux amd64 and arm64 and checks byte reproducibility, ELF architecture, build
metadata, the derivative version, and absence of Coder runtime modules. The
job then performs the repository's Go, infrastructure, static iOS,
supply-chain, and release-policy checks.

It uses no cache or artifact upload. Workflow logs are public and must never
contain credentials, private repository content, personal paths, or production
configuration.

## Xcode simulator workflow

`.github/workflows/ios.yml` runs for the same events. Its `ios-simulator` job
uses standard `macos-26`, selects
`/Applications/Xcode_26.6.app/Contents/Developer`, downloads the pinned
XcodeGen 2.45.4 release archive, and verifies its recorded SHA-256 before use.
It regenerates the Xcode project and executes:

```shell
xcodebuild \
  -project apps/ios/CodexMobile.xcodeproj \
  -scheme CodexMobile \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' \
  -onlyUsePackageVersionsFromResolvedFile \
  -skipPackagePluginValidation \
  CODE_SIGNING_ALLOWED=NO \
  test
```

The resolved-file flag prevents dependency drift. Plugin validation is skipped
only for the exact `swift-openapi-generator` revision pinned in
`Package.resolved`, because hosted Xcode cannot accept an interactive
plugin-trust prompt.

The simulator workflow contains no Apple account, signing, APNs, App Store
Connect, repository, or environment secret. It does not archive or upload an
application.

## Pull requests and branch protection

Workflows from outside contributors require owner approval. Pull-request jobs
receive a read-only token and no secrets. `pull_request_target`,
`workflow_run`, `issue_comment` execution, reusable-workflow runner delegation,
dynamic untrusted checkout, write permissions, and persisted checkout
credentials are prohibited.

`main` requires the successful `backend-and-policy` and `ios-simulator` check
contexts. Because both workflows always create those jobs for pull requests,
path filtering cannot leave a required check permanently pending.

## Emergency shutdown and re-enable

1. Set `PUBLIC_CI_ENABLED` to `false` or remove it.
2. Cancel any already-running workflow.
3. Confirm no new job allocates a runner.
4. Diagnose the billing, security, or platform change without adding secrets or
   weakening permissions.
5. Re-enable only after policy tests pass and the owner accepts the revised
   boundary.

The retired Windows workflow and runner are historical context in
[ADR 0021](../adr/0021-private-owner-pc-self-hosted-smoke.md). The active
decision is [ADR 0022](../adr/0022-clean-public-history-and-hosted-ci.md).
