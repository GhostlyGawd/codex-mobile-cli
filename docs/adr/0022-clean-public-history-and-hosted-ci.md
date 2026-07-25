# ADR 0022: Publish a clean history and use hosted CI

## Status

Accepted on 2026-07-25. Supersedes ADR 0021 for active CI.

## Context

The owner develops from Windows and has exhausted private-repository Actions
minutes. The product still requires Linux race verification and Xcode 26.6
simulator testing. A persistent self-hosted runner on the owner's daily-use PC
cannot safely execute public or fork-supplied workflow code.

The original private repository also retains pull-request and Actions metadata
that is not part of the product source. GitHub pull-request refs are read-only,
so rewriting user-controlled branches would not produce a reliably sanitized
public record.

## Decision

Preserve the original repository under the private
`codex-mobile-cli-private-archive` name and publish the verified current tree as
a new root commit in a distinct public `codex-mobile-cli` repository. The
private archive remains the provenance record; its pull requests, workflow
history, and old commit metadata are not copied into the public repository.

Remove every workflow route to the owner's PC and unregister that repository
runner before publication. Public pull requests and `main` use only standard
GitHub-hosted runners:

- `ubuntu-24.04` runs backend, policy, static, and supply-chain validation.
- `macos-26` selects `/Applications/Xcode_26.6.app`, installs checksum-verified
  XcodeGen 2.45.4, regenerates the project, and tests the iPhone 17 Pro
  simulator with signing disabled.

Jobs require both public repository visibility and
`PUBLIC_CI_ENABLED == "true"`. Workflows have read-only permissions, disabled
checkout credential persistence, bounded timeouts and concurrency, immutable
Action SHAs, no repository secrets, and no artifact uploads. Fork workflows
require approval for all external contributors.

TestFlight signing and upload are a separate owner-gated workflow. Apple
credentials, if later approved, must be isolated in a protected environment
and must never be exposed to pull-request jobs.

The public repository intentionally has no open-source license. Public
visibility does not grant permission to copy, modify, or redistribute the
first-party source or media.

## Consequences

- Routine Linux and Xcode verification runs remotely from any browser or PC.
- Standard hosted runners are free while the repository remains public; larger
  runners remain prohibited.
- Pull-request code cannot reach the owner's PC or Apple/production secrets.
- The public repository has intentionally compact history. Historical review
  records remain available only in the private archive.
- A future private-visibility change causes the visibility guard to skip hosted
  jobs until the owner deliberately establishes a new billing policy.
- Device behavior, signing, APNs, TestFlight, and the target VPS remain separate
  acceptance gates.
