# Implementation plan

Last updated: 2026-07-27 (America/New_York)

Status values: `not started`, `in progress`, `locally verified`, `owner-gated`, `blocked`.

## Environment inventory

| Capability | Result | Consequence |
| --- | --- | --- |
| GitHub repository | The clean-history cutover is complete: `GhostlyGawd/codex-mobile-cli` is public from a distinct clean root, while the original history remains private at `GhostlyGawd/codex-mobile-cli-private-archive` | Develop and verify the active product at the public URL without exposing the private repository's historical metadata |
| Go | 1.26.5 installed and verified | Backend build/test available |
| Windows self-hosted runner | Historical trusted smoke validation passed; this repository's listener, registration, root, and launcher were removed before publication, and the public repository has no self-hosted runners | Use only the public standard-runner workflows; unrelated owner-PC runners remain outside this repository's scope |
| Active beta host | The owner selected the D-backed Ubuntu WSL environment on the Windows PC for the first private beta with zero new recurring hosting cost. `owner_pc_beta` is the explicit active configuration profile, rejects VPS checkout metadata, and implements a separate fail-closed 64 GiB XFS guest-storage/runtime boundary. Dated 2026-07-27 evidence now covers the initializer, quota/singleton boundary, mount persistence, private runtime socket, and cold service restart | Complete the template-created Coder relay/workload, Safe Mode, production ingress, and credentialed end-to-end evidence; do not bypass a failed owner-profile check or substitute the deferred VPS profile. The app is unavailable while the PC, WSL, services, or reviewed HTTPS ingress is offline, and the host foundation alone is not TestFlight go-live |
| Docker/Compose | A D-backed Ubuntu WSL environment provides Docker 29.1.3 and Podman 4.9.3; checksum-verified Compose 5.3.1 schema validation passed, and the exact commit-tagged candidate-image build/runtime/profile-3 audit/manifest gate is executable there. The owner profile's XFS byte/inode quota, singleton lease, restart persistence, sub-ID pool, and socket boundary have dated live host evidence | Reuse the verified local engines. A real template-created Coder relay/workload must still prove its cgroups, I/O, distinct user mappings, relay routing, and Safe Mode denial; do not claim the unavailable WSL AppArmor control or any VPS backup/reboot/load evidence |
| Swift/Xcode | Local Xcode is unavailable on Windows; a historical public `macos-26` run passed project generation, compilation, unit tests, and UI tests with Xcode 26.6, checksum-verified XcodeGen 2.45.4, and the iPhone 17 Pro simulator on revision `c2aef5d3640f9f4660a550e1c0d3df6aacf26cf1`; the current-tree rerun is pending | Unsigned simulator evidence is automated, but revision-specific; signing, physical devices, manual accessibility, APNs, and TestFlight remain owner-gated |
| Codex CLI shell binary | Packaged app binary is not directly executable from this shell | Version-pinned Linux CLI validation uses disposable Linux infrastructure later |
| External credentials | GitHub App, APNs, stable HTTPS origin/domain, and Apple signing values are not stored in the repository | Real-account E2E remains owner-gated; a VPS is explicitly not an active dependency |

## Milestones

| Milestone | Status | Dependencies | Exit evidence |
| --- | --- | --- | --- |
| 0. Feasibility and contracts | locally verified | Official docs and provider terms | Architecture/security/cost/capability docs, ADRs, OpenAPI and terminal contracts |
| 1. Reproducible skeleton | locally verified | Milestone 0 boundaries | Full Go vet/race/coverage, migrations, deterministic Linux cross-builds, Compose/static infrastructure validation, and iOS static contract policy have recorded local evidence. Public hosted Linux and unsigned Xcode checks passed only on historical revision `c2aef5d3640f9f4660a550e1c0d3df6aacf26cf1`; current-tree hosted reruns are pending |
| 2. Identity and GitHub | owner-gated | Stable RP ID and owner-created GitHub App for live E2E | Passkey/session contracts include bounded partitioned ceremony admission. Owner-scoped GitHub status and shared/exclusive lease wiring pass unit tests; disposable PostgreSQL race runs passed the cross-pool drain, final-write, reconnect-availability, and `MaxConns=1` regressions. Real associated-domain, external App install/uninstall and GitHub flows remain gated |
| 3. Workspace | owner-gated | Local Coder endpoint/template and D-backed WSL container host for live E2E | Lifecycle, retention, queue, fail-closed private-input persistence, continuous admission-to-runtime reservation, durable provider ambiguity recovery, exact-running Coder build barriers, conservative quota high-water/level-triggered reconciliation, durable setup-review reconciliation, confirmed suspension/deletion authority drains, branch/worktree isolation, immutable disk allocation, per-workspace Coder relay/control-uplink policy, and adapter contracts are implemented. The owner profile fixes one workload at 2 CPU / 2 GiB / 512 processes with one immutable 8–16 GiB persistent volume; live template-created Coder agent/PTY relay and Safe Mode routing remain gated. WSL AppArmor is unavailable, and VPS-only AppArmor/backup/reboot/load claims remain deferred |
| 4. Persistent terminal | owner-gated | Linux PTY/tmux and Mac/device for live E2E | Portable protocol/replay/gap/lease, targeted input-receipt, mandatory output-redaction, stale-token recovery, persistent-tab, native controls, bounded global/owner/workspace/tab/device state, and revocation writer-drain checks pass. Swift compilation and the automated simulator suite passed on the historical hosted baseline; the current-tree hosted rerun, real tmux survival, SwiftTerm fidelity, and device behavior remain gated |
| 5. Genuine Codex | owner-gated | ChatGPT device login and Linux runtime access by owner | Portable wrapper/config/auth security tests, per-workspace status/confirmed disconnect that stops only app-owned Codex tmux and removes runtime/encrypted auth, deterministic Linux cross-builds, and a bounded attachment-staging boundary for the authoritative TUI pass; live Linux TUI/device-login/reauth/resume/attachment evidence remains owner-gated |
| 6. Files/Git/review | owner-gated | Production Linux workspace filesystem | Linux fd-relative no-follow file/search/save, exact displaced-content ETag CAS, bounded Git, and recoverable checkpoint/discard contracts pass locally; hosted native compilation and simulator Git-review reachability passed on the historical hosted baseline, while the current-tree hosted rerun, live contention, and target-filesystem proof remain gated |
| 7. Previews/secrets/offline | owner-gated | Domain/TLS for live preview E2E and Mac/device for native runtime tests | Preview revocation, live grant/revoke tmpfs sync, pre-replay terminal redaction, encrypted read-only cache/drafts/history, and attachment cache exclusion pass portable/static tests; hosted native unit/UI tests passed on the historical hosted baseline, while the current-tree hosted rerun, domain/TLS, live workspace integration, device file protection, and physical-device behavior remain gated |
| 8. Operations/hardening | in progress | Local-beta service lifecycle and reviewed stable HTTPS ingress | Supply-chain reproducibility, recorded frozen-tree source-security scanning, release-artifact validation, private runtime policy, and runbooks are locally exercised. The exact merged-main OCI candidate passed build/runtime checks, the profile-3/schema-2 image audit, and manifest-schema-2 binding in D-backed WSL. Dated 2026-07-27 live evidence covers the active profile's 64 GiB XFS mount, singleton 8 GiB byte/inode quota and refusal behavior, inode-limit inheritance on project-ID reuse, private socket, mount/restart persistence, sub-ID pool, and stable loopback. Template-created Coder relay/workload cgroup/I/O/distinct-mapping proof, Coder/EnvBuilder, Safe Mode denial, reviewed HTTPS ingress, and truthful offline-state evidence remain |
| 9. Product polish/release | owner-gated | Apple team, APNs key, physical devices, TestFlight authorization | Xcode unit/UI simulator tests passed on the historical hosted baseline; the current-tree hosted rerun, manual VoiceOver/Dynamic Type device evidence, a signed archive, APNs, TestFlight, and the release checklist remain owner-gated |

## Milestone execution rules

1. Implement dependency order even when code is grouped into broader workstreams.
2. Run locally available tests at each milestone and record exact commands/results.
3. Keep unavailable integrations disabled and fail closed with actionable configuration errors.
4. Do not mark an external scenario passed using a fake; mark the implementation contract verified and the live scenario owner-gated.
5. Never weaken the single-host isolation boundary to make a test pass.
6. Keep the owner-PC private beta as the active deployment direction. Do not
   reintroduce a VPS as a requirement unless the owner explicitly reopens the
   decision recorded in ADR 0025.

## Current work

- [x] Read the complete build specification.
- [x] Confirm repository ownership, visibility, permissions, default branch, and initial state.
- [x] Register a private single-owner repository-scoped Windows runner in
  zero-UAC user mode, verify its exact process owner/path/labels, and keep it
  outside the repository with a per-user sign-in launcher.
- [x] Add a bounded manual/`main` Windows smoke workflow, CI policy tests,
  security/cost documentation, and ADR 0021 in draft PR #2.
- [x] Merge PR #2 and confirm the resulting `main` push completes on the exact
  self-hosted runner, with every step successful and a clean credential/path
  log audit.
- [x] Approve a clean-history public publication that preserves the original
  repository and its historical metadata privately.
- [x] Add public-only standard Linux/macOS workflows, remove the self-hosted
  workflow route, pin Xcode/XcodeGen, and enforce the boundary with negative
  policy tests.
- [x] Merge public-readiness changes while the original repository is private.
- [x] Unregister and remove only the `codex-mobile-cli` owner-PC runner.
- [x] Rename the original repository to the private historical archive and
  publish the verified tree from a distinct public repository.
- [x] Require successful hosted Linux and Xcode simulator checks on public
  `main` and record their run and job URLs before closing the publication
  milestone.
- [x] Verify current Go stable version and install it locally.
- [x] Verify official Codex authentication, TUI/resume, notification, and app-server maturity facts.
- [x] Complete Coder, Apple, GitHub App, and VPS official-source research used by the implementation boundaries.
- [x] Generate deterministic CycloneDX, dependency, and license reports and verify their byte-for-byte reproducibility.
- [x] Add confirmation-gated operations, credential, restore, incident,
  APNs/GitHub, public hosted CI, and owner-only TestFlight runbooks.
- [x] Implement race-safe true-inactivity detection, runtime process/port probing, two-phase idle suspension, fair queue promotion, retention warnings, and guarded automatic deletion.
- [x] Implement authenticated additional-passkey enrollment, metadata-only listing, owner-scoped revocation with final-credential protection, and recovery-to-two-credential verification contracts.
- [x] Bound passkey admission without trusting proxy headers: preserve 256 of 4,096 ceremony slots for owner-authorized enrollment, replace retries per stable device instance, separate rate/cap lanes for unknown and historical devices, cap admission memory, prune deterministically, and return one resource-neutral capacity problem.
- [x] Implement identity-bound local checkpoints, verified file/workspace delta restore with deletions and rollback, recoverable confirmed tracked-path discard, fast-forward-only pull preconditions, authenticated APIs, and native static recovery flows.
- [x] Implement the native multiline composer with workspace/tab targeting, encrypted target-scoped drafts/history, explicit-send bracketed paste, system Photos/files import, and bounded randomized attachment staging on a dedicated no-exec tmpfs outside repositories.
- [x] Implement reliable targeted terminal input receipts, full retained replay after a gap, stale reconnect-token recovery, and mandatory active-grant output redaction before replay/cache.
- [x] Implement production-Linux fd-relative no-follow file access and exact displaced-content ETag compare-and-swap, with an honest portable-platform limitation and fresh-read reconciliation rule for uncertain save errors.
- [x] Implement serialized live grant/revoke synchronization to the helper's authoritative tmpfs state and mandatory synchronization before a new terminal process launches.
- [x] Implement immutable 8–16 GiB XFS project-quota volumes through the private root-owned workspace runtime, plus the historical 40 GiB host reserve and worst-case start-admission guard, for the deferred VPS/XFS profile.
- [x] Linearize each admitted workspace start from its durable capacity
  reservation through the provider-runtime gate; distinguish a proven no-call
  reservation from provision/start ambiguity, recover by deterministic lookup
  and confirmed stop, and block unsafe starts or expansion while a transitional
  provider may still be live.
- [x] Treat the exact Coder start build reaching `running` as the readiness
  boundary for ordinary, approved-setup, and quota starts; persist a
  component-wise quota upper bound across provider/store crash windows and
  retry per-owner convergence on every lifecycle scan.
- [x] Persist only a non-secret marker while creation-time environment/prompt
  values are being encrypted; clear it after all values commit, and quarantine
  any crash, partial, or legacy ambiguous outcome as
  `private_inputs_recreate_required` before provider work.
- [x] Bound the deferred XFS-profile workspace runtimes at creation: fixed CPU/memory/swap, a dedicated-engine 512-process cgroup default, explicit verified-device BPS/IOPS limits, and a 4 GiB EnvBuilder writable-rootfs quota.
- [x] Implement the distinct `owner_pc_beta` boundary: a 64 GiB
  loop-backed XFS guest image inside the dynamic D-backed WSL VHD; a single
  persistent quota-bearing volume lease and physical project-ID scan; immutable
  8–16 GiB byte quotas with a fixed 1,048,576-inode XFS project ceiling; one
  2 CPU / 2 GiB / 512-process workload; fixed I/O ceilings; exact internal
  `dev,nosuid` Podman self-binds beneath a `nodev` parent; and distinct
  65,536-ID mappings from `containers:1000000:1048576`. Provide a bounded
  no-release bootstrap for the free pinned host tools and first-manifest
  runtime/firewall artifacts, refuse post-activation working-tree overwrite,
  and hard-order dependent units after the verified owner mount. Keep AppArmor
  marked unavailable on WSL and require dated live proof before claiming
  acceptance.
- [x] Run the exact owner-PC initializer from revision `74b44a6`, exercise the
  singleton quota boundary and controlled WSL restarts, and preserve the
  resulting dated evidence. Apply and cold-start-verify the mount-parent and
  bounded socket-finalization fix at revision `c1d6a41`. This completes the host
  foundation evidence only; it does not complete the template-created
  Coder/EnvBuilder, Safe Mode, ingress, or TestFlight gates.
- [x] Implement the Dev Container bootstrap boundary: exact standard-directory detection is persisted, the admitted plain workspace receives the in-process-authenticated clone and confirms shutdown before structured review, approved supported setups restart with EnvBuilder, and unsupported/denied/queued/failed paths remain on the explicit plain fallback until a fresh decision.
- [x] Make setup review a durable reconciled boundary shared by direct application transitions and lifecycle queue promotion: atomically persist one pending event/activity, repair interrupted transitions, keep owner decisions nonexpiring, and finalize the event only after retryable workspace acceptance or denial is durable.
- [x] Make suspension and deletion authority boundaries durable and retryable: persist `suspending`/`deleting`, drain terminal and preview authority under the application workspace gate, wait for confirmed provider stop/absence, and retain the intermediate state on every ambiguous failure before final persistence.
- [x] Implement owner-authenticated connection lifecycle: aggregate GitHub/per-workspace
  Codex status, idempotent local GitHub disconnect that exclusively drains
  earlier installation-token leases and blocks later mint/use; reconnect and
  provider suspension share the ordering; ordinary sync and signed provider
  unsuspend hold one exclusive lease from fresh provider fetch through final
  writes, with only a fresh active unsuspend allowed to clear provider suspension
  and no path allowed to clear owner disconnect. Shared dedicated sessions are
  capped at `min(max(1, MaxConns), 8)` and exclusive sessions at
  `min(max(1, MaxConns), 2)`,
  and confirmed per-workspace Codex disconnect that stops only app-owned Codex
  tmux sessions and removes tmpfs/encrypted auth while preserving conversation
  history and non-Codex processes. Keep external App uninstall and genuine
  ChatGPT device-login/reauth flows owner-gated.
- [x] Linearize terminal credential issuance with session/device revocation and refresh replay using a bounded per-owner/device gate, durable principal revalidation immediately before mint, and atomic ticket-consume/subscriber installation against the terminal sweep.
- [x] Linearize revocation, tab close, suspension, and deletion with already-admitted PTY mutations and WebSocket delivery; bound all terminal queues/maps plus the Coder quota cache, and prove fresh PTY registration after resume.
- [x] Implement a fail-closed workspace autonomy transition: owner-scoped changes require suspension, Full Access requires destructive native confirmation, and resume applies one stored mode to provider egress and managed Codex configuration before exposing terminals.
- [x] Implement the static per-workspace Coder control path: an immutable relay
  alone joins the root-owned fixed uplink, host rules allow only the exact
  private Coder address/port, and Safe Mode receives no separate egress bridge.
  Keep `CODER_WORKSPACE_CONNECTIVITY_CONFIRMED=false` until a template-created
  target-Ubuntu workspace proves agent registration, PTY control and denial of
  every other host/general-egress route.
- [x] Run the source-security scanner against the recorded frozen verification tree.
- [x] Wire the integrated verifier to hash the deterministic Linux amd64/arm64 workspace-helper artifacts and require exact equality with the EnvBuilder image pins; statically require the same pins in the image-build verifier.
- [x] Validate the local release candidate after the final generated-contract, helper-hash, and version-pin checks.
- [x] Complete all locally achievable milestones and criterion mapping.
- [x] Build and runtime-check the three exact
  revision-`88ccb962a2fd7f11c6b86749b1b0c95119ffa4a8` OCI candidate images in the
  D-backed Ubuntu WSL Docker/Podman environment.
- [x] Run the profile-3/schema-2 audit against those exact image IDs and account
  for all 1,300 findings through exact expiring dispositions or the
  duplicate-sensitive non-forbidden-license baseline.
- [x] Rebuild, runtime-check, profile-3 rescan, and manifest-bind the exact
  images produced from the final documentation-bearing candidate. The
  authoritative release identity remains in the root-only receipt and
  generated manifest rather than this self-referential document.

## Final verification evidence

Historical hosted baseline only: on public `main` revision
[`c2aef5d3640f9f4660a550e1c0d3df6aacf26cf1`](https://github.com/GhostlyGawd/codex-mobile-cli/commit/c2aef5d3640f9f4660a550e1c0d3df6aacf26cf1),
the GitHub-hosted Linux [run `30183058698`](https://github.com/GhostlyGawd/codex-mobile-cli/actions/runs/30183058698)
([job `89742869774`](https://github.com/GhostlyGawd/codex-mobile-cli/actions/runs/30183058698/job/89742869774))
passed on `ubuntu-24.04`. The full race suite reported 33 package passes and three
packages without test files. Infrastructure verification reported 69 passes
and one expected root/POSIX-only skip; static policy, billing, deterministic
supply-chain, and release-artifact checks also passed.

On that same historical revision, the GitHub-hosted iOS [run `30183058643`](https://github.com/GhostlyGawd/codex-mobile-cli/actions/runs/30183058643)
([job `89742869559`](https://github.com/GhostlyGawd/codex-mobile-cli/actions/runs/30183058643/job/89742869559))
passed on `macos-26` with Xcode 26.6, checksum-verified XcodeGen 2.45.4, and
the iPhone 17 Pro simulator on iOS 26.5. Project generation and compilation
succeeded, followed by 63 unit tests and five UI tests with zero failures. This
is unsigned simulator evidence only; physical-device behavior, manual
accessibility review, signing, APNs, App Store/TestFlight, and credentialed
flows remain owner-gated.

Those hosted runs predate the current EnvBuilder source derivative, Codex
0.145.0 pin, and related dependency/policy changes. They are evidence only for
the linked revision, not the current tree; current-tree hosted Linux and macOS
runs are pending.

On the 2026-07-25 public-readiness tree, `go work sync`, full `go vet`, fresh
coverage, and `pwsh ./scripts/verify.ps1` passed. Coverage remained 55.8% and
the integrated verifier completed in 72.648 seconds; its 70-test
infrastructure suite completed successfully with six expected Windows skips. The literal root
`go fmt ./services/control-plane/...` is
rejected by Go 1.26's workspace-root module-pattern handling; the module-local
`go -C services/control-plane fmt ./...` equivalent passed without a diff. The
literal race command was attempted but this host has no CGO compiler, so the
current-tree race result remains unexecuted here. The hosted Linux run above is
historical evidence only for its linked revision. Xcode remains unavailable
locally on Windows; the hosted macOS result above is likewise historical and
does not supply a current-tree simulator result.

On 2026-07-16, `go work sync`, the Windows-compatible
`GO111MODULE=off go fmt ./services/control-plane/...`, full `go vet`, full
`go test -race -count=1 ./services/control-plane/...`, fresh coverage, and
integration-tag compilation passed. The integrated verifier reported 55.8%
total statement coverage and completed in 320.2 seconds with the portable GCC
toolchain. A live disposable PostgreSQL race run passed the complete
`internal/postgres` integration package, including `TestIntegrationPersistence`
and `TestIntegrationTerminalTabMutations`.

The same 2026-07-16 verifier completed its 66-test infrastructure suite with six expected
Windows skips, iOS static policy, supply-chain reproducibility, release-artifact
validation, and deterministic Linux workspace-helper verification. The exact
helper hashes are amd64
`f6fc430a2200d13ee0ef04dd576875b4f9a7c95a04287cbdec2deec3b495493c` and
arm64 `c7e4577a465b55721043612f9b6919248806576816388b01898f6c2784dc163e`.

On 2026-07-26, after the current Go security-dependency upgrade, two independent
`GOOS=linux CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w"`
cross-builds reproduced the new helper-profile-2 hashes: amd64
`ba7080f880206d90e05d751245c3635b9bdcbcbbc6152d61c3ec4221fd5bdf14`
and arm64
`3042240a601842f35233e383835a3e40aef6b05640b44f723bafefb133fdf9aa`.
The current `pwsh ./scripts/verify.ps1` run matched those active pins; profile 1
remains in the trusted verifier only for historical rollback compatibility.

Also on 2026-07-26, the D-backed Ubuntu WSL environment built and
runtime-checked release
`sha-88ccb962a2fd7f11c6b86749b1b0c95119ffa4a8` from that exact source revision.
Podman recorded control-plane image ID
`sha256:f2e275c9be9da96ae7ca8f3182152a44080ca5c519e1a3a2dc203d62327ca3e2`,
workspace image ID
`sha256:5c69392a575f6737aefde346e413dd3ee44adf2128525120dc23e6339fd8e64d`,
and EnvBuilder image ID
`sha256:958e6fb68ec8366c092fb93f8695ca08a8d546f404fa8ca2bf00734c9923ed76`.
The profile-3/schema-2 audit scanned those IDs with one frozen Trivy database
and accounted for all 1,300 findings: 66 vulnerabilities plus 1,234 license
findings, represented by 68 exact expiring dispositions (including the two
forbidden-license findings) and one duplicate-sensitive 1,232-entry
non-forbidden workspace-license baseline. Raw reports remained root-only and
outside the tracked repository. This developmental scan established the
profile-3 policy against those exact commit-88 images. Before handoff, the final
documentation-bearing candidate independently repeated the exact image build,
runtime checks, profile-3/schema-2 scan, receipt verification, and
manifest-schema-2 create/verify gate. This document intentionally does not
embed its own commit hash: the root-only receipt/report tree and generated
manifest name the authoritative audited revision. Every later Git commit,
including a merge-generated `main` commit, is a distinct release identity and
must repeat that exact gate before promotion.

Xcode 26.6/XcodeGen 2.45.4 testing was `NOT EXECUTED` on Windows. The hosted
unsigned simulator run above predates this tree, so current-tree hosted Xcode
execution remains pending.

On 2026-07-27, the exact initializer from revision
[`74b44a6`](https://github.com/GhostlyGawd/codex-mobile-cli/commit/74b44a6daafac5fec3ecff029398b6d5bf211f3a)
ran on the D-backed Ubuntu WSL host. It created the root-owned mode-`0600`
64 GiB XFS image and mounted it at `/srv/codex-mobile` with
`rw,nosuid,nodev,noatime,prjquota`. The singleton gate admitted one workspace
claim and rejected a different claim. Its 8 GiB project received equal block
soft/hard limits and equal 1,048,576-inode soft/hard limits. A stale inode limit
failed closed, was repaired once, and a later project-ID reuse inherited the
required inode limit. A 1 MiB write succeeded and a 9 GiB write failed with
`ENOSPC`; the proof lease and volume were removed afterward.

An empty marker on that XFS mount survived two WSL terminations. The cold-start
fix at revision
[`c1d6a41`](https://github.com/GhostlyGawd/codex-mobile-cli/commit/c1d6a41e85a4ced768307c839fee61e0927f7e01)
then made the active storage mount's parent ID authoritative so hidden stale
self-binds cannot satisfy the mount check, and kept socket finalization bounded
within its unit timeout. After a cold boot, the owner and workspace runtime
services were active; the private socket was owned by
`root:coder-provisioner` with mode `0660`; repeated mount-helper execution did
not stack global self-binds; the dedicated sub-ID pool remained
`containers:1000000:1048576`; and loopback retained `10.86.0.1/32`.

This is host-foundation evidence, not a complete Workspace, Host boundary,
Capacity, Maintenance, or release pass. Still `GATED` and `NOT EXECUTED` are a
real template-created Coder relay/workload with cgroup, I/O, and distinct user
mapping evidence; the Coder/EnvBuilder flow; Safe Mode network denial; reviewed
public HTTPS ingress and DNS/TLS/AASA; the owner-created GitHub App; and
physical-device, signing, APNs, and TestFlight scenarios. AppArmor is
unavailable in the selected WSL environment and is not claimed as passing.
Future VPS-specific provider-backup, reboot, ten-session, and load evidence is
deferred.

The recorded 2026-07-16 tree's source-security audit completed with Syft
1.46.0, Trivy 0.72.0, Gitleaks 8.30.1, go-licenses 2.0.1, and govulncheck 1.6.0.
Gitleaks found no leak; Trivy reported zero unsuppressed high/critical
misconfiguration, secret, or license findings; and govulncheck reported zero
called/imported-package vulnerabilities plus seven required-module
vulnerabilities whose affected symbols are not called. `go-licenses` exited
successfully; unlicensed first-party-package unknown classifications are not scan
errors. Detailed scanner reports were ephemeral outside the repository. Built
OCI image scanning is executed for both the developmental commit-88 candidates
and the final documentation-bearing candidate described above. Production-host
activation remains unverified.
