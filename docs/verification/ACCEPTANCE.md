# Acceptance verification

Last updated: 2026-07-26. `PASS` requires executed evidence; a fake at an
external boundary proves only the local contract. `GATED` means owner
credentials, physical Apple devices, or a purchased target VPS is required.
`GATED (backend PASS)` means the automated backend portion passed, but the
complete acceptance scenario is still gated. See [BACKEND.md](BACKEND.md) for
commands, evidence boundaries, and the live verification runbook.

## Public repository and CI cutover

- The original repository and its historical pull requests, workflow logs, and
  commit metadata are preserved privately at
  `GhostlyGawd/codex-mobile-cli-private-archive`. It has not been marked
  archived on GitHub.
- The active product tree is public at `GhostlyGawd/codex-mobile-cli`,
  repository node `R_kgDOTjbM3w`, from the distinct clean root
  `fee059a75afa8f0d07dc7dccdcbaaad5da82f0b4`; the historical verified public
  `main` baseline revision is
  [`c2aef5d3640f9f4660a550e1c0d3df6aacf26cf1`](https://github.com/GhostlyGawd/codex-mobile-cli/commit/c2aef5d3640f9f4660a550e1c0d3df6aacf26cf1).
- Before publication, only this repository's owner-PC listener, GitHub
  registration, runner root, and launcher were removed. The public repository
  has no self-hosted runner, and unrelated owner-PC runners were left
  untouched.
- Public workflow policy uses only standard `ubuntu-24.04` and `macos-26`
  GitHub-hosted runners. Jobs require public visibility plus
  `PUBLIC_CI_ENABLED == "true"`, have read-only permissions, and receive no
  secrets or persisted checkout credential.
- On that historical baseline, the public `main` Linux [run `30183058698`](https://github.com/GhostlyGawd/codex-mobile-cli/actions/runs/30183058698)
  ([job `89742869774`](https://github.com/GhostlyGawd/codex-mobile-cli/actions/runs/30183058698/job/89742869774))
  and unsigned Xcode simulator [run `30183058643`](https://github.com/GhostlyGawd/codex-mobile-cli/actions/runs/30183058643)
  ([job `89742869559`](https://github.com/GhostlyGawd/codex-mobile-cli/actions/runs/30183058643/job/89742869559))
  passed. Those runs predate the current EnvBuilder source derivative, Codex
  0.145.0 pin, and related dependency/policy changes. They are evidence only for
  the linked revision, not the current tree; current-tree hosted Linux and macOS
  runs are pending. The historical hosted evidence also does not satisfy any
  physical-device, signing, APNs, TestFlight, provider, Docker, VPS,
  manual-accessibility, or credentialed acceptance gate.

Unless a row names a later exact revision, its reference to a hosted simulator
pass means the historical baseline above and does not claim current-tree hosted
execution.

| # | Scenario | Status | Evidence / remaining gate |
| ---: | --- | --- | --- |
| 1 | Passkey | GATED (backend PASS) | `passkeys` proves short-lived single-use bootstrap and authenticated registration ceremonies bound to the owner/current active installation, existing-credential exclusion, recovery followed by a second credential, owner-scoped/idempotent revoke, replay/device-swap rejection, and final-credential race protection. Admission tests prove a five-minute/4,096 total bound; a 256-slot owner-enrollment reserve; one replace-on-retry login per stable instance; four-start/one-per-15-second per-instance pacing; a 512-active and 32-burst/one-per-second unknown lane; a separate 32-burst/four-per-second lane backed by at most 4,096 historical device hashes; a 4,608-entry admission-state bound; concurrent exhaustion isolation; deterministic refill/pruning; and identical resource-neutral capacity errors. `session` proves rotation, replay-family revocation, expiry, and device revocation; `application` and `httpapi` prove metadata-only DTO/base64url, protected-route boundaries, and stable problem mapping. A real associated-domain ceremony still requires the owner domain, TLS, Mac, and Apple device. |
| 2 | GitHub | GATED (backend PASS) | `githubapp` proves signed App JWTs, scoped installation tokens, repository listing, suspension rejection, and official `DELETE /installation/token` cleanup. `gitops`/`workspacehelper` prove repository-scoped tokens are used only as bounded in-process `go-git` HTTPS auth with an exact GitHub host/direct trusted transport, then cleared/released; remote token operations enforce a control-plane-owned inner deadline independent of local Coder SSH. No AskPass, credential/token file, environment, argv or token URL is created. Unit concurrency tests prove every mint reserves non-secret durable use metadata and keeps its shared owner/installation lease through detached cleanup. Early local cancellation retains an outstanding record through the remote safe-after deadline even when GitHub accepts revocation; disconnect/suspension commit the local disable but return conflict until that boundary, reconnect completion refuses old records, and sync cannot become the last availability write after disconnect. The PostgreSQL implementation uses dedicated advisory-lock sessions with shared concurrency capped at `min(max(1, MaxConns), 8)` and exclusive concurrency at `min(max(1, MaxConns), 2)`. A live disposable PostgreSQL run passed the cross-pool drain, metadata-only token lifecycle, conflict-until-expiry, stale final-write rejection, failed-reconnect Get/List availability, and `MaxConns=1` callback regressions. Local disconnect does not uninstall the external App; explicit token revocation can fail or leave an already-authorized request running only through its recorded safe-after/provider expiry. A live private/org installation, clone/push/PR, provider-side uninstall/reconnect, token-persistence inspection and webhook delivery still require the owner-created GitHub App. |
| 3 | Workspace | GATED | Terraform 1.14.5 formatting, locked initialization, and validation pass for the Coder template with exact provider/image/helper pins, persistent data, plain/EnvBuilder paths, an immutable create-time `disk_gib` parameter bounded to 8–16 GiB (12 GiB default), and a per-workspace Coder relay/control-uplink contract. The integrated verifier deterministically cross-built Linux amd64/arm64 workspace helpers and matched both artifacts to the EnvBuilder Dockerfile pins. D-backed WSL built and runtime-checked the exact commit-tagged workspace and EnvBuilder candidates, including the final documentation-bearing candidate. Go/application/lifecycle/Coder/PostgreSQL tests cover durable non-expiring setup-review reconciliation; `suspending`/`deleting` retry states; terminal/preview authority drain under the workspace gate; confirmed provider stop/absence before final persistence; exact cascade finalization; and a fresh PTY on resume. Creation persists only a `private_inputs_pending` non-secret marker while environment/prompt values are encrypted; crash, partial, and legacy ambiguity becomes `private_inputs_recreate_required` before provider work. Autonomy tests prove resume sends the stored mode to provider egress and rewrites managed Codex configuration before returning to running; Full Access has destructive native confirmation. `CODER_WORKSPACE_CONNECTIVITY_CONFIRMED` remains false until a template-created Ubuntu 24.04 workspace proves Coder agent registration/PTY through the relay, Safe Mode no-general-egress behavior, approval success/failure, suspend/resume, Dev Container and persistent-volume behavior on the dedicated private quota runtime. |
| 4 | Isolation | GATED | Static tests verify per-workspace internal/optional-egress networks, data/trusted-helper volumes, immutable non-root/read-only Coder relay, capability/cgroup limits, private user namespaces, non-root interactive users, capability drops, `no-new-privileges`, AppArmor/seccomp, read-only root/helper mounts, no host path/device/runtime socket, and a hostile helper-shadow fixture. Only the relay joins the fixed control uplink; the workspace does not. The target-Linux suite must prove two-workspace/EnvBuilder separation, actual user namespaces, that Coder is reachable only through the scoped relay, and that Safe Mode cannot reach any other host/control/general-egress destination. |
| 5 | Host boundary | GATED | Compose, Caddy, Ansible, systemd, unprivileged provisioner separation, private socket membership, secret-file and billing-policy checks pass statically. Network tests validate the managed RFC1918 `codex-mobile-control` bridge, literal private Coder bind, and `INPUT`/`DOCKER-USER` rules that allow `cm-control0` only to the exact Coder address/port. The dedicated Podman API is root-owned, mode `0660` for `root:coder-provisioner`, deliberately root-equivalent, and absent from Coder/workspaces; privileged Coder control-plane/provisioner credentials are likewise absent. Every workspace necessarily contains its standard `CODER_AGENT_TOKEN` with `api_key_scope=no_user_data`, and same-authority repository code may observe/use it. Exact `/srv/codex-mobile` XFS `pquota`/`prjquota`, real rootful-Podman bridge/firewall paths, socket ownership, audit, AppArmor, reboot behavior, and hostile proof that the scoped agent token grants no privileged Coder API/cross-workspace authority require the configured Ubuntu 24.04 VPS. |
| 6 | PTY persistence | GATED (backend PASS) | `coder` proves fixed persistent tmux command construction and PTY endpoint validation; `application`, `postgres`, `httpapi`, and `terminal` prove owner/workspace scoping, bounded metadata-only rename, exact atomic reorder, explicit confirmed/idempotent close, primary-Codex protection, PTY unregister, ticket/reconnect revocation, one-time lazy runtime registration, and authenticated fallback after a stale reconnect token. Adversarial concurrency tests prove a request authenticated before revocation cannot mint afterward: issue, session/device revoke, and refresh rotation/replay share a reference-counted per-owner/device gate with durable principal revalidation; replay sweeps terminal access before releasing it; ticket consumption/subscriber installation is atomic with the terminal sweep; and unregister/suspension waits for admitted PTY mutations and WebSocket writes before returning. Gate entries disappear after the final holder/waiter. Suspension tests prove every runtime authority is cleared and resume registers a fresh PTY. The live disposable PostgreSQL terminal-tab mutation race passed. iOS static policy covers gap reset/rebuild plus native rename/reorder/close confirmation controls, and the hosted unsigned simulator suite compiled and passed. Coder agent registration through the relay, process survival, and real PTY termination across control-plane/network interruption still need a Linux Coder workspace; real-device behavior remains gated. |
| 7 | Terminal fidelity | GATED (backend PASS) | `terminal` proves frames, complete retained replay after a nonzero gap marker, lease/takeover, targeted reliable per-device/tab idempotent-input receipts after PTY write, retry dedupe, two-device isolation, receipt backpressure/capacity rejection before write, OSC 52 blocking, title sanitization, mandatory split-chunk active-grant redaction before output enters replay/subscribers/cache, and bounded tab/ticket/reconnect/subscriber/queue state at global and narrower scopes. Each subscriber has mutation and delivery gates, so revocation cannot return while an earlier PTY mutation or WebSocket write remains in flight and no later delivery can begin. Native model tests cover same-key composer retry, stale reconnect-token fallback, renderer/cache reset on gap, and resume from the announced earliest sequence; those tests compiled and passed in the hosted unsigned simulator suite. Dedupe/receipts are process-memory reliability, not durable exactly-once delivery: a gateway crash after PTY write but before receipt can make a later retry duplicate input. Pending composer keys are also memory-only, so app termination after receipt but before encrypted draft clearing can leave a stale resendable draft; attachments reuse the exact staged payload only until expiry. The VT/xterm corpus, Unicode width, hardware keys, SwiftTerm rendering fidelity, and input fidelity still require a Mac and physical Apple device. |
| 8 | Genuine Codex | GATED (backend PASS) | Managed config forces ChatGPT and the file store; the trusted fixed-path wrapper tests authenticated encryption, tamper/wrong-key rejection, concurrent leases, request/API-key scrubbing, strict ambient-environment allowlisting, and absence of auth/environment plaintext from persistent workspace state. Owner-authenticated aggregate/per-workspace status validates only credential state. Confirmed Codex disconnect is owner/workspace scoped and rejected for unavailable/suspended runtimes. It validates every stored Codex tab, then the helper kills only those app-owned tmux sessions, waits for their leases and removes tmpfs key/materialized auth plus encrypted-at-rest auth as the security commit point; control-plane unregister follows. An injected unregister failure returns/audits partial cleanup while proving credentials remain revoked. Non-Codex processes and conversation history are preserved. iOS static policy covers bounded status, destructive confirmation, honest effects and device-login reauth guidance. The final documentation-bearing workspace and EnvBuilder candidates passed build/runtime checks with the pinned Codex 0.145.0/helper contract. The authenticated attachment API validates owner/workspace/tab scope, content signatures, count and byte limits, returns randomized paths under a private dedicated no-exec tmpfs, records metadata-only audit, scrubs helper request bytes, and expires files through opportunistic and periodic cleanup. A real Linux tmpfs/helper-volume/disconnect run plus owner ChatGPT device login, reconnect/refresh, checkpoint, suspend/resume, attachment consumption, and TUI verification remain required; local disconnect does not claim to revoke the upstream ChatGPT account/session. |
| 9 | Approvals/APNs | GATED (backend PASS) | `workspace`, `githubworkspace`, `coder`, and PostgreSQL tests prove the admitted plain workspace starts, receives its authenticated clone, stops, and only then waits for approval; both standard config locations persist exactly through queue/denial/failure/retry, supported approval selects EnvBuilder, and unsupported approval stays on the explicit plain fallback. `setupreview`, `application`, `lifecycle`, and a live disposable PostgreSQL race prove direct and queued transitions reconcile one atomic event/activity pair even under concurrent repair, remain pending beyond the former 24-hour window, notify only after commit, and retry event finalization without re-running already accepted setup. `apns` proves environment-key selection, generic payloads, retry/unregistered handling, invalid-device rejection, and live PostgreSQL registration/revocation ordering. Live APNs delivery, real Coder/EnvBuilder execution, notification delivery, and deep-link UX still require owner keys, a configured Ubuntu host, entitlements, and a device. |
| 10 | Git/editor | GATED (backend PASS) | `files` proves bounded read/tree/search and create/update behavior. Production Linux pins the workspace root, uses fd-relative `O_NOFOLLOW` directory traversal and regular-file opens, and updates by rename-exchange followed by hashing the exact displaced file; commit-boundary mismatch rolls back. Parent/root/path swap, symlink/special-file, traversal, sensitive-path, resource/cancellation, create-race, and concurrent ETag tests pass. Portable `os.Root` tests prove confinement and deterministic conflicts, but non-Linux cannot guarantee external-writer CAS in the final check-to-rename window. Any save error after a possible commit requires a fresh read/ETag before retry. `gitops`/`workspacehelper` prove bounded status/stage/diff/commit, checkpoint-backed confirmed discard, strict Git subprocess environments, path safety, and active-grant scanning before mutation. Pull remains fast-forward-only. The hosted Accessibility XXXL UI test reaches Git review and opens the read-only diff destination. Live native editing against a workspace, target-Linux filesystem/scanner behavior, and terminal-vs-native contention still require a device and live-workspace verification. |
| 11 | Preview | GATED (backend PASS) | `preview` proves audience- and device-bound expiry/revocation, loopback-only targets, fragment-token exchange with credential stripping, active HTTP/WS context cancellation, and route/grant/tunnel teardown. `application` proves fragment-only access URLs bound to the private Coder workspace target; durable-principal validation inside the device revocation gate; and device/session/suspension/deletion sweeps serialized against new grants under the workspace gate. Infrastructure validates separate API/wildcard Caddy sites and preserved preview `Host`. Wildcard DNS/TLS, real HTTP/WebSocket forwarding, hostile-origin isolation, and deployed revoke behavior still require a configured Linux deployment; stock Caddy cannot issue the wildcard via HTTP-01, so a reviewed DNS-01 provider build or externally managed wildcard certificate is also required. |
| 12 | Offline | GATED | Native sources and static policy implement a Keychain-backed AES-GCM read-only cache plus separately encrypted, target-scoped composer drafts/history. The server removes exact and encoded active-grant forms before terminal bytes enter replay/cache; the native cache adds a bounded conservative credential-label/opaque-token heuristic and resets on a replay gap. Neither claims to recognize every unrelated human-readable secret. Attachment selections remain memory-only, original filenames and bytes are excluded from offline persistence, and composer launch/send is disabled offline while received terminal history remains visibly cached. CryptoKit authentication/tamper/bounds tests compile and pass in the hosted unsigned simulator suite, but physical-device file-protection behavior, offline/reconnect UX, and backup inspection remain gated. |
| 13 | Retention | GATED (backend PASS) | Lifecycle tests prove running-to-idle-to-suspended transitions, activity compare-and-swap protection, foreground/background process preservation, one-time pre-expiry warnings, 7/30/90-day anchors at suspension, keep-forever/dirty/unpushed protection, per-workspace/global idle policy, and fair queue promotion after failed provisioning. Durable `suspending` and `deleting` states retry cleanup/provider/final-persistence failures without repeating the checkpoint, and live PostgreSQL integration proves exact finalization cascades operational children while retaining metadata-only audit identity. Process-idle classification never trusts a reported `comm`/name as identity: only quiescent managed terminal infrastructure with a trusted executable/ancestry is excluded, ambiguity fails busy, and every TCP listener counts as activity; adversarial legacy-name spoofing and runnable trusted-shell cases are covered. Real Linux `/proc` ancestry/executable/port behavior and timed provider/tmux/tunnel cleanup still require a Coder workspace. |
| 14 | Capacity | GATED (backend PASS) | Public/backend/native disk requests are 8–16 GiB with a 12 GiB default and are sent to Coder only at create. Each volume is immutable and requests XFS local-volume `size=<G>G,inodes=<G*65536>`. Backend admission reserves 40 GiB of the 200 GiB host budget and requires at least 56 GiB free for any new start, so ten maximum 16 GiB volumes total 160 GiB; boundary tests reject 55 GiB and admit 56 GiB. New starts hold admission continuously from the durable `provider_start_reserved` marker through the runtime gate, switch to `provider_provision_unconfirmed` before a provider call, and fail closed while another transition may still be live. Coder start, setup, and quota operations do not become ready until the exact returned build reaches `running`. Quota changes persist a component-wise conservative high-water before possible provider expansion, persist the exact target after confirmation, and receive level-triggered per-owner reconciliation on lifecycle scans. Static policy fixes memory/swap/CPU; applies 64/32 MiB/s and 2,000/1,000 IOPS to an explicitly verified mount device; caps EnvBuilder's writable overlay at 4 GiB; and supplies the provider's missing PIDs field through the dedicated Podman engine's creation-time `pids_limit = 512`. The target-host spike now refuses to pass without inspecting a real running template-created container's HostConfig, `pids.max`, and `io.max`, plus disposable volume/rootfs over-quota failures. That spike, ten interactive sessions, and 11th-workspace refusal remain `GATED` and `NOT EXECUTED` VPS checks. |
| 15 | Recovery | GATED (backend PASS) | Local v2 checkpoint creation/list/hash verification and identity binding, v1 file-only compatibility, mandatory pre-restore checkpoints, recorded file/deletion restore, delta-over-current semantics, idempotency, atomic replacement, Git/control-metadata preservation, and rollback journaling pass portable tests. Tampered, oversized, traversal, sensitive, duplicate/case/hierarchy-conflicting, symlink/FIFO and cross-workspace archives fail closed; injected mid-apply failure rolls back, and incomplete rollback retains its private journal. Authenticated APIs and iOS static policy cover list/file/workspace restore with explicit confirmation and visible recovery IDs, and the native target compiles in the hosted unsigned simulator suite. Target-Linux race/permission behavior, database restore, suspended-volume restore, server-loss reconstruction, provider daily-backup restoration, and physical-device recovery UX still require the VPS/provider or owner device. The provider recovery design explicitly treats the whole-server capture as containing encrypted state and the host master key together: availability/key-data consistency, not cryptographic separation. |
| 16 | Maintenance | GATED (backend PASS) | Immutable release promotion, pre-checkpoint, health-gated rollback, service ordering, non-automatic reboot policy, and update/incident/credential runbooks pass portable checks. Master-key unit tests cover exact all-family AAD rewrap, verify-before-update, tamper/unknown-row abort, rollback, confirmation, and untouched key files; an integration-tag test is available for active-serve refusal. The runbook records that whole-server backups may retain the old or new host key with their matching database generation; deleting live rollback material does not erase provider retention. Executing that PostgreSQL lock test, a live rotation/checkpoint rollback, and drain/update/restart/reboot and post-reboot recovery require the target VPS; active user processes must not be claimed to survive reboot. |
| 17 | Performance | GATED | Benchmarks pending; representative network/VPS/iPhone measurement required |
| 18 | Accessibility | GATED | The hosted unsigned simulator UI suite passed at the Accessibility XXXL content-size category and kept terminal switching, Git review/read-only diff, and Settings reachable. The asset catalog contains the universal app icon; static policy parses the PNG and proves a non-interlaced 1024×1024, 8-bit truecolor image without alpha/transparency. Manual VoiceOver, contrast, touch-target, orientation, and physical-device Dynamic Type evidence remain gated. |
| 19 | Billing | GATED | Billing policy and negative tests pass and no script provisions a provider resource. Dated research found one published candidate within the fixed-price/no-overage/backup contract; no second qualifying plan was established. Taxed checkout terms and any purchase remain explicit owner gates. |

## Executed infrastructure evidence by revision

- Historical hosted baseline only: on public `main` revision
  [`c2aef5d3640f9f4660a550e1c0d3df6aacf26cf1`](https://github.com/GhostlyGawd/codex-mobile-cli/commit/c2aef5d3640f9f4660a550e1c0d3df6aacf26cf1),
  the hosted Linux [run `30183058698`](https://github.com/GhostlyGawd/codex-mobile-cli/actions/runs/30183058698)
  ([job `89742869774`](https://github.com/GhostlyGawd/codex-mobile-cli/actions/runs/30183058698/job/89742869774))
  passed on `ubuntu-24.04`. The race suite reported 33 package passes and three packages
  without test files. Infrastructure verification reported 69 passes and one
  expected root/POSIX-only skip; static policy, billing, deterministic
  supply-chain, and release-artifact checks also passed.
- On the same public revision, the hosted iOS [run `30183058643`](https://github.com/GhostlyGawd/codex-mobile-cli/actions/runs/30183058643)
  ([job `89742869559`](https://github.com/GhostlyGawd/codex-mobile-cli/actions/runs/30183058643/job/89742869559))
  passed on `macos-26` with Xcode 26.6,
  checksum-verified XcodeGen 2.45.4, and the iPhone 17 Pro simulator on iOS
  26.5. Project generation and compilation succeeded, then all 63 unit tests
  and five UI tests passed. This is unsigned simulator evidence, not
  physical-device, signing, APNs, App Store/TestFlight, credentialed, or manual
  accessibility evidence.
- On 2026-07-25, the public-readiness working tree ran
  `pwsh ./scripts/verify.ps1` successfully in 72.648 seconds. The 70-test
  infrastructure suite completed successfully with six expected Windows skips: five checkpoint
  execution cases requiring POSIX and one installed-artifact case requiring
  root POSIX ownership/mode semantics. Workspace-control-network, billing, iOS
  static, deterministic supply-chain, public-workflow, and release-artifact
  policy checks passed. Xcode was skipped locally; the hosted macOS result above
  is historical evidence only for its linked revision, not a current-tree
  simulator result.
- On 2026-07-25, a fresh persistent D-drive clone ran
  `pwsh ./scripts/verify.ps1` successfully in 216.685 seconds. The 68-test
  infrastructure suite completed successfully with six expected Windows skips: five
  checkpoint execution cases requiring POSIX and one installed-artifact case
  requiring root POSIX ownership/mode semantics. Workspace-control-network,
  billing, iOS static, deterministic supply-chain, and release-artifact policy
  checks passed. The current Windows environment also explicitly skipped the Go
  race detector because CGO and a C compiler are unavailable, and skipped the
  Xcode 26.6/XcodeGen 2.45.4 build because no configured macOS host exists.
- On 2026-07-16, `pwsh ./scripts/verify.ps1` passed on the then-current tree in 320.2
  seconds with a portable GCC toolchain. Its 66-test infrastructure suite
  completed successfully with six expected POSIX-only Windows skips. Coverage
  includes negative preflight/billing cases, immutable volume/rootfs quota
  options, explicit I/O-device binding, the 512-PID engine default, the 18,432
  MiB memory ceiling, private root-owned socket boundary, provisioner
  separation, XFS mount policy, isolation, and helper checksum-pin policy.
- Docker Compose `5.3.1` accepts the local base file and the GitHub-only,
  APNs-only, and combined file-secret override combinations.
- Caddy `2.11.4` validates both local defaults and production API/wildcard site
  substitutions. This is syntax/routing evidence, not certificate issuance.
- Terraform `1.14.5` formatting, locked provider initialization, and validation
  pass on the current quota-template tree. The
  `docker_volume.driver_opts` shape was also checked against the pinned
  provider's official schema. Ruff lint/format, ShellCheck 0.11.0, Hadolint
  2.14.0, and Caddy 2.11.4 validation also pass on the combined tree.
- On 2026-07-26, D-backed Ubuntu WSL built and runtime-checked release
  `sha-88ccb962a2fd7f11c6b86749b1b0c95119ffa4a8`. The exact Podman IDs were
  control plane
  `sha256:f2e275c9be9da96ae7ca8f3182152a44080ca5c519e1a3a2dc203d62327ca3e2`,
  workspace
  `sha256:5c69392a575f6737aefde346e413dd3ee44adf2128525120dc23e6339fd8e64d`,
  and EnvBuilder
  `sha256:958e6fb68ec8366c092fb93f8695ca08a8d546f404fa8ca2bf00734c9923ed76`.
  The profile-3/schema-2 audit scanned those IDs with one frozen Trivy database
  and accounted for all 1,300 findings: 66 vulnerabilities and 1,234 license
  findings, using 68 exact expiring dispositions (including the two
  forbidden-license findings) plus one duplicate-sensitive baseline for all
  1,232 non-forbidden workspace-license findings. Raw evidence remained
  root-only outside the tracked repository. This developmental run established
  the profile-3 policy against those exact commit-88 candidates. Before
  handoff, the final documentation-bearing candidate independently repeated
  the exact build/runtime/profile-3/schema-2 audit and manifest-schema-2
  create/verify gate. The root-only receipt/report tree and generated manifest,
  rather than this self-referential document, name the authoritative revision.
  Every later commit, including a merge-generated `main`, must repeat the gate
  before promotion.

Still `NOT EXECUTED` as production evidence: Compose-stack deployment, the
dedicated production Podman provisioner/runtime, XFS volume/rootfs
project-quota enforcement/write-past-limit probes, live PID/I/O cgroups on a
template-created workspace, live EnvBuilder/Dev Container behavior, Coder
workspace lifecycle, AppArmor/host hardening, ten-session load,
restore/rollback/reboot drills, public DNS/TLS, and provider backup restoration.
Those checks remain `GATED`; their results must not be inferred from the WSL
candidate-image evidence.

## Executed backend evidence

- On the 2026-07-25 public-readiness tree, `go work sync`, full `go vet`, and
  fresh non-race coverage passed at 55.8% total statements. The literal
  root-level `go fmt ./services/control-plane/...` is rejected by Go 1.26's
  Windows workspace path handling; the module-local equivalent
  `go -C services/control-plane fmt ./...` passed and left no source diff. The
  literal race command was attempted but could not allocate the race runtime
  because this Windows host has no CGO compiler. The hosted public `main` Linux
  run above is historical evidence only for its linked revision and does not
  supply the current-tree race gate.
- The 2026-07-25 fresh-clone run used
  `go -C services/control-plane fmt ./...`, the module-local equivalent required
  by Go 1.26 when the checkout is outside GOPATH. Full `go vet` and a fresh
  non-race coverage run passed, including the restored tracked
  `internal/secrets` package and Windows-safe local Git remote fixtures.
- On 2026-07-16, `go work sync`, `GO111MODULE=off go fmt
  ./services/control-plane/...`, and full `go vet
  ./services/control-plane/...` completed successfully.
- `go test -race -count=1 ./services/control-plane/...` passed for every
  control-plane package. A fresh coverage run passed, and the integrated
  verifier reported 55.8% total statement coverage. The integration-tag suite
  also compiled successfully.
- With a disposable local PostgreSQL instance, `go test -race
  -tags=integration -count=1 -v ./services/control-plane/internal/postgres`
  passed in full, including `TestIntegrationPersistence` and
  `TestIntegrationTerminalTabMutations`. This is live local database evidence,
  not evidence for GitHub, Apple, Coder, Docker, or any provider account.
- The PostgreSQL run covers, among other package cases, advisory-lock drain,
  metadata-only installation-token use, disconnect conflict until safe-after,
  stale availability-write rejection, `MaxConns=1` regressions, exact terminal
  tab mutations, durable private-input quarantine, and workspace lifecycle
  persistence. The full race run also covers continuous admission-to-runtime
  capacity reservation, provider ambiguity markers, exact-running Coder build
  barriers, conservative quota high-water persistence, and level-triggered
  reconciliation.

## Executed release/operations evidence

- The recorded 2026-07-16 integrated verifier passed iOS static policy,
  supply-chain reproducibility, and release-artifact validation. That dated
  tree's source-security audit then passed with Syft 1.46.0, Trivy
  0.72.0, Gitleaks 8.30.1, go-licenses 2.0.1, and govulncheck 1.6.0. Gitleaks
  found no leak; Trivy reported zero unsuppressed high/critical
  misconfiguration, secret, or license findings; and govulncheck reported zero
  called/imported-package vulnerabilities plus seven required-module
  vulnerabilities whose affected symbols are not called. `go-licenses` exited
  successfully; unlicensed first-party-package unknown classifications are not
  errors. Detailed reports were ephemeral outside the repository.
- The recorded 2026-07-16 deterministic Linux workspace-helper verification
  passed with profile-1 hashes amd64
  `f6fc430a2200d13ee0ef04dd576875b4f9a7c95a04287cbdec2deec3b495493c`
  and arm64
  `c7e4577a465b55721043612f9b6919248806576816388b01898f6c2784dc163e`.
- On 2026-07-26, after the current Go security-dependency upgrade, two
  independent `GOOS=linux CGO_ENABLED=0 go build -trimpath -buildvcs=false
  -ldflags="-s -w"` cross-builds reproduced profile-2 hashes amd64
  `ba7080f880206d90e05d751245c3635b9bdcbcbbc6152d61c3ec4221fd5bdf14`
  and arm64
  `3042240a601842f35233e383835a3e40aef6b05640b44f723bafefb133fdf9aa`.
  The current `pwsh ./scripts/verify.ps1` run matched the active profile-2 pins;
  profile 1 remains accepted only for historical rollback compatibility.
- The retired private Windows workflow completed a bounded trusted smoke before
  publication. Its exact run, runner identity, path metadata, and logs remain
  only in the private historical archive. That historical evidence is not used
  to satisfy Linux race, Xcode, container, or public-workflow acceptance; the
  hosted public runs above supply Linux and unsigned-simulator evidence only
  for their linked historical public revision.
- D-backed WSL executed the exact developmental commit-88 OCI build, runtime
  checks, and profile-3/schema-2 Trivy/package/license audit described above,
  then repeated the complete gate and manifest binding for the final
  documentation-bearing candidate. Local production Compose startup was not
  executed.
- The unsigned Xcode/iOS simulator build and automated tests passed in the
  historical hosted run linked above. Current-tree hosted Xcode execution is
  pending. Signing, physical-device behavior, App registration, APNs,
  TestFlight, GitHub App, DNS/TLS, VPS deployment, and every
  provider/restore/load/reboot drill remain `GATED`. The runbooks are executable
  guidance and safety policy, not evidence those external actions occurred.
- `pwsh ./scripts/test-ios-static.ps1` passed on Windows. It covers the universal
  1024×1024 app-icon mapping, accessibility identifiers, Accessibility XXXL
  UI-test scenarios, terminal receipt/gap contracts, encrypted caches, and
  cache-only heuristic redaction. Xcode 26.6/XcodeGen 2.45.4 generation and
  `xcodebuild` testing were `NOT EXECUTED` on Windows. They passed only in the
  historical hosted unsigned iPhone 17 Pro simulator run above; the current-tree
  rerun is pending.
