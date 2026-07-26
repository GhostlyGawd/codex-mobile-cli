# Backend verification runbook

This runbook records what the Go backend suite proves and, just as importantly, what it does not prove. Unit tests that use fake GitHub, Coder, APNs, WebAuthn, or network boundaries are contract evidence only. They are not substitutes for credentialed end-to-end verification.

## Automated verification

Use the Go version pinned by the repository. The required full pass runs from
the repository root:

```shell
go work sync
go fmt ./services/control-plane/...
go vet ./services/control-plane/...
go test -race ./services/control-plane/...
go test ./services/control-plane/... -coverprofile=coverage/control-plane.out
```

On Windows with Go 1.26.5, use
`go -C services/control-plane fmt ./...`; the integrated PowerShell verifier
applies that module-local equivalent. The POSIX verifier and public Linux
workflow use `GO111MODULE=off go fmt ./services/control-plane/...`.

For a focused backend security/contract pass from `services/control-plane`:

```shell
go test ./internal/passkeys ./internal/session ./internal/httpapi ./internal/application
go test ./internal/githubapp ./internal/githubsync ./internal/files ./internal/gitops ./internal/workspacehelper
go test ./internal/coder ./internal/terminal ./internal/preview ./internal/apns ./internal/workspace
```

With an isolated PostgreSQL integration DSN available, run from the repository
root:

```shell
POSTGRES_TEST_DSN='postgres://...' go test -race -tags=integration -count=1 -v ./services/control-plane/internal/postgres
```

Historical hosted baseline evidence on public `main` revision
[`c2aef5d3640f9f4660a550e1c0d3df6aacf26cf1`](https://github.com/GhostlyGawd/codex-mobile-cli/commit/c2aef5d3640f9f4660a550e1c0d3df6aacf26cf1):

- The `ubuntu-24.04` Linux [run `30183058698`](https://github.com/GhostlyGawd/codex-mobile-cli/actions/runs/30183058698)
  ([job `89742869774`](https://github.com/GhostlyGawd/codex-mobile-cli/actions/runs/30183058698/job/89742869774))
  passed the full race suite with 33 package passes and
  three packages without test files. Infrastructure verification reported 69
  passes and one expected root/POSIX-only skip; static policy, billing,
  deterministic supply-chain, and release-artifact checks also passed.
- The `macos-26` iOS [run `30183058643`](https://github.com/GhostlyGawd/codex-mobile-cli/actions/runs/30183058643)
  ([job `89742869559`](https://github.com/GhostlyGawd/codex-mobile-cli/actions/runs/30183058643/job/89742869559))
  passed project generation and compilation with Xcode 26.6 and
  checksum-verified XcodeGen 2.45.4, followed by 63 unit tests and five UI tests
  on the iPhone 17 Pro simulator running iOS 26.5. This is unsigned simulator
  evidence only; physical-device behavior, manual accessibility, signing, APNs,
  TestFlight, provider, and credentialed scenarios remain gated.

Those hosted runs predate the current EnvBuilder source derivative, Codex
0.145.0 pin, and related dependency/policy changes. They are evidence only for
the linked revision, not the current tree. The current-tree hosted Linux
EnvBuilder verifier/backend suite and macOS simulator rerun remain pending.

Recorded local evidence on 2026-07-16:

- `go work sync`, `GO111MODULE=off go fmt
  ./services/control-plane/...`, and full `go vet
  ./services/control-plane/...` passed.
- `go test -race -count=1 ./services/control-plane/...` passed for every
  control-plane package. A fresh coverage run passed, and the integrated
  verifier reported 55.8% total statement coverage. The integration-tag suite
  compiled successfully.
- `POSTGRES_TEST_DSN=... go test -race -tags=integration -count=1 -v
  ./services/control-plane/internal/postgres` passed against a live disposable
  PostgreSQL instance, including `TestIntegrationPersistence` and
  `TestIntegrationTerminalTabMutations`.
- On 2026-07-16, `pwsh ./scripts/verify.ps1` passed on the then-current tree in 320.2 seconds with a
  portable GCC toolchain. It included full Go vet/race/coverage, integration-tag
  compilation, deterministic Linux cross-builds, 66 infrastructure tests with
  six expected POSIX-only Windows skips, iOS static policy, supply-chain
  reproducibility, and release-artifact validation.
- Exact workspace-helper verification passed for amd64
  `f6fc430a2200d13ee0ef04dd576875b4f9a7c95a04287cbdec2deec3b495493c` and
  arm64 `c7e4577a465b55721043612f9b6919248806576816388b01898f6c2784dc163e`.
  Infrastructure policy requires the same pins in the EnvBuilder Dockerfile and
  image-build verifier.
- On 2026-07-26, after the current Go security-dependency upgrade, two
  independent `GOOS=linux CGO_ENABLED=0 go build -trimpath -buildvcs=false
  -ldflags="-s -w"` cross-builds reproduced helper profile 2: amd64
  `ba7080f880206d90e05d751245c3635b9bdcbcbbc6152d61c3ec4221fd5bdf14`
  and arm64
  `3042240a601842f35233e383835a3e40aef6b05640b44f723bafefb133fdf9aa`.
  The current `pwsh ./scripts/verify.ps1` run matched those active pins; profile
  1 remains in the trusted verifier only for historical rollback compatibility.
- The recorded 2026-07-16 tree's source-security audit passed with Syft 1.46.0,
  Trivy 0.72.0, Gitleaks 8.30.1, go-licenses 2.0.1, and govulncheck 1.6.0.
  Gitleaks found no leak; Trivy reported zero unsuppressed high/critical
  misconfiguration, secret, or license findings; and govulncheck reported zero
  called/imported-package vulnerabilities plus seven required-module
  vulnerabilities whose affected symbols are not called. `go-licenses` exited
  successfully; unlicensed first-party-package unknown classifications are not
  errors. Detailed reports were ephemeral outside the repository. Built OCI
  image scanning remains `GATED` and `NOT EXECUTED`.
- These local runs did not contact GitHub/ChatGPT, execute a real Linux Coder
  workspace, or compile Swift with Xcode.

Rerun the full commands after any integration, dependency, migration, or
generated-contract change. A prior green run is not evidence for a later tree.

## Evidence map

Unless a row names a later exact revision, its reference to a hosted simulator
pass means the historical baseline above and does not claim current-tree hosted
execution.

| Area | Automated evidence | What remains unproven |
| --- | --- | --- |
| Passkeys and sessions | `internal/passkeys` covers explicit five-minute server ceremony storage capped at 4,096; 256 slots inaccessible to login traffic; one replace-on-retry login per stable device instance; per-instance four-start/one-per-15-second pacing; an unknown-instance lane capped at 512 active with a 32-start/one-per-second bucket; a separate 32-start/four-per-second lane backed by at most 4,096 historical device hashes, including revoked instances; a 4,608-entry rate-state cap; deterministic expiry/refill/pruning; concurrent unknown-flood isolation from the historical-device lane; and store-load backoff/recovery. It also covers bootstrap and authenticated-registration single use, existing-credential exclusion, owner/current-installation binding, replay/device/principal swap rejection, recovery followed by a second credential, metadata listing, idempotent owner-scoped revoke, and concurrent final-credential/add-revoke protection. PostgreSQL integration-tag coverage exercises the atomic recovery proof and serialized add/revoke path. `internal/session` covers issue/authenticate/rotate, refresh replay family revocation, expiry, and device revocation. `internal/application` covers WebAuthn DTO conversion, 1024-byte canonical credential identities, and metadata-only responses. `internal/httpapi` covers public/protected route boundaries and the identical resource-neutral `503 capacity_unavailable` response. | Apple Associated Domains, production RP ID/origin, Secure Enclave/iCloud Keychain behavior, and a real recovery/register-second/login/revoke flow. Distributed network denial and first login from a new installation under hostile unknown-identity traffic remain deployment observations; neither is claimed as externally proven. |
| GitHub | `internal/githubapp` covers App JWT signing, scoped installation tokens, repository enumeration, suspended installations, and the official token-revocation endpoint. `internal/gitops` and `internal/workspacehelper` cover bounded repository-scoped credentials used only as in-process `go-git` HTTPS BasicAuth, exact GitHub URL/direct trusted transport, mutable input/auth cleanup, a control-plane-owned remote operation deadline, and post-helper request scrubbing. No AskPass, credential/token file, environment, argv or token-bearing remote is created. `internal/githubsync` covers signed webhook synchronization and revocation-before-reconnect completion. | Real owner/org installation, private repository clone, branch push, pull request creation, permission changes, webhook delivery, token expiry, and live process/config/workspace inspection against GitHub. The token remains transiently present in trusted helper/control-plane process memory; explicit revocation can fail and an already-authorized request can remain in flight until the recorded safe-after/provider expiry. Arbitrary CLI Git is not service-authenticated. |
| Connection lifecycle | `internal/application`, `internal/httpapi`, `internal/githubworkspace`, `internal/githubsync`, `internal/postgres`, and `internal/workspacehelper` unit tests cover owner-authenticated aggregate GitHub/per-workspace Codex status; bounded/malformed/cross-owner rejection; metadata-only reservation before every installation-token mint; shared-lease participation through detached explicit revocation; independent remote helper deadlines; early-cancellation authority retention; exclusive disconnect/reconnect/suspension ordering; conflict-until-safe-after behavior; stale-sync final-write rejection; and confirmed running-workspace Codex disconnect. The PostgreSQL implementation caps dedicated shared sessions at `min(max(1, MaxConns), 8)` and exclusive sessions at `min(max(1, MaxConns), 2)`. Terminal concurrency tests prove issue/session-revoke/device-revoke/refresh-replay linearization through a reference-counted owner/device gate, immediate durable-principal revalidation before mint, replay-triggered sweep before gate release, bounded gate cleanup, and manager-atomic ticket-consume/subscriber-install versus sweep. Codex disconnect validates every stored Codex tab, then the helper kills only those app-owned sessions, waits for credential leases and removes materialized/key/encrypted auth as the security commit point before control-plane unregister. An injected unregister failure returns/audits partial runtime cleanup with credentials still revoked; conversation sessions/non-Codex processes remain. Audit is counts/identifiers only. The live disposable PostgreSQL run covers the cross-pool advisory-lock drain, metadata-only token lifecycle, disconnect conflict until expiry, final availability writes, and `MaxConns=1` callback regression. | GitHub local disconnect does not uninstall the external App, and real GitHub revocation/authorized-request timing still requires owner-gated provider verification. Codex disconnect does not revoke the upstream ChatGPT account/session and requires a running workspace; reauthentication is a fresh owner-completed device-login flow. Real provider uninstall/reconnect, Linux tmux/process/auth-file inspection, genuine device login/reauth, and live provider/physical-device UX remain owner/platform-gated. |
| Codex credentials | `internal/workspacehelper` covers the pinned fixed-path launcher, ChatGPT-only/file-store config, per-workspace AES-GCM auth sealing, wrong-key/tamper rejection, concurrent leases, checkpoint sealing, sensitive request/environment scrubbing, and no plaintext in persistent workspace state. Workspace/PostgreSQL tests prove creation persists only a non-secret `private_inputs_pending` marker while environment/prompt values encrypt, clears it only after all encrypted values commit, and quarantines crash, partial, or legacy ambiguity as `private_inputs_recreate_required` before provider work. PostgreSQL integration also covers the stable 32-byte per-workspace key as an envelope-encrypted `encrypted_secrets` record. | Genuine Codex 0.145.0 device login/token refresh/TUI/resume, Linux tmpfs and permission semantics, immutable helper-volume behavior through EnvBuilder, signal/crash timing, and same-authority attack observation on the target Linux runtime. |
| Runtime secrets and master key | `internal/postgres`, `internal/application`, `internal/githubworkspace`, `internal/workspacehelper`, and `internal/gitops` cover active explicit-grant loading, per-workspace serialized database mutation followed by authoritative live tmpfs sync, future-process-only audit scope, honest committed-database/runtime-sync partial failure, mandatory sync before terminal launch, transfer/request wiping, tmpfs seal removal, generic fail-closed Git scanning, and exact AAD-family rewrap/rollback. `workspacehelper` also proves shell/direct-Codex/helper-Git ambient-environment allowlists exclude the agent token, database/control-plane, GitHub/APNs, shell-hook, and unknown parent variables while preserving trusted owner configuration/grants. This does not hide the standard agent process token from same-authority hostile code. | A process already running when a grant is revoked retains its launch environment until closed. The root-owned master key is outside PostgreSQL/database-only dumps but is expected in the whole-server provider backup with encrypted state, so provider/full-backup compromise is not cryptographically separated. Target-Linux tmpfs behavior, hostile agent-token observation/scope, process-crash observation, a credentialed real-grant shell/Codex run, execution of the PostgreSQL serve-lock test, a live all-family rotation/checkpoint rollback drill, and the operator's atomic production key-file switch remain unproven. |
| PTY and terminal protocol | `internal/coder` covers fixed tmux construction, prompt non-interpolation, initial-prompt readiness, PTY URL construction, and loopback-only forwarding. `application`/`postgres`/`httpapi` cover terminal ownership and persistent-tab mutations; the live PostgreSQL race run includes `TestIntegrationTerminalTabMutations`. `internal/terminal` covers binary validation; complete retained-window replay after truncated/ahead gaps; one-use tickets; reconnect audience binding/revocation; explicit takeover; targeted reliable per-connection input receipts after successful PTY write; per-device/tab same-key retry dedupe and changed-payload rejection; 2,048-per-device/4,096-per-tab capacity rejection before write; two-device receipt isolation; output backpressure; mandatory exact/hex/base64/base64url/URL/wrapped active-grant redaction across PTY chunks before sequence/replay/subscription; OSC 52 removal; and title sanitization. Native model/static tests cover same-key composer retry until receipt, full renderer/cache reset and earliest-sequence resume on gap, and one-time stale reconnect-token fallback through the authenticated owner session; those tests compile and pass in the hosted unsigned simulator suite. | Receipt/dedupe records live only for the gateway process/replay generation. A crash after PTY write and before receipt leaves an ambiguity that can duplicate a later retry. The pending native delivery key is also memory-only: app termination after confirmation but before encrypted draft clearing can leave a resendable stale draft. Attachment retry reuses the exact staged payload only until expiry. This is not durable exactly-once delivery. Real PTY/tmux survival/termination on Linux, pinned-TUI timing, SwiftTerm rendering, input fidelity, and physical-device behavior remain gated. |
| Files and Git | `internal/files` covers bounded/cancelable pure-Go search plus root confinement, special/sensitive-path denial, create races, and ETag behavior. The production Linux implementation pins the workspace root, traverses parent descriptors with `O_NOFOLLOW`, requires regular files, stages/fsyncs atomic saves, exchanges the target, verifies the exact displaced-content ETag, and rolls back a commit-boundary conflict; Linux tests exercise root/parent/path symlink swaps and concurrent CAS. The portable `os.Root` backend proves confinement and deterministic conflict handling. `internal/gitops` covers status/stage/commit/diff, checkpoint-backed discard, fast-forward-only pull, index-lock contention, path safety, bounded active-grant scanning, and strict Git environments. | Non-Linux platforms lack rename-exchange and therefore cannot guarantee external-writer CAS in the final check-to-rename window. Any error after a possible namespace commit must be reconciled by a fresh read/ETag before retry. Native-versus-terminal contention, target-Linux filesystem/scanner runtime, large repositories/binaries, editor/diff runtime, uploads, and device cache behavior remain live-gated. |
| Workspace capacity/runtime | `internal/admission`, `internal/core`, workspace/lifecycle tests, Coder adapter tests, infrastructure static tests, and API/native contracts bind disk requests to immutable 8–16 GiB with a 12 GiB default. Admission independently requires the 40 GiB host reserve plus one worst-case 16 GiB start (55 GiB rejects, 56 GiB admits), while the ten-running maximum and 16 GiB cap bound workspace volumes to 160 GiB. New starts hold admission continuously from the durable `provider_start_reserved` record through runtime acquisition, switch to `provider_provision_unconfirmed` before the provider call, and block unsafe starts/expansion while a transition may still be live. Coder create, setup, and quota builds become ready only when the exact returned build reaches `running`. Quota reconciliation persists the component-wise conservative high-water before provider expansion, persists the exact target after confirmation, and retries owner convergence on lifecycle scans. Template/runtime policy covers XFS volume options, an EnvBuilder 4 GiB writable-rootfs cap, immutable create-only propagation, memory/swap/CPU, fixed block-device BPS/IOPS on the exact operator-verified data-mount source, and a creation-time Podman `pids_limit = 512` compensating for the pinned provider's missing field. Static tests also cover the immutable per-workspace relay, root-owned RFC1918 control bridge, exact Coder address/port firewall allow, absence of a Safe Mode egress bridge, `api_key_scope=no_user_data` on the standard agent token, and exclusion of privileged Coder API/provisioner credentials from workspaces. | The target Ubuntu spike must still execute and prove volume/rootfs EDQUOT behavior, PID/I/O cgroup enforcement, private user namespaces/networking/socket isolation, ten-session behavior and 11th-workspace admission. It must also prove a template-created Coder agent registers and operates a PTY only through its relay while Safe Mode reaches no other host/control/general-egress destination. Same-authority repository code may observe/use the unavoidable agent token; hostile live inspection must show it grants no privileged Coder API/cross-workspace authority. Possession of the provisioner socket remains root-equivalent host authority. |
| Lifecycle and retention | Lifecycle tests cover activity compare-and-swap, running/idle/suspended transitions, process preservation, retention anchors/protection and fair queue promotion. Idle classification never treats a process `comm`/name as identity: only quiescent managed terminal infrastructure with a trusted executable/ancestry is excluded, ambiguous classification fails busy, and TCP listeners always count. Adversarial tests cover spoofed legacy names and a runnable trusted shell. | Validate the same executable/ancestry and listener behavior against real Linux `/proc` and Coder workspace processes, then exercise timed suspension/deletion on the target host. |
| Local checkpoint recovery | `internal/checkpoint`, `internal/workspacehelper`, `internal/application`, and `internal/httpapi` cover owner scoping, v1 file-only compatibility, identity-bound v2 full restore, strict archive/hash/path/type/mode/cap validation, recorded deletions, mandatory pre-restore checkpoints, private sibling staging, atomic replacement, reverse rollback, incomplete-rollback journal retention, idempotency, metadata preservation, authenticated confirmation-gated routes, and recovery IDs. iOS static verification covers matching typed routes, checkpoint/hash metadata, confirmation dialogs, and the visible restore link; the native target compiles in the hosted unsigned simulator suite. | Target-Linux filesystem race/fsync/permission behavior, terminal contention under real load, physical-device runtime UX, suspended whole-volume/database restore, and provider/server-loss drills. |
| Previews | `internal/preview` covers audience binding, expiry, route revocation, loopback-only targets, and fragment-token exchange that strips credentials before proxying. `internal/application` covers fragment-only access URLs and binding to the private Coder workspace identifier. | Wildcard DNS/TLS, a real Coder tunnel, HTTP and WebSocket development servers, hostile preview content isolation in `WKWebView`, Safari handoff, and stop/revoke behavior under deployment. |
| Approvals and APNs | `internal/githubworkspace` preserves the exact root or `.devcontainer` directory and rejects unsupported isolation requests; `internal/workspace` covers admitted plain start, authenticated initialization, stop-before-review, supported EnvBuilder approval, explicit unsupported plain fallback, denial, queue, failure, and exact retry behavior. `internal/coder` proves only the approval build carries the EnvBuilder mode/receipt, and PostgreSQL persists the detection. `internal/application` creates a fresh structured review after delayed or denied bootstrap. `internal/apns` covers sandbox/production key selection, generic payloads, invalid tokens, unregistered responses, and retry timing. | Live Coder/EnvBuilder execution on the persistent volume, APNs authentication/delivery, entitlements, quiet-hours UX, notification deep links, and approval prompts on a real device remain gated. |

## Credentialed and platform-gated verification

Run these only after the owner supplies the relevant accounts, keys, domain, Mac/device, and target Linux host. Keep secrets in the documented secret files or platform key stores; never paste them into commands, logs, screenshots, issue text, or this report.

1. Deploy the pinned Compose stack on the selected Linux host and record image digests, kernel details, health output, and the exact tested revision. Do not create or resize a billable host without separate owner confirmation.
2. Complete first-owner passkey bootstrap through the production HTTPS origin. Verify the bootstrap token is one-use, add a second credential from **Settings → Passkeys** without a bootstrap token, prove login with it, verify a cross-device/principal ceremony cannot finish, confirm passkey revoke does not silently revoke sessions, and confirm the final credential cannot be deleted. Then verify refresh rotates, replay revokes the family, and device/session revocation removes access.
3. Install the owner-created GitHub App on one private user repository and one organization repository if available. Verify sync, unique task branch/checkout, pull, push, PR creation and suspended-installation denial. Inspect redacted process, environment, remote/config and workspace state to prove the token exists only transiently in the trusted in-process `go-git` operation and no AskPass/credential/token file, argv value, log entry or token-bearing remote was created.
4. From Settings, disconnect that GitHub installation. Prove repository listings disappear and clone/pull/push/token minting fail locally without a new GitHub call, while the external App remains installed. Prove a webhook cannot reconnect it; use the explicit owner-run sync to reconnect, then separately exercise provider-side App uninstall only with owner approval.
5. Start a template-created Safe Mode workspace. Prove its Coder agent registers and a real PTY works through `cm-coder-control`; the workspace is absent from `codex-mobile-control`, cannot reach the configured Coder listener by any other path, and cannot reach another host/control port, workspace, engine socket or general network. Treat its standard `CODER_AGENT_TOKEN` as visible to same-authority repository code and prove `api_key_scope=no_user_data` yields no privileged Coder API/user-data/cross-workspace authority; separately prove the control-plane Coder token and provisioner key/socket are absent. Prove Balanced/Full Access adds only the separate expected egress bridge. Set `CODER_WORKSPACE_CONNECTIVITY_CONFIRMED=true` only after recording these target-Ubuntu results.
6. Start Codex and shell tabs in that real Coder workspace. Disconnect the iOS app and network, reconnect with replay, force a replay gap and verify renderer/cache replacement, reject a stale reconnect token and verify authenticated recovery, and take the writer lease from a second device. For composer input, lose a receipt without killing the gateway and prove a same-key retry does not duplicate bytes. Separately crash the gateway after an injected PTY write and record the documented ambiguous-delivery limitation. Verify tmux remains authoritative and record latency without terminal content.
7. With a separate shell process running and Codex conversation history present, confirm the per-workspace Codex disconnect. Prove the helper first stops only app-owned Codex tmux sessions and removes tmpfs material/key plus encrypted auth, then the control plane unregisters runtimes; non-Codex processes/history remain. Inject a runtime-unregister failure and prove the API reports partial cleanup without restoring credentials. Verify status becomes disconnected, then complete a fresh `codex login --device-auth` and resume the retained history. Do not claim this revoked the upstream ChatGPT account/session.
8. Grant and revoke a test secret in a running workspace. Verify future shells/Codex processes see the authoritative set, an existing process retains its launch-time value until closed, a failed live sync is returned/audited as a committed-database partial failure, and exact/encoded/split forms cannot enter terminal replay or the encrypted cache. Do not record the value in evidence.
9. Exercise the native file tree, search, ETag conflict, stage/unstage, diff, commit, pull, and push while a terminal process swaps parent paths and a terminal Git process attempts a conflicting operation. Confirm Linux confinement/CAS, contention reporting, and that an injected post-commit error triggers a fresh read rather than a blind save retry.
10. On the exact production storage/runtime, prove `/srv/codex-mobile` is encrypted XFS with `pquota`/`prjquota`, create the disposable quota volume, verify a small write succeeds and a write past its bound fails specifically for quota exhaustion, and inspect user namespaces, cgroups, networks, and runtime-socket absence from Coder/workspaces. Treat provisioner socket access as root-equivalent evidence.
11. Start one HTTP and one WebSocket development server. Verify the detected route uses wildcard TLS, an unauthenticated request fails, the fragment credential is exchanged and removed before proxying, cookies/origins are isolated, the target remains loopback inside the workspace, and revoke/stop invalidates access.
12. Send sandbox and production APNs notifications only with the corresponding owner keys and provisioned app. Verify generic detail by default, quiet-hours behavior, unregistered-token disablement, retry handling, and safe deep links on a real device.
13. On the owner-controlled Mac, run the SwiftTerm VT/xterm corpus and native editor/diff flows, including Unicode/emoji width, alternate screen, bracketed paste, resize, hardware control keys, OSC 52 denial, malicious titles/links, VoiceOver, and Dynamic Type.

For every live run, attach a redacted evidence record with date, revision, environment, command or manual procedure, expected result, actual result, and remaining limitations. Only then change the corresponding row in [ACCEPTANCE.md](ACCEPTANCE.md) from `GATED` to `PASS`.
