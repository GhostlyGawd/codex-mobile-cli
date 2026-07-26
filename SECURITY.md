# Security model

## Reporting a vulnerability

Use GitHub's **Security → Report a vulnerability** private-reporting flow for
this repository. Do not include credentials, private repository content,
terminal output, production configuration, or personal data in a public issue.
If private reporting is temporarily unavailable, open a metadata-only issue
asking the owner to enable a private channel; do not disclose the vulnerability
there.

## Scope and assumptions

This is a single-owner MVP for repositories the owner explicitly trusts enough to execute. Workspaces share one Linux kernel; OCI isolation reduces risk but is not VM-grade isolation. Code with the same runtime authority as Codex can potentially read materialized Codex credentials or any secret deliberately granted to that workspace. A fully compromised running host can access in-use keys. These are residual risks, not hidden claims.

## Trust boundaries

1. iOS device and Keychain ↔ public TLS edge.
2. Public edge ↔ control plane.
3. Control plane ↔ PostgreSQL, Coder, GitHub, APNs, and container engine.
4. Coder/agent ↔ each workspace container.
5. Workspace root ↔ untrusted repository/setup/devcontainer/content.
6. Terminal/preview bytes ↔ native rendering surfaces.
7. VPS storage and its whole-server backup (including the host master key) ↔
   owner-held offline availability/recovery copies.
8. Public workflow source ↔ standard ephemeral GitHub-hosted Linux/macOS
   runners. The owner's Windows PC is a local development host, not a
   repository runner.

## Threat register

| Threat | Preventive controls | Detection | Recovery | Residual risk | Verification |
| --- | --- | --- | --- | --- | --- |
| Malicious repository, setup, devcontainer, dependency, or prompt injection | Repository is cloned by the fixed helper in plain mode before the container stops for structured trust; the exact standard config directory is persisted; a shared reconciler atomically creates one non-expiring pending review/activity across direct and queued transitions, and resolves it only after workspace acceptance/denial is durable; unsupported privilege/mount/root/nested-Docker requests can only use an explicit plain fallback; project `.codex` remains untrusted; egress policy; no host mounts | Setup/audit events, policy denials, resource alerts | Stop workspace, revoke grants/tokens, rebuild | Approved repository code can abuse granted workspace access | Plain-bootstrap ordering, exact-directory persistence, queued/retry/repair/decision-ordering, fallback, and egress tests |
| Public pull request attempts workflow privilege or runner abuse | Public CI uses only standard ephemeral GitHub-hosted runners, read-only permissions, disabled checkout credential persistence, immutable Action SHAs, no secrets/artifacts/caches/environments, bounded timeouts, and approval for every external contributor; unsafe triggers, reusable runner delegation, self-hosted/larger labels, and write permissions are rejected by policy | GitHub workflow/check identity, branch rules, fork-approval setting, and release-policy tests | Disable `PUBLIC_CI_ENABLED`, cancel runs, rotate any unexpectedly exposed authority, and restore the reviewed workflow/settings contract before re-enabling | Pull-request code still executes on GitHub infrastructure and can consume public-runner time or emit hostile test output; platform compromise remains outside repository controls | Workflow-policy negative tests plus historical baseline standard Linux and Xcode simulator runs; current-tree hosted reruns remain pending |
| Vulnerable, secret-bearing, license-incompatible, or substituted release image | The locked deploy captures the three locally built image IDs, scans those IDs through explicit engines with checksum-pinned Syft/Trivy and one frozen database snapshot, rejects tag drift, and binds the root-only receipt/report tree into manifest schema 2 before promotion. The workflow is configured to reconstruct EnvBuilder from an exact bounded archive and manifest-bound patch and test/cross-build it in public Linux CI; after the workspace image is verified, the release build is configured to copy its complete helper seed from that immutable image ID. Profile-3/schema-2 dispositions bind all 14 finding identity fields and expire; forbidden licenses require individual exact records, while complete non-forbidden license inventories use expiring per-image duplicate-sensitive canonical multiset baselines. Broad ignores and pre-generated evidence are rejected | Metadata-only tool/database/policy/report hashes, source-lock/archive/patch hashes, canonical helper-seed digest, image IDs, finding/disposition/baseline counts, and manifest verification | Leave the candidate staged and unpromoted; update/remove the dependency or review one narrowly scoped expiring disposition/baseline; rebuild and rescan as a new release | Scanner/database defects and a malicious root remain host trust; an accepted disposition or baseline retains its documented upstream/license-review risk until expiry/update | Configured source-lock/archive/patch/architecture/reproducibility tests and audit parser, bound/timeout/tamper/extra/symlink/ID-drift/disposition/baseline/ordering tests; current-tree hosted source rebuild and exact Linux Docker/Podman build-and-scan execution remain pending |
| Lost or partially persisted creation-time private input | The workspace row contains only `private_inputs_pending`, never the environment values or initial prompt; the marker clears only after every private input is encrypted and committed. Preparation error, crash recovery, and legacy ambiguous state quarantine the row as `private_inputs_recreate_required` before any provider work | Non-secret pending/failure state; no private values in workspace reads or logs | Delete and recreate the workspace, re-entering the intended values | The owner must re-enter values because recovery deliberately cannot infer whether a partial encrypted write committed | Store, partial-write, crash-recovery, lifecycle, deletion-tombstone, and no-plaintext tests |
| Container escape / host socket exposure | Drop capabilities; no privilege; `no-new-privileges`; seccomp/LSM; user namespaces; no engine socket/devices in Coder or workspaces. A dedicated root-owned Podman API is mode `0660` for only `root:coder-provisioner` | Runtime/config policy checks, auditd, socket membership checks | Stop runtime/workspaces, rotate provisioner credentials, rebuild host | Shared-kernel zero-days; compromise of the provisioner or its private socket is root-equivalent | Host-boundary integration test on target kernel |
| Cross-workspace leakage | Separate volumes, per-workspace internal and optional egress bridges, Unix users, branches/worktrees, credentials and quotas; no shared writable cache. Each workspace reaches Coder only through its own immutable TCP relay; only that relay joins the fixed control uplink, whose host firewall permits one Coder address/port. Privileged Coder API/provisioner credentials never enter workspaces/relays | Canary probes, network-policy validation and audit | Stop affected sessions/relays, rotate scoped Coder credentials and secrets, restore checkpoint | Kernel/provider defect; the unavoidable standard `CODER_AGENT_TOKEN` (`api_key_scope=no_user_data`) lives in the workspace agent process, and same-authority repository code may observe/use it through the relay. It must not confer privileged Coder API or cross-workspace authority | Two-workspace isolation suite plus target-host hostile token-scope/relay/route probes |
| Stolen phone/session/replay/deep link | Passkeys; Keychain; short access TTL; rotating refresh; family replay revocation; universal-link validation; no lock-screen approval. Terminal ticket and preview-grant issuance bind to the exact device. Ticket issuance revalidates durable session state inside the bounded per-owner/device revocation gate; ticket redemption/subscriber installation is atomic with the sweep; device/family revocation cancels terminal and preview access and drains admitted terminal mutations and WebSocket writes before return | Replay/device/audit events | Revoke device and sessions via SSH admin CLI | Unlocked compromised phone session; ordinary non-authority-creating HTTP work retains normal in-flight semantics | Auth rotation/replay/deep-link tests plus adversarial issue/redeem/write/preview/revoke ordering tests |
| GitHub token theft/overreach | GitHub App minimum permissions; backend-only short-lived repository-scoped installation tokens; verified installation-owner binding. Trusted clone/pull/push/reference operations use in-process `go-git` HTTPS BasicAuth with an exact GitHub host, direct transport and root-owned CA bundle; no AskPass/credential/token file, environment variable, argv value or token URL is created. Mint plus complete use holds an owner/installation shared PostgreSQL advisory lease. Before mint, the broker reserves metadata-only authority using a random use ID and unrelated random nonce; no token or token-derived value is persisted. Every use has a bounded callback and detached, bounded cleanup calls GitHub's official `DELETE /installation/token`. Remote helpers also enforce a control-plane-owned inner deadline independent of the local SSH process. Ordinary sync and signed provider-unsuspend hold one exclusive lease from fresh provider metadata fetch through active check, token/list use and final repository writes; ordinary refresh preserves suspension/disconnect, and unsuspend clears only provider suspension after a fresh active response. Disconnect, reconnect and provider suspension are also exclusively ordered. Disconnect and suspension durably disable local authority and hide repositories, but return conflict while an ambiguous unrevoked use remains before its remote safe-after/provider expiry; reconnect cannot complete during that interval. Dedicated shared sessions are capped at `min(max(1, MaxConns), 8)` and exclusive sessions at `min(max(1, MaxConns), 2)` | Metadata-only token-use/disconnect state, org-denial errors | Locally disconnect; for provider compromise separately uninstall/revoke installation/key at GitHub and rotate the App key | The token exists transiently in trusted control-plane/helper process memory. Revocation transport can fail, and an already-authorized remote request can continue until its recorded safe-after deadline; local disconnect does not uninstall the external App | No-persist clone/push, explicit-revocation and early-cancellation tests, deterministic concurrency/trusted-transport tests, live PostgreSQL cross-pool/final-write/token-expiry/`MaxConns=1` runs, and owner-gated live GitHub/process/config inspection |
| Codex credential theft | Dedicated `CODEX_HOME`; forced ChatGPT login; per-workspace DB-envelope key; trusted wrapper AES-GCM ciphertext; auth/runtime environment plaintext only on tmpfs; file API denylist | Auth-envelope tamper failure, access/reauth events, secret scan | Logout/revoke ChatGPT session, delete sealed state, and rebuild workspace | Same-authority code may read in-use tmpfs material or invoke the mounted real binary directly | Encryption/tamper/concurrency/no-persistent-plaintext tests plus live Linux spike |
| Terminal escape, clipboard, hyperlink, output flood, secret echo | Treat bytes as untrusted; block OSC 52; confirm links; sanitize title; cap frames/chunks/input, tabs, replay bytes/frames, tickets, reconnects, subscribers and every queue at global/owner/workspace/tab/device scopes; backpressure; mandatory stateful exact/encoded active-grant redaction before output enters the sequence ring, subscribers, or cache | Dropped-byte/gap, capacity, redaction-failure and rate metrics | Disconnect renderer, revoke grants, close affected tabs, reconnect from a safe replay point | Renderer/parser defects; output that is sensitive but is not a known active-grant representation cannot be recognized perfectly | Capacity/recovery, VT corpus, fuzz, OSC 52, flood and split-secret redaction tests |
| Path traversal, symlink race, TOCTOU, archives, attachments | On production Linux, a pinned workspace-root descriptor, fd-relative `O_NOFOLLOW` traversal, regular-file checks, atomic create, and rename-exchange ETag save that verifies the exact displaced content. Checkpoints add identity/version/hash and duplicate/case/hierarchy validation, size/type/mode caps, private staging, and rollback. Attachments are owner/tab scoped, signature-checked and bounded, discard original names, and enter randomized mode-`0600` files in a mode-`0700` dedicated `nosuid,nodev,noexec` tmpfs outside every repository with a 30-minute TTL | Rejected-operation and counts/bytes-only attachment audit, checkpoint hash status, periodic expiry cleanup | After any save error that may follow commit, perform a fresh read/ETag reconciliation before retry; expire staged files, clear tmpfs on stop, retain incomplete-rollback journals, restore a verified checkpoint | Portable non-Linux development uses `os.Root` and cannot guarantee external-writer CAS in the final check-to-rename window; same-authority code can read staged attachments; local checkpoints share the host failure domain | Linux parent/root symlink-swap and exact commit-race tests; portable confinement/conflict tests; checkpoint and attachment attack suites |
| Preview auth bypass, DNS rebinding, SSRF, hostile JS | Separate origins; audience- and device-bound short tokens; host-only cookies; port ownership registry; isolated WKWebView; no JS bridge; destination allowlist. Device/session revocation cancels its grants and active HTTP/WS contexts; workspace suspension/deletion revokes routes and cancels Coder tunnels while holding the workspace mutation gate | Route/token/audience denials | Revoke route/token/device, suspend workspace, stop process | Browser/WebKit vulnerabilities | HTTP/WS auth, origin, rebinding, device/workspace revocation and suspension-boundary tests |
| WebSocket hijack/replay/truncation/multiple writers | TLS; bearer auth; origin rejection; monotonic output sequence/ack; bounded rotating reconnect token with authenticated stale-token fallback; one-writer lease; per-device/tab idempotent input keys and targeted reliable receipts only after PTY write | Sequence gaps, duplicate/rejected input, receipt and lease audits | Reset renderer/cache on a gap, revoke socket/token, take lease explicitly | Compromised authenticated client can view authorized output. Gateway dedupe and the app's pending delivery key are in memory: a gateway crash after PTY write or an app termination after receipt but before draft clearing can leave ambiguous/resendable input. Receipt capacity fails closed before write | Protocol/replay/gap/two-device/receipt/backpressure/lease tests |
| APNs privacy leakage | Generic default payload; no repository/path/prompt/command/output; authenticated in-app review; no approval action | Payload snapshot tests and delivery status | Disable/revoke device token | Apple sees delivery metadata | Payload privacy tests |
| Backups/logs/diagnostics/admin credential compromise | Encrypted secret values; root-owned master-key file outside PostgreSQL and database-only dumps; metadata-only logs; redacted deliberate diagnostics; key-only SSH. The included whole-server backup intentionally captures both ciphertext and the host key for consistent recovery; an offline matching key copy improves availability | Integrity/restore checks, auditd, secret scans | Rotate keys/tokens, rebuild, restore; after host/provider/full-backup compromise assume encrypted values were readable and rotate or re-enter them | There is no cryptographic separation from provider administrators or compromise of the running host/full-server backup; the offline copy is an availability copy, not a control that removes the backed-up host key | Restore, diagnostics, secret-scan and compromise-response drills |
| Resource exhaustion across ten sessions | Fixed admission pool; continuous admission-to-provider-runtime reservation; durable no-call/ambiguous provider phases; one provider-mutation order; exact-running start/quota barriers; equal CPU/memory controls with conservative component-wise quota high-water and scan-driven reconciliation; immutable 8–16 GiB XFS project quotas; read-only plain rootfs; 4 GiB EnvBuilder overlay quota; 512-process cgroup limit; fixed BPS/IOPS on the exact verified mount device; bounded terminal buffers; queues; 40 GiB host reserve and 56 GiB free-space start threshold | Durable lifecycle/capacity phases, pressure, quota, EDQUOT and disk-reserve metrics | Resolve provider ambiguity or confirm stop; lifecycle retries fair-share convergence; suspend/stop offending workspace | Ambiguity or provider failure can temporarily block starts and underallocate peers; heavy fair-share workloads slow all sessions; target filesystem/driver/cgroup enforcement is not proven until the live spike | Admission/runtime ordering, response-loss, high-water/reconciliation, and portable config tests plus actual-template-container PID/I/O/rootfs and target ten-session/load/quota tests |
| Stale authority across workspace stop/delete | Persist `suspending`/`deleting` before cleanup; serialize provider lifecycle per owner/workspace; drain terminal tickets/reconnects/subscribers/mutations/writes and preview grants/tunnels under the application workspace gate; hold it through confirmed provider stop/absence and final persistence. Exact owner/state deletion cascades operational children while audit links become NULL | Lifecycle state, bounded cleanup/provider errors and metadata-only audits | Automatic retry of durable tombstone; operator inspects provider before intervention | Process crash can delay cleanup until restart/scan; target Coder/tmux/tunnel behavior remains deployment-gated | Deterministic suspend/delete/resume races, failure retries, fresh-PTY checks, Coder confirmation tests and live PostgreSQL cascade/audit/recreation integration |
| Passkey origin/RP confusion, bootstrap theft, credential lockout, or ceremony exhaustion | Stable RP/origin allowlist; challenge binding; one-use short bootstrap token; automatic bootstrap disable; authenticated enrollment bound to owner/current installation; metadata-only owner-scoped management; serialized final-credential protection. Five-minute ceremony state is capped at 4,096 with 256 slots reserved from login traffic. Each stable device instance has one replace-on-retry login ceremony, a four-start burst and one refill per 15 seconds. Unknown instances share a 32-start/one-per-second lane and at most 512 active ceremonies; up to 4,096 silently recognized historical instance hashes, including revoked devices eligible to reauthenticate, use a separate 32-start/four-per-second lane. Admission state is capped at 4,608 entries and all denials use the same generic response | Generic capacity responses, HTTP metrics, and failed ceremony/add-revoke audit events | Automatic expiry/refill; SSH-only recovery reset; immediate enrollment of two passkeys; credential revoke | A sufficiently distributed unknown-identity or network flood can delay first login from a new installation; network-layer denial remains outside the in-process limiter. RP domain loss may require a new passkey | Deterministic replacement/refill/pruning, concurrent unknown-lane exhaustion, known-lane survival, owner-reserve, state-cap recovery, origin/replay/bootstrap, cross-owner revoke, and final-delete tests |
| Vault/key misuse | AES-256-GCM envelope encryption; random nonces/data keys; master key outside PostgreSQL and database-only dumps; active explicit grants; serialized authoritative grant/revoke sync to tmpfs; mandatory sync before process launch; encoded-value Git/output redaction; offline all-row verified rewrap under an exclusive serve lock | Grant/decrypt/runtime-sync/rotation counts-only audit metadata and generic scan denials | Revoke grants, close processes that inherited them, seal/suspend workspace, rotate value/data/master keys using matching checkpoint | Runtime secret is readable by granted code; an already-running process retains its launch environment after revoke; rewrap does not undo prior compromise; whole-host backups include the wrapping key | Live-sync/partial-failure, tamper, wrong-AAD, raw/encoded scan, rollback, unknown-row and rotation tests |

## Security invariants

- Production startup fails if TLS/RP/domain, master key, database, provider credentials, or secure-cookie configuration is incomplete.
- Public workflow code executes only on standard ephemeral GitHub-hosted
  runners. The repository has no self-hosted runner route; pull-request jobs
  receive no secret or write authority, and external contributors require
  approval before a workflow starts.
- Passkey state is five-minute and memory-bounded: login traffic cannot consume the 256 owner-enrollment reserve, one stable device instance cannot accumulate ceremonies, unknown identities cannot consume the historical-device lane, and every admission failure is the same resource-neutral `503 capacity_unavailable` problem.
- External-facing request bodies, terminal buffers, search output, diffs, uploads, and logs are bounded.
- Workspace subprocesses use fixed executable paths/argv and explicit inherited-environment allowlists. The standard per-workspace `CODER_AGENT_TOKEN`, database/control-plane credentials, GitHub/APNs material, `BASH_ENV`/`ENV`, and unknown ambient variables do not enter helper-launched shell, Codex, or helper Git environments. The Coder agent itself necessarily receives its `api_key_scope=no_user_data` token; same-authority repository code may still observe its process environment, so this allowlist is not claimed to hide that token from a hostile workspace. Privileged Coder control-plane/provisioner tokens never enter the workspace.
- Authenticated Git bootstrap and native remote operations receive a bounded
  repository-scoped installation token only as in-process `go-git` auth at the
  trusted helper/control-plane boundary. The service does not authenticate an
  arbitrary repository-controlled Git subprocess and creates no AskPass,
  credential or token file. Each token use is reserved as non-secret durable
  metadata before mint, explicitly revoked at GitHub after use, and retained as
  outstanding authority through its remote safe-after/provider expiry whenever
  local cancellation or revocation transport makes completion ambiguous.
- Service credentials and active-grant exact/encoded forms never enter repository config, Git remotes, audit payloads, notification text, offline cache, diagnostics by default, or native file APIs. Native Git mutation fails closed when safely matched active-grant values are detected. Unrelated sensitive terminal output remains the explicit recognition limitation above.
- Codex `auth.json` and configured environment plaintext never persist in a workspace volume: only authenticated auth ciphertext persists, while the per-workspace key and materialized runtime files live on container tmpfs.
- Connection inspection is owner-scoped and metadata-only. GitHub disconnect is
  a local authority revocation, not an external App uninstall. Its exclusive
  advisory lease drains complete prior token uses and commits before successful
  return. A disconnect or suspension commits the local disable but returns a
  conflict while any ambiguous token-use record is still unexpired; a retry can
  succeed only after confirmed cleanup or the recorded safe-after/provider
  expiry. Reconnect completion and provider suspension participate in the same
  ordering.
  Ordinary sync holds one exclusive lease from fresh provider read through final
  repository writes and cannot clear either revocation. A signed unsuspend uses
  the same one-lease flow and may clear provider suspension only after the fresh
  response is active; it never clears an owner disconnect.
  Confirmed
  per-workspace Codex disconnect validates every recorded Codex tab, then the
  helper stops only those app-owned tmux sessions, waits for their auth leases
  and deletes tmpfs/encrypted workspace auth as the security commit point.
  Control-plane runtime unregister/cleanup follows; a cleanup failure is
  returned/audited with credentials already revoked. Non-Codex processes and
  conversation session history remain.
- Terminal ticket issue revalidates the durable principal inside the same
  owner/device gate used for session revoke, device revoke and refresh
  rotation/replay. Replay-triggered revocation sweeps terminal access before
  releasing the gate; ticket consume plus subscriber install is atomic with the
  gateway sweep. Preview grants bind to that device and are swept too. Active
  subscribers have separate mutation and delivery gates; revoke, unregister and
  tab close wait for previously admitted PTY work and WebSocket writes, and no
  later write can begin.
- Suspension persists `suspending` before taking the application workspace gate,
  drains terminal and preview authority, and retains the gate through confirmed
  provider stop plus the final `suspended` write. Manual, idle and maintenance
  paths share it; failures remain suspending for idempotent retry and resume
  opens a fresh PTY.
- Deletion persists `deleting`, confirms provider absence, drains process-local
  authority, and only then removes the exact owner/state row and reviewed child
  records. Failures retain the tombstone; audit target identity survives the
  nullable workspace link.
- Repository setup approval is a durable stopped-workspace boundary, not an
  expiring notification side effect. Application and lifecycle transitions
  reconcile one pending event/activity transactionally; approval or denial is
  persisted on the workspace before the event is resolved, and a partial
  finalization is retryable without executing setup twice.
- Creation-time environment values and the optional initial prompt never persist
  in the workspace row. Its private-input marker clears only after all encrypted
  destinations commit. An interrupted or partial result is quarantined as
  `private_inputs_recreate_required`; neither manual retry nor lifecycle repair
  starts a provider from an uncertain subset, while a deleting tombstone remains
  authoritative until cleanup finishes.
- Workspace start admission remains held from the capacity decision and durable
  reservation through acquisition of the provider-runtime gate. Only
  `provider_start_reserved` proves no provider call; provision/start ambiguity
  remains capacity-counted until deterministic lookup and confirmed cleanup.
  Coder start and quota success requires the exact build to reach `running`.
  Persisted quota is a component-wise upper bound across provider/store crash
  windows, and lifecycle scans retry per-owner convergence. See
  [ADR 0020](docs/adr/0020-durable-provider-capacity-reconciliation.md).
- Granted values are loaded only from active explicit workspace grants, cross the trusted configure boundary as bounded wipeable buffers, live only in the helper's private tmpfs runtime, and are removed at the checkpoint/suspend seal boundary. Grant/revoke serializes per workspace and updates authoritative tmpfs state for future processes; running processes must be closed to lose inherited values.
- A terminal cannot start without a redactor built from the current authoritative grant set. Exact, hex, base64/base64url, URL-escaped, and wrapped representations are removed across output chunk boundaries before replay or cache; values outside safe supported bounds fail terminal start.
- Production file operations stay relative to a pinned Linux root descriptor and reject symlink/special-file traversal. A failed save after a possible namespace commit is never blindly retried: the client must read and reconcile the current ETag first.
- Production requires operator-provisioned encrypted storage and an explicit encryption acknowledgement. The workspace engine itself starts only when `/srv/codex-mobile` is the exact XFS mount with `pquota` or `prjquota`; its private socket is root-equivalent and is never mounted into Coder or a workspace.
- A workspace never joins the shared `codex-mobile-control` network. Its Coder
  agent uses a fixed per-workspace relay on the private workspace bridge; the
  relay alone joins that uplink and the host firewall permits only the exact
  private Coder address and port. This route is not accepted until a target-host
  Safe Mode probe proves agent registration/PTY control while every other host
  and general-egress path remains denied.
- Workspace I/O limits bind only to the explicit block-device source that `findmnt` reports for `/srv/codex-mobile`; host hardening and every production entry point reject a mismatch rather than guessing. The dedicated engine applies a fixed creation-time 512-process cgroup default because the pinned Terraform provider cannot express `PidsLimit`; acceptance inspects the template-created container's kernel cgroup files.
- Production Compose secret sources are unsymlinked, single-link, root-owned mode-`0444` files beneath a root-owned mode-`0700` directory whose ancestors are not group/other-writable. The direct read bit is available only after Docker mounts a declared file into its intended non-root service; host users cannot traverse the source directory. Preflight uses `lstat`, `O_NOFOLLOW`, and open-time inode/metadata checks.
- Infrastructure checkpoints preserve a 40 GiB host reserve plus their maximum output, serialize writers, independently check producer/compressor status, cap compressed bytes, validate gzip/tar integrity, sync, and atomically publish. Staging artifacts are never restore candidates and are removed under the writer lock after an interrupted run.
- Composer drafts and sent-message history are target-scoped AES-GCM ciphertext protected by a this-device-only Keychain key. Selected attachment bytes stay in bounded volatile native memory until explicit Send, are never added to the offline cache, and are scrubbed on removal, dismissal, or successful send.
- Staged attachments never enter a repository, database, backup, audit body, notification, or persistent workspace volume. Only the trusted fixed attachment helper may create their randomized files; cleanup is time-bounded and idempotent.
- Master-key rotation cannot overlap a serving process, never skips an unknown/legacy AAD row, and commits every verified replacement envelope plus counts-only audit metadata in one transaction. Key-file switching remains an explicit operator action.
- The root-owned master-key file is separate from PostgreSQL and database-only
  exports, but the contracted provider backup is a whole-server availability
  copy and is expected to contain both encrypted rows and that file. It offers
  recovery consistency, not cryptographic separation from provider or
  full-backup compromise; the owner-held offline copy protects against key loss
  or corruption only.
- Selected tracked-path discard requires explicit confirmation, a completed verified checkpoint, and `git restore` from `HEAD`; native Git never force-resets, rewrites history, or rebases. Full local restore is v2 identity-bound and applies only its recorded delta, while v1 remains file-restore-only.
- Production deployment and backup restore are deliberate operator commands; no automatic billable mutations exist.

## Incident priorities

1. Contain: revoke public sessions/routes, stop workspaces, restrict edge access.
2. Preserve metadata-only audit and provider logs without copying terminal/file content.
3. Rotate GitHub App, Codex, APNs, session, database, and vault material appropriate to scope.
4. Rebuild from pinned infrastructure and restore the last verified backup/checkpoint.
5. Re-enroll passkeys if the RP or signing trust is affected.
6. Document impact, recovery point, and residual risk honestly.

Detailed procedures live under `docs/runbooks/` and must be exercised before production use.
