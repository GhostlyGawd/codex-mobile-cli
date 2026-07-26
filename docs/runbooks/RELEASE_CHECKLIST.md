# Release checklist

This checklist's active profile is the owner-PC private beta selected in
[ADR 0025](../adr/0025-owner-pc-private-beta-hosting.md). Items explicitly
labelled **deferred future VPS** are retained design evidence, not private-beta
launch blockers. A release decision is **NO-GO** unless every applicable PASS
has executed evidence and every remaining GATED item is explicitly accepted by
the owner as an external step—not silently converted into a pass.

- [ ] Reviewed commit is immutable, clean, pushed only after owner authorization, and release directory/image tag is `sha-<commit>`.
- [ ] `scripts/verify.sh` passes on Linux/macOS and tracked supply-chain reports reproduce.
- [ ] The strict EnvBuilder source lock reconstructs exactly
      `1.3.0-codex-mobile.1`; all eight patch paths, unit/race and
      integration-compile checks pass; two clean static builds per amd64/arm64
      are byte-identical; the runtime Coder SDK graph is absent; and the source
      SBOM preserves the Apache-2.0 ancestor versus first-party no-license patch
      boundary.
- [ ] `scripts/security-audit.sh` passes with the exact pinned tools; govulncheck is clean/dispositioned; every built OCI image has a manifest-bound Syft/Trivy vulnerability/secret/license report for its exact ID, with zero undispositioned findings, no expired/unused exact disposition, and an exercised unexpired duplicate-sensitive baseline for every non-forbidden license inventory.
- [ ] Xcode 26.6 generated project, simulator/unit/UI tests and physical iPhone/iPad acceptance all pass with recorded evidence.
- [ ] Threat model, residual risks, cost model, capability matrix, ADRs and criterion-level acceptance report match the release.
- [ ] The owner-PC private-beta profile runs on the D-backed Ubuntu WSL host
      through a reviewed stable HTTPS ingress. PostgreSQL, Coder, Podman,
      runtime sockets, SSH, and workspace ports remain non-public. Live
      authorization, isolation, restart, and accepted local capacity checks
      pass without claiming VPS-only XFS, AppArmor, provider-backup, or
      ten-session evidence.
- [ ] **Deferred future VPS:** if the owner explicitly reopens always-on
      hosting, provider checkout, included daily backup, restore, DNS/wildcard
      TLS, XFS project quotas, host hardening, and ten-session/11th-refusal
      drills pass on the selected target before that migration.
- [ ] Schema-2 immutable release manifest verifies the root-only audit receipt/report tree, exact local image IDs, helper/template/Podman/systemd hashes and installed host artifacts. The EnvBuilder image has the exact scratch runtime contract, its complete canonical helper seed matches the immutable workspace-base ID, a Coder activation receipt exists, and full health plus the bounded disposable smoke gate pass without rebuilding or rescanning.
- [ ] Active-host database, file, workspace, and service restart/recovery checks
      pass, with PC/WSL storage loss and the absence of an assumed provider
      backup shown honestly.
- [ ] **Deferred future VPS:** provider restore passes and the approximately
      24-hour whole-server recovery gap is shown honestly. Evidence acknowledges
      that a provider whole-server backup contains encrypted state and the host
      master key together: it is an availability copy, not cryptographic
      separation.
- [ ] GitHub App and APNs least-privilege credentialed tests pass without token/content leakage. Local GitHub disconnect blocks minting/hides repositories without claiming external uninstall; explicit sync reconnect and provider-side uninstall are tested separately.
- [ ] Genuine Codex ChatGPT device auth, TUI/resume, approvals/notifications and no API-key fallback pass live. Per-workspace disconnect stops only app-owned Codex tmux, removes local runtime/encrypted auth, preserves other processes/history, and a fresh device login reconnects it without claiming upstream account revocation.
- [ ] Passkey total-loss recovery and master-key rotation have tested procedures, or the owner explicitly blocks release until they do.
- [ ] Accessibility, offline encryption/staleness, performance measurements and key-flow screenshots/recordings are complete.
- [ ] Repository visibility is public, `PUBLIC_CI_ENABLED` is true, and every CI
      job uses a standard hosted runner; no larger or persistent self-hosted
      runner is configured.
- [ ] Owner separately approves owner-PC beta activation, public HTTPS ingress,
      Apple archive signing, and private TestFlight upload.

Known limitations shown to the owner/testers: Linux workspaces cannot run
Xcode/macOS tools; containers share one kernel; granted runtime secrets can be
read by repository code and already-running processes retain a revoked value
until closed; terminal input receipts do not provide durable exactly-once
delivery across a gateway crash, and an app termination in the receipt-to-draft
clear window can leave a stale resendable draft; portable non-Linux file saves do not provide
the production Linux external-writer CAS guarantee; the provisioner's private
Podman socket is root-equivalent authority; workspaces within the measured
active local cap share finite fixed resources, while the historical
ten-session target is deferred; active
processes do not survive a Windows, WSL, or service restart; local checkpoints
do not survive loss of the PC/WSL storage; the beta is offline whenever the PC,
WSL, services, network, or ingress is offline; there is no HA or automatic
capacity purchase; and Safe Mode's Coder relay is an application-level TCP path
whose rootful-Podman/firewall behavior remains unaccepted until the live
target-host gate passes. If the owner later reopens VPS hosting, its provider
recovery point and whole-server-backup exposure must be assessed separately.
