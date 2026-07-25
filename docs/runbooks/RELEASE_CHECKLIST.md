# Release checklist

A release decision is **NO-GO** unless every PASS has executed evidence and
every remaining GATED item is explicitly accepted by the owner as an external
step—not silently converted into a pass.

- [ ] Reviewed commit is immutable, clean, pushed only after owner authorization, and release directory/image tag is `sha-<commit>`.
- [ ] `scripts/verify.sh` passes on Linux/macOS and tracked supply-chain reports reproduce.
- [ ] `scripts/security-audit.sh` passes; govulncheck is clean/dispositioned; every built OCI image has a clean/dispositioned Trivy vulnerability/license scan.
- [ ] Xcode 26.6 generated project, simulator/unit/UI tests and physical iPhone/iPad acceptance all pass with recorded evidence.
- [ ] Threat model, residual risks, cost model, capability matrix, ADRs and criterion-level acceptance report match the release.
- [ ] Provider plan/current checkout, included daily backup, restore drill, DNS/wildcard TLS, and host hardening pass on the selected VPS. The exact encrypted `/srv/codex-mobile` XFS `pquota`/`prjquota` mount and private root-owned runtime pass the write-past-quota, user-namespace, cgroup/network, socket-isolation, ten-session, and 11th-start-refusal drills. A template-created Safe Mode workspace proves Coder-agent registration/PTY only through its per-workspace relay, absence from the fixed control uplink, and denial of every other host/control/general-egress route before `CODER_WORKSPACE_CONNECTIVITY_CONFIRMED=true`. Hostile use of the expected `api_key_scope=no_user_data` agent token yields no privileged/user-data/cross-workspace authority, and no control-plane Coder/provisioner credential enters the workspace.
- [ ] Immutable release manifest verifies exact local image IDs, helper/template/Podman/systemd hashes and installed host artifacts; a Coder activation receipt exists; full health and the bounded disposable smoke gate pass without rebuilding.
- [ ] Database/file/workspace/provider restore drills pass and the approximately 24-hour whole-server recovery gap is shown honestly. Evidence acknowledges that the provider whole-server backup contains encrypted state and the host master key together: it is an availability copy, not cryptographic separation.
- [ ] GitHub App and APNs least-privilege credentialed tests pass without token/content leakage. Local GitHub disconnect blocks minting/hides repositories without claiming external uninstall; explicit sync reconnect and provider-side uninstall are tested separately.
- [ ] Genuine Codex ChatGPT device auth, TUI/resume, approvals/notifications and no API-key fallback pass live. Per-workspace disconnect stops only app-owned Codex tmux, removes local runtime/encrypted auth, preserves other processes/history, and a fresh device login reconnects it without claiming upstream account revocation.
- [ ] Passkey total-loss recovery and master-key rotation have tested procedures, or the owner explicitly blocks release until they do.
- [ ] Accessibility, offline encryption/staleness, performance measurements and key-flow screenshots/recordings are complete.
- [ ] Repository visibility is public, `PUBLIC_CI_ENABLED` is true, and every CI
      job uses a standard hosted runner; no larger or persistent self-hosted
      runner is configured.
- [ ] Owner separately approves production deployment, Apple archive signing and private TestFlight upload.

Known limitations shown to the owner/testers: Linux workspaces cannot run
Xcode/macOS tools; containers share one kernel; granted runtime secrets can be
read by repository code and already-running processes retain a revoked value
until closed; terminal input receipts do not provide durable exactly-once
delivery across a gateway crash, and an app termination in the receipt-to-draft
clear window can leave a stale resendable draft; portable non-Linux file saves do not provide
the production Linux external-writer CAS guarantee; the provisioner's private
Podman socket is root-equivalent authority; ten sessions share finite fixed
resources; active
processes do not survive a host reboot; local checkpoints do not survive server
loss; the provider recovery point may be about 24 hours; there is no HA or
automatic capacity purchase; the whole-server provider backup co-captures the
host master key and encrypted state, so provider/full-backup compromise may
expose those values; and Safe Mode's Coder relay is an application-level TCP
path whose rootful-Podman/firewall behavior remains unaccepted until the live
target-host gate passes.
