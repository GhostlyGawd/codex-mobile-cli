# Controlled update and maintenance

Never use floating image tags, automatic major upgrades, Coder's update check,
Codex self-update, unattended container replacement, or automatic reboot.
Security updates may be accelerated, but the same checkpoint and health gates
apply.

## Prepare

1. Open a change record naming every old/new version and upstream security or
   compatibility reason. Revalidate license and cost implications.
2. Update source pins, digests, checksums, lockfiles, ADR/capability/security
   assumptions, and generated supply-chain reports in one reviewed commit.
3. Run backend/race/migration/API tests, iOS generation and Xcode tests, static
   infrastructure tests, Syft/go-licenses/govulncheck/Gitleaks/Trivy, and image
   scans. Exercise Coder template/EnvBuilder/Codex TUI changes on disposable
   local infrastructure before production.
4. Confirm rollback compatibility. PostgreSQL/Coder schema upgrades may make a
   binary-only rollback unsafe; plan a tested checkpoint restore if so.

## Weekly maintenance window

1. Notify the owner/devices without repository, path, prompt, or command detail.
   Stop admitting long-running work near the configured window.
2. Enumerate dirty/unpushed workspaces. Warn prominently; never delete them.
   Gracefully drain input, suspend where safe, and checkpoint the database and
   each stopped dirty workspace. Verify free space and provider daily backup.
3. Ask the owner to approve activation of the exact staged release and, in a
   separate question, any required host reboot. Run [DEPLOY.md](DEPLOY.md).
4. Apply Ubuntu security packages in reviewed groups. Reboot only if required
   and explicitly approved. Active processes cannot survive; after reboot mark
   them stopped or restart only documented services—not user commands.
5. Run `scripts/infra-health.sh`, connect a genuine terminal, resume/suspend a
   workspace, verify Coder template/image version, test preview auth, and review
   resource reserve. Reopen admission only after checks pass.
6. Retain the previous release, all three image IDs named by its immutable
   manifest, activation receipt, and checkpoints through the observation
   window. Never run a broad Docker/Podman image prune: first prove an image ID
   is absent from both `current` and `previous` manifests, then remove only that
   explicitly reviewed ID under the documented age/disk policy. Deleting a
   recorded image makes rollback fail closed rather than rebuilding it.

For an urgent incident, warn with the time available, make best-effort
checkpoints, contain first, and use [INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md).
