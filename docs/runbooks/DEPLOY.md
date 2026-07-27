# Guided future VPS deployment

This runbook is the deferred always-on VPS path from ADR 0005. It is not the
active private-beta deployment direction and must not be presented as a launch
requirement unless the owner explicitly reopens that decision. The active
owner-PC direction is recorded in
[ADR 0025](../adr/0025-owner-pc-private-beta-hosting.md).
Use [OWNER_PC_BETA.md](OWNER_PC_BETA.md) for the active zero-recurring-cost
host. A failed owner-profile check is not permission to continue here.

If reopened, this deploys to an existing, owner-approved Ubuntu 24.04 VPS. Nothing in the
repository purchases or resizes a server, attaches storage/backup, changes DNS,
creates integration credentials, or uploads an app.

The tracked billing policy currently marks `fixed_price_vps` unauthorized.
Reopening hosting therefore requires a separate reviewed repository decision;
changing only an environment value cannot enable this runbook.

## External-action gates

Stop at each row. Show the exact proposed mutation and continue only after a
fresh explicit owner approval. The owner performs the mutation in the provider
UI; automation merely validates its result.

| Gate | Required evidence before approval | Automated action |
| --- | --- | --- |
| VPS purchase | Final monthly cart, region, tax, zero commitment, included daily backup, no overage/add-on | None |
| DNS API and wildcard records | Exact API and `*.preview` names, values, TTL, rollback values | None |
| GitHub App | Name, callback/webhook URLs, selected repositories and least permissions | None |
| Apple identifier/APNs key | Team, explicit bundle ID, environments and key custody | None |
| First host configuration | Existing IP, Ubuntu 24.04, SSH allowlist, encrypted XFS data mount with project quotas | Owner runs Ansible with explicit confirmation |
| Release activation | Commit, source audit, manifest-bound image audit policy, checkpoint, eligible audited rollback release | Owner runs local deploy script on existing host |

## Prepare and harden the existing host

1. Verify the owner already purchased the exact plan documented in
   `COST_MODEL.md`; capture the provider backup status and measured CPU/RAM/disk.
   Reject any unexpected recurring or usage-priced line.
2. Provision and mount operator-managed LUKS/dm-crypt storage exactly at
   `/srv/codex-mobile` as XFS with `pquota` or `prjquota`. Keep recovery
   material offline. Do not let the playbook partition, format, remount, or
   silently substitute a directory on the root filesystem. Ansible, deploy
   preflight, and the workspace-runtime unit all fail closed on the wrong mount,
   filesystem, or option.
3. Copy `infra/ansible/inventory.example.yml` outside the repository, replace
   every placeholder, restrict it to the existing host, and review the diff.
4. After the owner confirms the exact target and SSH/firewall change, run:

   ```shell
   ansible-playbook -i /secure/path/inventory.yml infra/ansible/playbook.yml --check --diff
   ansible-playbook -i /secure/path/inventory.yml infra/ansible/playbook.yml
   ```

   The inventory's awkward
   `codex_confirm_existing_ubuntu_host=CONFIGURE_EXISTING_UBUNTU_24_04` guard
   must remain. Keep a second verified SSH session open until access is tested.

## Configure without exposing integrations

1. Copy `infra/env/production.env.example` to
   `/etc/codex-mobile/production.env`, mode `0600`. Only after the reviewed
   policy change, set `DEPLOYMENT_PROFILE=fixed_price_vps`, uncomment all seven
   `VPS_*` values, and fill the domain, existing VPS, immutable release tag, and
   billing confirmations. Keep `GITHUB_ENABLED=false` and
   `APNS_ENABLED=false` during Coder bootstrap.
2. Generate local application/database secrets once:

   ```shell
   sudo /bin/sh /opt/codex-mobile/staging/sha-<commit>/scripts/infra-generate-secrets.sh \
     --secrets-dir /etc/codex-mobile/secrets
   ```

   Store an offline matching copy of the control-plane master key for recovery
   from host-file loss or corruption. The key is separate from PostgreSQL and
   database-only dumps, but the included provider product is a whole-server
   backup and is expected to capture the root-owned host key with encrypted
   state. That backup offers availability/key-data consistency, not
   cryptographic separation from provider or full-backup compromise. The
   generator refuses to replace existing files.
3. Run `scripts/infra-bootstrap-coder.sh`. Complete the private Coder owner
   ceremony over an SSH tunnel, create scoped control-plane/provisioner
   credentials, install their root-owned mode-`0444` files beneath the
   root-owned mode-`0700` secrets directory, then build the pinned bootstrap
   workspace images and perform the one permitted pre-release template import:

   ```shell
   sudo env REPO_ROOT=/opt/codex-mobile/staging/sha-<commit> \
     /bin/sh /opt/codex-mobile/staging/sha-<commit>/scripts/infra-build-workspace-image.sh
   sudo env REPO_ROOT=/opt/codex-mobile/staging/sha-<commit> \
     ENV_FILE=/etc/codex-mobile/production.env \
     /bin/sh /opt/codex-mobile/staging/sha-<commit>/scripts/infra-import-coder-template.sh \
       --bootstrap
   ```

   Record the returned
   template UUID in `CODER_TEMPLATE_ID`; the bootstrap flag is rejected after
   an immutable release exists. These are manual credential gates; never print
   tokens. The image build reconstructs EnvBuilder from the exact source lock
   and local patch, resolves the verified workspace-base tag to one immutable
   local ID, and compares the complete helper seed without executing image
   content. It must not accept `ENVBUILDER_BASE_IMAGE` or inherit the upstream
   prebuilt image.
   The provisioner is unprivileged, but membership in
   `coder-provisioner` grants access to the private root-owned Podman socket and
   is therefore root-equivalent host authority. Confirm the socket is mode
   `0660`, owned by `root:coder-provisioner`, and absent from both Coder and
   workspace mounts.
   Keep `CODER_WORKSPACE_CONNECTIVITY_CONFIRMED=false`. Configure a canonical
   RFC1918 `/24`–`/28` `WORKSPACE_CONTROL_SUBNET` disjoint from the literal
   private `CODER_BIND_ADDRESS`, and never use loopback, a wildcard or a public
   address for the production Coder listener. Bootstrap may import the template
   before the live connectivity proof; normal preflight/activation may not.
4. Run the full preflight and billing guard:

   ```shell
   python3 scripts/check-billing-policy.py --repo-root "$PWD" \
     --deployment-profile fixed_price_vps
   python3 scripts/infra-preflight.py \
     --env-file /etc/codex-mobile/production.env --repo-root "$PWD"
   ```

   Under the current decision both commands must reject this deferred profile.
   Do not continue unless a later reviewed repository decision explicitly
   authorizes `fixed_price_vps` and updates both guards.

5. Only after separate owner approvals, complete [GITHUB_APP.md](GITHUB_APP.md),
   [APNS.md](APNS.md), and the DNS/certificate gate in `infra/README.md`. Enable
   each integration only after all of its secret files validate.

## Activate an immutable release

On a trusted build host, run all commands in `AGENTS.md` and the source
supply-chain audit, including
`python3 -I scripts/verify-envbuilder-source.py`. Stage an owner-reviewed tree named exactly
`/opt/codex-mobile/staging/sha-<lowercase-commit>`, with matching
`CONTROL_PLANE_IMAGE_TAG`. Do not stage `.git`, local secrets, reports with local
paths, untracked code, or pre-generated image-audit evidence. The locked deploy
builds and audits the final host-local image IDs; an earlier WSL or workstation
scan is useful developmental evidence but cannot authorize a later rebuild.

Immediately before activation, record current health, create a database
checkpoint, verify the provider's included backup, and ask the owner to approve
activation of the named commit. Then run on the existing host:

```shell
sudo /bin/sh /opt/codex-mobile/staging/sha-<commit>/scripts/infra-deploy.sh \
  /opt/codex-mobile/staging/sha-<commit>
```

The script freezes the staged tree, validates billing/preflight including the
exact XFS project-quota mount, and builds each control-plane/workspace image
once under the commit-derived release tag. It captures and scans those exact
IDs with checksum-pinned Syft 1.46.0 and Trivy 0.72.0, a single frozen
vulnerability-database snapshot, explicit Docker/Podman engines, and the
reviewed profile-3/schema-2 policy. Vulnerabilities and forbidden licenses use
14-field exact expiring dispositions; each image's complete non-forbidden
license inventory uses one expiring duplicate-sensitive canonical multiset
baseline. New, missing, changed, expired, unused, malformed, oversized, or
undispositioned evidence fails before promotion. The root-only
`infra/image-audit` receipt and report tree are then bound into schema 2 of
`infra/release-manifest.json` alongside the workspace-helper checksum, Coder
template tree, Podman configuration, systemd units and privileged wrappers.
`infra/release.env` binds that release to those image references. The script
verifies all evidence and tag IDs again, checkpoints the current
database, installs the matching host artifacts, atomically switches the release
link, restarts the runtime/control/provisioner, activates the exact Coder
template, and writes a root-only activation receipt beneath
`/opt/codex-mobile/activations`.

Activation never builds. Health fails unless the running control-plane image,
all local image tags, installed host artifacts, four Compose services, systemd
units, XFS storage verifier, private Podman socket/API, and recently registered
`runtime=private-podman` Terraform provisioner all match. Deployment also runs
one bounded networkless disposable volume/container smoke check and removes it.
If any step fails, the script makes one attempt to restore the prior manifest,
host artifacts, template and services; it never rebuilds the old source. It
does not reverse a database migration.

Verify passkey auth, repository sync (if enabled), one isolated workspace,
Codex device-auth/TUI, terminal reconnect, file/Git flow, preview auth/revoke,
generic APNs, checkpoint creation, capacity refusal, logs and disk reserve.
Credentialed checks not actually run remain `GATED`.

Before admitting production data, run the Linux runtime spike against the
dedicated engine. It must create the disposable quota volume, allow a small
write, reject a write beyond the configured bound specifically for quota
exhaustion, inspect the private user namespace/cgroups/network, and prove no
Coder/workspace process can access the engine socket. Also verify the 8–16 GiB
create-time range, 12 GiB default, 40 GiB host reserve, and 56 GiB minimum free
space for a new start.

Using a template-created Safe Mode workspace, prove the workspace is absent
from `codex-mobile-control`, its Coder agent registers and a real PTY works only
through the per-workspace `cm-coder-control` relay, and direct access to the
private Coder listener, every other host/control-stack port, another workspace,
the engine socket and the general network fails. Inspect the relay to confirm it
alone joins the fixed uplink and has no token, volume, host path, device,
capability or socket. The workspace's standard `CODER_AGENT_TOKEN` is expected
and may be visible to same-authority repository code; prove its
`api_key_scope=no_user_data` cannot obtain privileged Coder API/user-data or
cross-workspace authority, and prove no control-plane Coder token/provisioner
key enters the workspace. Then prove Balanced/Full Access adds only the separate
expected per-workspace egress bridge. Record the address/subnet, runtime,
firewall and route evidence without tokens. Only after every probe passes may
the operator set `CODER_WORKSPACE_CONNECTIVITY_CONFIRMED=true`, rerun preflight
and activate/import the normal template. Static Terraform, labels or a successful
container start are not substitutes for this kernel/network/filesystem proof.
