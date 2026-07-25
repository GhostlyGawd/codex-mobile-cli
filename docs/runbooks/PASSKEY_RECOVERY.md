# Passkey recovery

There is no password fallback. A recovery action must not weaken the RP ID,
origin validation, user verification, credential ownership, or one-use session
rules. Changing `PASSKEY_RP_ID` can invalidate every credential and requires an
explicit migration decision—not a troubleshooting shortcut.

## One working passkey or authenticated device remains

1. Authenticate normally from a trusted device and confirm the stable HTTPS
   origin/RP ID. Revoke the lost device and all of its refresh families.
2. In the iOS app, open **Settings → Passkeys**, tap **Add Passkey**, and finish
   the system passkey sheet on the currently authenticated installation. The
   API binds this short-lived, single-use registration ceremony to the owner,
   current active device, and this-device-only installation identity; it does
   not accept a bootstrap token. Existing credentials are excluded.
3. Confirm two entries are listed, sign out and prove login with the new
   passkey, then return to **Settings → Passkeys** before revoking the old one.
   Revocation is owner-scoped and idempotent, and the server refuses to delete
   the final passkey. Record only opaque credential IDs and enrollment device
   names; never record challenges, public keys, or credential material.
4. Revoke APNs registration for the lost device and review authentication,
   safety-mode, secret-grant, preview and GitHub audit metadata since last use.
   Treat suspicious activity as an incident.

## All passkeys/devices are lost

Use only the audited SSH break-glass command; never edit identity tables by
hand. From a key-authenticated console on the VPS:

1. Stop the public control-plane service and confirm it cannot accept new
   requests. Leave PostgreSQL running. The command also checks
   `pg_stat_activity` and refuses to run while a `codex-mobile-control-plane`
   server connection exists.
2. Preserve the current database/provider backup recovery point. This command
   is intentionally destructive to identity credentials, although it preserves
   the owner, repositories, workspaces, checkpoints, vault, and audit history.
3. Run:

   ```sh
   /bin/sh /opt/codex-mobile/current/scripts/infra-admin.sh \
     recover-passkeys --confirm=REVOKE-ALL-PASSKEYS
   ```

   The root-only wrapper first verifies the active release/image/installed-host
   manifest, stops Caddy and only the serving control-plane container while
   leaving PostgreSQL running, and launches the exact recorded control-plane
   image through Compose. No host binary or ad-hoc database client is assumed.
   In one serializable transaction it revokes every passkey, device, access and
   refresh credential, APNs endpoint, and preview token; disables older
   bootstrap credentials; creates one owner-bound short-lived recovery token;
   and writes a metadata-only administrator audit event. Only a keyed hash is
   stored. The plaintext token is printed once after commit.
4. The wrapper restores the exact control-plane/Caddy images and runs the full
   infrastructure health check only after the recovery transaction commits.
   Enroll the first replacement from the stable
   production RP origin before the printed expiry, and then destroy the console
   copy of the token. The recovery token cannot create a different owner and
   cannot be used when the
   bound owner still has a passkey. While that recovered session is active,
   immediately open **Settings → Passkeys** and use **Add Passkey** to enroll a
   second credential without another recovery/bootstrap token.
5. Confirm the list contains two passkeys, prove a fresh login, and confirm the
   app/server refuse an attempt to revoke the final remaining credential. A
   displayed enrollment device name identifies where registration began; an
   iCloud Keychain passkey may be synced elsewhere. Passkey revocation does not
   end existing app sessions, and device revocation does not necessarily
   invalidate a synced passkey.
6. If enrollment or console output fails, stop the service again and rerun the
   command. The replacement transaction invalidates the prior recovery token.

The source and portable tests cover the binding, single-use token, transaction,
and command guard. The live PostgreSQL/production-origin recovery drill remains
a release gate until the owner-controlled VPS and RP domain are configured.

Total VPS/storage loss is a **release-blocking operational limitation** for this
procedure: the SSH command requires the application database and master-key
recovery material to be present. Restore the provider's included backup and the
owner-held master-key copy through the server-loss runbook first; do not create
a replacement owner or weaker password path. That provider-restore sequence
remains a live release gate and may recover only to the latest daily backup.

After any recovery, enroll and test at least two owner-controlled passkeys,
review the administrator audit event, reconnect APNs, and record the drill in
`docs/verification/ACCEPTANCE.md` without token or credential material.
