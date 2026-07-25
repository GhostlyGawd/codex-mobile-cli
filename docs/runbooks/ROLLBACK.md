# Application rollback

Rollback changes the active release on the existing VPS. It does not reverse
forward-only migrations, downgrade Coder/PostgreSQL data, or recover data that
was already modified by the newer application.

1. Open an incident/change record, stop new workspace admission through the
   application maintenance control if available, and record dirty/unpushed
   workspaces. Do not stop tmux/workspaces merely to change the control plane.
2. Run the current health check and inspect metadata-only logs. Confirm that
   `/opt/codex-mobile/previous` resolves beneath `/opt/codex-mobile/releases`
   and identify both immutable commit IDs.
3. Review migrations introduced after the previous release. If the old binary
   is not forward-compatible with the current schema, do not run this script;
   use the database restore procedure in [CHECKPOINT_RESTORE.md](CHECKPOINT_RESTORE.md)
   only with explicit owner approval and an accepted recovery point.
4. Create a fresh database checkpoint. Ask the owner to approve rollback to the
   exact prior commit, then run:

   ```shell
   sudo /bin/sh /opt/codex-mobile/current/scripts/infra-rollback.sh
   ```

5. The script first verifies that both releases' recorded image IDs still exist
   and that the target source/template/host-artifact hashes match its immutable
   manifest. It checkpoints, installs the target's Podman/systemd/wrapper
   artifacts, swaps `current`/`previous`, restarts runtime/control/provisioner,
   reactivates that release's Coder template with a new root-only activation
   receipt, and runs full health plus the bounded disposable smoke check. It
   never rebuilds or retags old source. If target activation fails it attempts
   to restore the original release once; preserve both releases/checkpoints and
   follow incident response rather than repeatedly toggling links.
6. Verify authentication, workspace list/lifecycle, terminal reconnect/replay,
   preview revocation, GitHub/APNs enabled state, migrations, and disk reserve.
   Record active processes as stopped if a host/container restart ended them.
7. Keep the failed release for investigation without secrets, and create a new
   fixed commit; never modify an immutable release in place.
