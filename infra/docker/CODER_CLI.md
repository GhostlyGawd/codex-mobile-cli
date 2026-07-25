# Embedded Coder CLI

The control-plane image embeds the official, statically linked Coder CLI only
to run the fixed workspace helper over Coder's supported SSH transport. The
application does not expose an arbitrary remote-command endpoint.

Pinned release: Coder `v2.34.6`

- Release: <https://github.com/coder/coder/releases/tag/v2.34.6>
- AMD64 archive: <https://github.com/coder/coder/releases/download/v2.34.6/coder_2.34.6_linux_amd64.tar.gz>
- AMD64 SHA-256: `091acfd4356ab2f02bcaf561928841e9aecc630a28bc9678658d4ae47632df09`
- ARM64 archive: <https://github.com/coder/coder/releases/download/v2.34.6/coder_2.34.6_linux_arm64.tar.gz>
- ARM64 SHA-256: `d16b0f9393404e1d85669ec620aa90d2a0c10b1977c11c95e11b2d6b9bb0917d`
- Publisher checksum manifest: <https://github.com/coder/coder/releases/download/v2.34.6/coder_2.34.6_checksums.txt>

The Docker build verifies the selected archive before extraction and copies
both `LICENSE` and `LICENSE.enterprise` from that same release into
`/usr/share/licenses/coder`. The final scratch image runs as UID/GID 65532,
with a read-only root filesystem in Compose and writable space limited to its
bounded `/tmp` tmpfs.

The only supported helper invocation is equivalent to:

```sh
CODER_URL=http://coder:7080 \
CODER_SESSION_TOKEN='<read from /run/secrets/coder_api_token>' \
CODER_DISABLE_DIRECT_CONNECTIONS=true \
CODER_DISABLE_NETWORK_TELEMETRY=true \
coder ssh --disable-autostart --wait yes '<workspace UUID>' -- \
  /opt/codex-mobile-helper/codex-mobile-workspace-helper
```

Normal command mode is intentional: it is non-TTY, carries standard input and
output directly, and preserves the remote exit status. `coder ssh --stdio` is
a raw SSH proxy transport and is not used for the helper. The `/opt` directory
is a per-workspace, checksum-versioned named volume mounted read-only. This
keeps the fixed executable outside both the writable workspace and an approved
Dev Container's transformed root filesystem.
