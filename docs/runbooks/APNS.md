# APNs setup and environment handling

Apple identifier registration, entitlement changes, key creation/revocation,
and TestFlight upload are external account mutations. The owner must approve
each exact change. APNs must be direct from the VPS; do not add a push broker or
metered notification service.

1. Confirm the final explicit `IOS_BUNDLE_ID` and Apple team. Register/modify it
   only after owner approval, enable Push Notifications and the associated
   domain required for passkeys/universal links, and keep entitlements aligned
   with `apps/ios/Resources/CodexMobile.entitlements`.
2. Ask the owner to create/provide least-scope APNs signing key material. The
   runtime intentionally has explicit sandbox and production key IDs/files;
   never silently use one environment's configured identity as the other.
   TestFlight registers with production APNs.
3. Store each `.p8` value in its exact root-owned mode-`0444` secret file beneath
   the root-owned mode-`0700` secrets directory. Set the team/key/bundle identifiers and
   `/run/secrets/...` paths; keep `APNS_ENABLED=false` until preflight passes.
4. Deploy with `APNS_ENABLED=true` only after approval. Register a sandbox token
   from a local development build and a production token from TestFlight;
   verify the server rejects an environment mismatch and invalid device.
5. Send only generic payloads. Lock-screen text must not contain repository,
   branch, filename, path, prompt, command, terminal output, approval detail or
   secret. There is no lock-screen Approve action; authenticated app navigation
   fetches current context.
6. Verify retry/transient handling and permanent unregistered-token removal.
   Record device/environment identifiers only as redacted hashes.

For compromise, disable APNs without blocking workspace service, obtain owner
approval to revoke/create keys, follow [CREDENTIAL_ROTATION.md](CREDENTIAL_ROTATION.md),
and require devices to re-register. APNs account/device testing is unexecuted
and remains `GATED`.
