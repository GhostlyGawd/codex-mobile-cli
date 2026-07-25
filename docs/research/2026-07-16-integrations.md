# Integration and dependency decisions — 2026-07-16

This is a dated decision record for the integrations that materially define the
product. Primary vendor or upstream-project sources were used. Exact artifact
digests and resolved revisions are recorded separately in
[`docs/security/DEPENDENCIES.md`](../security/DEPENDENCIES.md); a source page
showing a version is not treated as integrity evidence.

## Decision summary

| Area | Selected boundary | Why | Live gate |
| --- | --- | --- | --- |
| Codex | Genuine Codex CLI `0.144.5`, interactive TUI in a persistent tmux PTY | Preserves the real terminal experience and stable interactive resume path | Owner ChatGPT device login and target-Linux run |
| Structured Codex events | Optional local-only app-server adapter; terminal OSC/generic attention remains the stable fallback | App-server has a documented protocol, but parts of its surface and WebSocket transport are experimental | Pinned-version compatibility spike |
| Workspace control | Self-hosted Coder `2.34.6` Community with Terraform templates | Fits one-host persistent workspaces without adding a managed bill | Purchased/configured VPS and live Coder deployment |
| Source control | GitHub App installation tokens, never a stored personal access token | Repository selection, revocation, short lifetime, and least-privilege permissions are available at the installation boundary | Owner-created GitHub App and installation |
| Identity | WebAuthn passkeys with an associated `webcredentials` domain | Platform-native phishing-resistant owner authentication | Owner domain, TLS, signing, and Apple device |
| Notifications | Direct APNs provider connection from the control plane | Avoids another hosted service and keeps payloads generic | Owner APNs key, entitlements, and device |
| iOS terminal/editor | SwiftTerm `1.14.0` and Runestone `0.5.2` behind app-owned adapters | Native components, exact revisions, replaceable boundaries | Xcode/Mac compile and device fidelity corpus |
| API client | Swift OpenAPI Generator `1.11.1` plus OpenAPI Runtime `1.11.0` | Build-time typed contract checking while retaining the app's hardened transport facade | Xcode package resolution/build |

## Codex CLI and ChatGPT authentication

- The implementation pins the official
  [`rust-v0.144.5` release](https://github.com/openai/codex/releases/tag/rust-v0.144.5)
  and verifies the downloaded Linux artifact against repository-held SHA-256
  values before placing it in the trusted helper volume.
- OpenAI documents ChatGPT subscription sign-in and API-key sign-in as distinct
  authentication modes. This product intentionally forces
  `forced_login_method = "chatgpt"` and rejects API-key credential state so it
  cannot silently create metered API usage. See the official
  [Codex authentication guide](https://developers.openai.com/codex/auth).
- For a remote/headless workspace, OpenAI documents
  `codex login --device-auth` as the device-code route and labels device-code
  authentication beta. The owner must enable and complete that flow; tests do
  not substitute fabricated credentials for the live acceptance gate.
- OpenAI documents `codex resume` as the interactive-session continuation
  command in the
  [CLI command reference](https://developers.openai.com/codex/cli/reference).
  The product keeps Codex itself alive inside a named tmux window and reconnects
  to the PTY; it does not recreate conversation state in a separate model API.
- The [Codex app-server documentation](https://developers.openai.com/codex/app-server)
  defines a bidirectional JSON-RPC-style protocol. It also labels WebSocket
  transport experimental and unsupported and gates some methods behind an
  experimental capability. Consequently app-server is an optional,
  loopback-only enrichment adapter, not the terminal or availability
  dependency. The genuine TUI and content-agnostic terminal signals remain the
  stable path.

## Coder and workspace provisioning

- Coder `2.34.6` is held at an exact image digest and exact host-package version.
  The upstream [`v2.34.6` release](https://github.com/coder/coder/releases/tag/v2.34.6)
  identifies that line as stable.
- Coder documents that
  [workspace templates are Terraform](https://coder.com/docs/admin/templates).
  The repository therefore keeps both plain and approved-Dev-Container
  workspace definitions as reviewed Terraform rather than generating an
  imperative host script from user input.
- The design uses only self-hosted Community behavior. Coder documents
  [template permissions](https://coder.com/docs/admin/templates/template-permissions)
  as a premium feature, so authorization must not depend on template RBAC or
  another paid feature. Owner/workspace checks remain in the control plane and
  trusted helper boundary.
- Licensing is tracked from Coder's upstream
  [license file](https://github.com/coder/coder/blob/main/LICENSE) and the exact
  image contents. The supply-chain report classifies the open-source and
  separately licensed component boundary; this project does not modify or
  redistribute Coder as a proprietary derivative.

## GitHub App boundary

- GitHub documents that an installation access token can be restricted to
  selected `repository_ids` and selected permissions and expires after one
  hour. See
  [Generating an installation access token](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app).
- GitHub Apps receive no repository permission by default; the owner must grant
  the minimum required permissions. The requested set is limited to repository
  metadata plus Contents read/write for HTTPS Git operations. See
  [Choosing permissions for a GitHub App](https://docs.github.com/en/enterprise-cloud@latest/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app).
- The control plane mints repository-scoped installation credentials just in
  time. The trusted helper/control-plane uses them as bounded in-process
  `go-git` HTTPS auth, clears the mutable input/auth field and releases the
  credential after the operation. It creates no AskPass, credential/token file,
  environment variable, argv value or token-bearing remote. The token still
  exists transiently in trusted process memory. The service does not store a
  user PAT, authenticate arbitrary CLI Git or send an installation token to the
  phone. Removing a repository from an installation removes access, matching
  GitHub's documented
  [GitHub App versus OAuth App](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/differences-between-github-apps-and-oauth-apps)
  boundary.
- Organization policy can restrict App installation, so private organization
  repository acceptance remains owner/admin-gated. See GitHub's
  [organization App restrictions](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/limiting-oauth-app-and-github-app-access-requests-and-installations).

## Apple platform decisions

- Apple's [passkey guidance](https://developer.apple.com/documentation/authenticationservices/supporting-passkeys/)
  requires the relying-party relationship to be established with an associated
  `webcredentials` domain. A loopback or fixture ceremony cannot prove this
  production association.
- The control plane talks directly to APNs over the provider interface described
  by Apple in
  [Setting up a remote notification server](https://developer.apple.com/documentation/usernotifications/setting-up-a-remote-notification-server).
  Token authentication, key/environment selection, and rotation follow
  [Establishing a token-based connection to APNs](https://developer.apple.com/documentation/usernotifications/establishing-a-token-based-connection-to-apns).
  Device tokens are registered with the backend and treated as replaceable, per
  [Registering your app with APNs](https://developer.apple.com/documentation/usernotifications/registering-your-app-with-apns).
- Photo attachments use Apple's system
  [PhotosPicker](https://developer.apple.com/documentation/photosui/photospicker)
  and transferable data. File imports bracket reads with security-scoped access
  as required by Apple's
  [file-importer guidance](https://developer.apple.com/documentation/swiftui/view/fileimporter%28ispresented%3Aallowedcontenttypes%3Aallowsmultipleselection%3Aoncompletion%3A%29)
  and copy bounded bytes into app-owned staging rather than retaining an
  external URL.

## Native library and contract pins

- [SwiftTerm tag `v1.14.0`](https://github.com/migueldeicaza/SwiftTerm/tree/v1.14.0)
  is pinned at resolved revision `849e8a4f3d6f79ddee07152400137f1370c32621`
  behind `TerminalRendering`. Its upstream
  [license is MIT](https://github.com/migueldeicaza/SwiftTerm/blob/main/LICENSE).
- [Runestone `0.5.2`](https://github.com/simonbs/Runestone/releases/tag/0.5.2)
  is pinned at resolved revision `592434a103a4d1ab83e14f87ac6eef569dd7a99d`
  behind `TextEditing`. Its upstream
  [license is MIT](https://github.com/simonbs/Runestone/blob/main/LICENSE).
- [Swift OpenAPI Generator `1.11.1`](https://github.com/apple/swift-openapi-generator/releases/tag/1.11.1)
  runs as an Xcode build plugin against the synchronized canonical OpenAPI file.
  OpenAPI Runtime is separately pinned to `1.11.0`. Generated types supplement,
  rather than bypass, the handwritten transport facade that enforces session
  rotation, response-size limits, error decoding, and retry policy.
- The exact package graph, revisions, licenses, and checksums are generated from
  `Package.resolved` and source locks. Version pages establish selection context;
  the lockfile and generated supply-chain artifacts establish repository state.

## What remains an external acceptance gate

No external account or paid resource was mutated during implementation. The
following cannot be converted from `GATED` to `PASS` without owner-controlled
resources and recorded evidence:

1. GitHub App registration/installation, organization approval, real private
   clone/push/webhook, and revocation.
2. ChatGPT device-code login, token refresh, genuine TUI/resume, and encrypted
   credential materialization on the target Linux filesystem.
3. Passkey associated-domain ceremony, Apple signing, APNs delivery, TestFlight,
   and iPhone/iPad interaction/accessibility tests.
4. Domain DNS/TLS and wildcard preview certificate configuration.
5. Purchased VPS provisioning, host firewall/runtime isolation, ten-session
   load, backup restore, maintenance/reboot recovery, and server-loss drills.

The executable procedures and required evidence are in
[`docs/runbooks/`](../runbooks/) and
[`docs/verification/BACKEND.md`](../verification/BACKEND.md).
