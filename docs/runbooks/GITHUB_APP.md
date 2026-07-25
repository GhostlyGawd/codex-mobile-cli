# GitHub App setup and recovery

Creating, installing, changing, suspending, or deleting a GitHub App is an
external account mutation. Stop before each action, show exact name/URLs,
repository selection and permissions, and obtain explicit owner approval. No
repository script calls a GitHub provisioning API.

## Owner-created App contract

- Use a private owner-specific App; do not publish it in Marketplace.
- Webhook URL: `https://<API_HOST>/v1/github/webhook` over valid public TLS.
- Webhook events: only `installation` and `installation_repositories`.
- Repository permissions: `Contents: Read and write` and
  `Pull requests: Read and write`; metadata read access is implicit. Add no
  administration, actions, checks, issues, secrets, organization, members, or
  billing permission.
- Prefer **only selected repositories**. Organization installation/approval is
  a separate owner/org-admin gate and denial must remain an expected UI state.
- User authorization/callback settings must match the exact implemented HTTPS
  callback before enabling OAuth. Do not guess or use wildcard callbacks.

## Install configuration

1. After approval, the owner creates the App and downloads a private key once.
   Record App/client identifiers but never key/client/webhook secrets.
2. Generate independent random client and webhook secrets in the GitHub UI.
   Place them as the exact root-owned mode-`0444` files documented in
   `infra/env/production.env.example`; keep the root-owned directory `0700`.
3. Fill the identifiers and `/run/secrets/...` paths, keep
   `GITHUB_ENABLED=false`, and run `infra-preflight.py`.
4. Ask for approval to install on the enumerated selected repositories. Confirm
   the returned installation/account belongs to the enrolled owner; do not
   accept an arbitrary installation ID.
5. Set `GITHUB_ENABLED=true`, deploy the reviewed Compose override, then run the
   metadata sync command inside the control-plane container with the approved
   installation ID. Do not put an installation token on the command line.

The in-app disconnect is deliberately local. It hides repositories and blocks
new token minting before a GitHub request, but does not uninstall or mutate the
provider-side App. Webhooks cannot undo that owner choice; an intentional local
reconnect uses the explicit reviewed synchronization command. External App
install/uninstall, repository selection and permission changes remain separate
owner-approved GitHub actions. The local/provider distinction and recovery
procedure are recorded in
[CREDENTIAL_ROTATION.md](CREDENTIAL_ROTATION.md).

## Live acceptance

With one private user repository and an organization repository if available,
prove list/suspension denial, clone, unique task branch/worktree, pull, commit,
push and PR creation. Authenticated bootstrap and native remote operations must
use the repository-scoped token only as in-process `go-git` HTTPS auth through
the trusted exact-GitHub/direct-CA transport. Inspect redacted Git
config/process/environment/audit state to prove no AskPass, credential/token
file, token-bearing remote, argv value, log entry or workspace file was created.
The token remains transiently present in trusted helper/control-plane process
memory and is cleared/released after the operation; do not claim arbitrary CLI
Git is service-authenticated. Deliver signed installation/repository-change
webhooks, reject a bad signature, and verify unavailable repositories disappear
without deleting workspace history.

On key compromise, disable GitHub integration, revoke sessions/tokens and the
App key, rotate client/webhook secrets under [CREDENTIAL_ROTATION.md](CREDENTIAL_ROTATION.md),
review repository/audit activity, then re-enable only after a clean live test.
Local disconnect alone is not provider-side revocation and is insufficient for
that incident.

Credentialed GitHub setup has not been executed in this worktree and must stay
`GATED` until the owner supplies/approves the App.
