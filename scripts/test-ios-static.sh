#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ROOT
cd "${ROOT}"

grep -Eq 'minimumXcodeGenVersion: 2\.45\.4' apps/ios/project.yml
grep -Eq 'xcodeVersion: "26\.6"' apps/ios/project.yml
grep -Eq 'exactVersion: 1\.14\.0' apps/ios/project.yml
grep -Eq 'exactVersion: 0\.5\.2' apps/ios/project.yml
grep -Eq 'exactVersion: 0\.1\.10' apps/ios/project.yml
grep -Eq 'exactVersion: 1\.11\.1' apps/ios/project.yml
grep -Eq 'exactVersion: 1\.11\.0' apps/ios/project.yml
grep -Eq 'plugin: OpenAPIGenerator' apps/ios/project.yml
grep -Fq '592434a103a4d1ab83e14f87ac6eef569dd7a99d' apps/ios/Package.resolved
grep -Fq '849e8a4f3d6f79ddee07152400137f1370c32621' apps/ios/Package.resolved
grep -Fq '15cf3a9ec3ab95e0d058b7df9f35619123c9e02d' apps/ios/Package.resolved
grep -Fq '73997cc62c2193d5046e431c9d546119dda14502' apps/ios/Package.resolved
grep -Fq 'f039fa6d6338aab5164f3d1be16281524c9a8f89' apps/ios/Package.resolved
grep -Eq '"filename"[[:space:]]*:[[:space:]]*"AppIcon\.png"' apps/ios/Resources/Assets.xcassets/AppIcon.appiconset/Contents.json
grep -Eq '"size"[[:space:]]*:[[:space:]]*"1024x1024"' apps/ios/Resources/Assets.xcassets/AppIcon.appiconset/Contents.json
test -s apps/ios/Resources/Assets.xcassets/AppIcon.appiconset/AppIcon.png
python3 - <<'PY'
from pathlib import Path
import struct

raw = Path("apps/ios/Resources/Assets.xcassets/AppIcon.appiconset/AppIcon.png").read_bytes()
assert raw[:8] == b"\x89PNG\r\n\x1a\n" and raw[12:16] == b"IHDR", "AppIcon.png must be a valid PNG"
header = struct.unpack(">IIBBBBB", raw[16:29])
assert header == (1024, 1024, 8, 2, 0, 0, 0), "AppIcon.png must be non-interlaced 1024x1024 8-bit truecolor without alpha"
offset = 8
while offset < len(raw):
    length = struct.unpack(">I", raw[offset:offset + 4])[0]
    chunk = raw[offset + 4:offset + 8]
    assert chunk != b"tRNS", "AppIcon.png must not contain transparency"
    offset += 12 + length
    assert offset <= len(raw), "AppIcon.png has an invalid chunk length"
assert offset == len(raw), "AppIcon.png has malformed trailing data"
PY
grep -Eq 'headerLength = 36' apps/ios/Sources/Terminal/TerminalProtocol.swift
grep -Fq 'Data([0x43, 0x4D])' apps/ios/Sources/Terminal/TerminalProtocol.swift
grep -Eq 'idempotentInput: UInt16 = 1 << 1' apps/ios/Sources/Terminal/TerminalProtocol.swift
grep -Eq 'inputReceipt: UInt16 = 1 << 2' apps/ios/Sources/Terminal/TerminalProtocol.swift
grep -Eq 'inputReceiptConfirmed: UInt16 = 1 << 3' apps/ios/Sources/Terminal/TerminalProtocol.swift
grep -Eq 'maximum_frame_bytes: \{[^}]*maximum: 1048576' packages/api-contract/openapi.yaml
cmp packages/api-contract/openapi.yaml apps/ios/Sources/GeneratedAPI/openapi.yaml
grep -Eq '^  - types$' apps/ios/Sources/GeneratedAPI/openapi-generator-config.yaml
grep -Eq '^  - client$' apps/ios/Sources/GeneratedAPI/openapi-generator-config.yaml
grep -Fq 'memory_gi_b:' packages/api-contract/openapi.yaml
grep -Fq 'writable_disk_gi_b:' packages/api-contract/openapi.yaml
grep -Fq 'requested_disk_gi_b:' packages/api-contract/openapi.yaml
grep -Eq 'requested_disk_gi_b: \{oneOf: \[\{type: integer, minimum: 8, maximum: 16, default: 12\}' packages/api-contract/openapi.yaml
grep -Fq 'expected_e_tag:' packages/api-contract/openapi.yaml
grep -Eq 'SecretValue: \{type: string, minLength: 4, maxLength: 8192, writeOnly: true\}' packages/api-contract/openapi.yaml
grep -Eq 'value_bytes: \{type: integer, minimum: 4, maximum: 8192\}' packages/api-contract/openapi.yaml
grep -Eq 'enum: \[sandbox, production\]' packages/api-contract/openapi.yaml

expected_routes="$(printf '%s\n' \
  'GET /v1/capabilities getCapabilities' \
  'POST /v1/auth/passkeys/registration/options beginPasskeyRegistration' \
  'POST /v1/auth/passkeys/registration/verify finishPasskeyRegistration' \
  'POST /v1/auth/passkeys/authentication/options beginPasskeyAuthentication' \
  'POST /v1/auth/passkeys/authentication/verify finishPasskeyAuthentication' \
  'POST /v1/passkeys/registration/options beginAdditionalPasskeyRegistration' \
  'POST /v1/passkeys/registration/verify finishAdditionalPasskeyRegistration' \
  'GET /v1/passkeys listPasskeys' \
  'DELETE /v1/passkeys/{credential_id} revokePasskey' \
  'POST /v1/auth/session/refresh refreshSession' \
  'DELETE /v1/auth/session revokeCurrentSession' \
  'GET /v1/devices listDevices' \
  'DELETE /v1/devices/{device_id} revokeDevice' \
  'GET /v1/secrets listSecrets' \
  'POST /v1/secrets createSecret' \
  'PUT /v1/secrets/{secret_id} updateSecret' \
  'DELETE /v1/secrets/{secret_id} deleteSecret' \
  'GET /v1/connections getConnections' \
  'DELETE /v1/connections/github/{installation_id} disconnectGitHub' \
  'GET /v1/repositories listRepositories' \
  'GET /v1/workspaces listWorkspaces' \
  'POST /v1/workspaces createWorkspace' \
  'GET /v1/workspaces/{workspace_id} getWorkspace' \
  'POST /v1/workspaces/{workspace_id}/actions performWorkspaceAction' \
  'GET /v1/workspaces/{workspace_id}/secret-grants listWorkspaceSecretGrants' \
  'PUT /v1/workspaces/{workspace_id}/secret-grants/{secret_id} grantWorkspaceSecret' \
  'DELETE /v1/workspaces/{workspace_id}/secret-grants/{secret_id} revokeWorkspaceSecret' \
  'GET /v1/workspaces/{workspace_id}/connections/codex getCodexConnection' \
  'DELETE /v1/workspaces/{workspace_id}/connections/codex disconnectCodex' \
  'GET /v1/activity listActivity' \
  'GET /v1/approvals/{approval_id} getApproval' \
  'POST /v1/approvals/{approval_id}/decision resolveApproval' \
  'GET /v1/workspaces/{workspace_id}/terminal-tabs listTerminalTabs' \
  'POST /v1/workspaces/{workspace_id}/terminal-tabs createTerminalTab' \
  'PUT /v1/workspaces/{workspace_id}/terminal-tabs/order reorderTerminalTabs' \
  'PATCH /v1/workspaces/{workspace_id}/terminal-tabs/{tab_id} renameTerminalTab' \
  'DELETE /v1/workspaces/{workspace_id}/terminal-tabs/{tab_id} closeTerminalTab' \
  'POST /v1/workspaces/{workspace_id}/terminal-tabs/{tab_id}/connection createTerminalConnection' \
  'POST /v1/workspaces/{workspace_id}/terminal-tabs/{tab_id}/attachments stageTerminalAttachments' \
  'GET /v1/workspaces/{workspace_id}/files getFileTree' \
  'GET /v1/workspaces/{workspace_id}/file-search searchFiles' \
  'GET /v1/workspaces/{workspace_id}/file getFile' \
  'PUT /v1/workspaces/{workspace_id}/file saveFile' \
  'GET /v1/workspaces/{workspace_id}/git/status getGitStatus' \
  'GET /v1/workspaces/{workspace_id}/git/diff getGitDiff' \
  'POST /v1/workspaces/{workspace_id}/git/stage setGitStaged' \
  'POST /v1/workspaces/{workspace_id}/git/commits createCommit' \
  'POST /v1/workspaces/{workspace_id}/git/pull pullWorkspace' \
  'POST /v1/workspaces/{workspace_id}/git/push pushWorkspace' \
  'POST /v1/workspaces/{workspace_id}/git/discard discardGitChanges' \
  'POST /v1/workspaces/{workspace_id}/pull-requests createPullRequest' \
  'GET /v1/workspaces/{workspace_id}/checkpoints listCheckpoints' \
  'POST /v1/workspaces/{workspace_id}/checkpoints/{checkpoint_id}/restore-file restoreCheckpointFile' \
  'POST /v1/workspaces/{workspace_id}/checkpoints/{checkpoint_id}/restore-workspace restoreCheckpointWorkspace' \
  'GET /v1/workspaces/{workspace_id}/previews listPreviews' \
  'POST /v1/workspaces/{workspace_id}/previews/access createPreviewAccess' \
  'DELETE /v1/workspaces/{workspace_id}/previews/{preview_id}/access revokePreviewAccess' \
  'GET /v1/maintenance getMaintenance' \
  'POST /v1/maintenance/schedule scheduleMaintenance' \
  'DELETE /v1/maintenance/{maintenance_id} cancelMaintenance' \
  'POST /v1/maintenance/{maintenance_id}/actions advanceMaintenance' \
  'GET /v1/diagnostics getDiagnostics' \
  'GET /v1/settings getSettings' \
  'PUT /v1/settings updateSettings' \
  'PUT /v1/devices/push registerPushDevice')"
actual_routes="$(awk '
  /^  \/[^:]+:/ {
    path = $1
    sub(/:$/, "", path)
  }
  /^    (get|post|put|patch|delete):/ {
    method = toupper($1)
    sub(/:$/, "", method)
  }
  /^      operationId:/ {
    print method, path, $2
  }
' packages/api-contract/openapi.yaml)"
[[ "$(printf '%s\n' "${actual_routes}" | wc -l | tr -d ' ')" -eq 65 ]]
[[ "${actual_routes}" == "${expected_routes}" ]]

expected_client_routes="$(printf '%s\n' "${actual_routes}" | awk '
  {
    $NF = ""
    sub(/[[:space:]]+$/, "")
    gsub(/\{[^}]+\}/, "{}")
    print
  }
' | LC_ALL=C sort)"
actual_client_routes="$(awk '
  /method: "(GET|POST|PUT|PATCH|DELETE)"/ {
    method_line = $0
    sub(/^.*method: "/, "", method_line)
    sub(/".*$/, "", method_line)
    method = method_line
  }
  /path: "v1\// {
    path_line = $0
    sub(/^.*path: "/, "", path_line)
    sub(/".*$/, "", path_line)
    gsub(/\\/, "", path_line)
    gsub(/[(][^)]*[)]/, "{}", path_line)
    if (method != "") {
      print method, "/" path_line
      method = ""
    }
  }
' apps/ios/Sources/Networking/HTTPAPIClient.swift | LC_ALL=C sort)"
[[ "$(printf '%s\n' "${actual_client_routes}" | wc -l | tr -d ' ')" -eq 65 ]]
[[ "${actual_client_routes}" == "${expected_client_routes}" ]]

grep -Fq 'memory_gi_b' apps/ios/Tests/JSONCodingContractTests.swift
grep -Fq 'writable_disk_gi_b' apps/ios/Tests/JSONCodingContractTests.swift
grep -Fq 'requested_disk_gi_b' apps/ios/Tests/JSONCodingContractTests.swift
grep -Fq 'expected_e_tag' apps/ios/Tests/JSONCodingContractTests.swift
grep -Fq 'websocket_url' apps/ios/Tests/JSONCodingContractTests.swift
grep -Fq 'client_data_json' apps/ios/Tests/JSONCodingContractTests.swift
grep -Fq 'allowed_credential_ids' apps/ios/Tests/JSONCodingContractTests.swift
grep -Eq 'in: 8\.\.\.16, step: 4' apps/ios/Sources/Features/Workspaces/NewWorkspaceView.swift
grep -Eq 'autonomy = defaults\.autonomyDefault' apps/ios/Sources/Features/Workspaces/NewWorkspaceView.swift
grep -Eq 'retention = defaults\.retentionDefault' apps/ios/Sources/Features/Workspaces/NewWorkspaceView.swift
grep -Fq 'isShowingFullAccessDefaultConfirmation' apps/ios/Sources/Features/Settings/SettingsView.swift
grep -Fq 'Full Access lets Codex act without approval' apps/ios/Sources/Features/Settings/SettingsView.swift
grep -Fq 'action: .updateAutonomy' apps/ios/Sources/Features/Workspaces/WorkspaceScreen.swift
grep -Fq 'detail.summary.lifecycle == .suspended' apps/ios/Sources/Features/Workspaces/WorkspaceScreen.swift
grep -Fq 'showsFullAccessConfirmation' apps/ios/Sources/Features/Workspaces/WorkspaceScreen.swift
grep -Fq 'Button("Use Full Access", role: .destructive)' apps/ios/Sources/Features/Workspaces/WorkspaceScreen.swift
grep -Fq 'matching network policy and managed Codex configuration' apps/ios/Sources/Features/Workspaces/WorkspaceScreen.swift
grep -Fq 'update_autonomy' packages/api-contract/openapi.yaml
grep -Eq 'pendingDeepLinkRoute = route' apps/ios/Sources/App/AppModel.swift
grep -Fq 'applyPendingDeepLinkIfReady()' apps/ios/Sources/App/AppModel.swift
grep -Fq 'consumeColdStartDeepLink()' apps/ios/Sources/App/CodexMobileApp.swift
grep -Fq 'await model.bootstrap()' apps/ios/Sources/App/CodexMobileApp.swift
grep -Fq 'launchOptions?[.remoteNotification]' apps/ios/Sources/Notifications/PushNotifications.swift
grep -Fq 'coldStartDeepLinks.store(url)' apps/ios/Sources/Notifications/PushNotifications.swift
grep -Fq 'testValidatedLinkWaitsForSessionBootstrap' apps/ios/Tests/ColdStartDeepLinkTests.swift
grep -Eq 'StructuredApprovalsAvailable:[[:space:]]*true' services/control-plane/internal/application/passkeys.go
grep -Fq '0x2028...0x202E' apps/ios/Sources/Security/HostileDisplayText.swift
grep -Fq '0x2060...0x206F' apps/ios/Sources/Security/HostileDisplayText.swift
grep -Fq 'scalar.value == 0x5C' apps/ios/Sources/Security/HostileDisplayText.swift
grep -Fq 'testEscapesControlsBidiOverridesAndLiteralEscapePrefixes' apps/ios/Tests/HostileDisplayTextTests.swift
grep -Fq 'display sanitization must not mutate the operational path' apps/ios/Tests/HostileDisplayTextTests.swift
grep -Fq 'HostileDisplayText.sanitized(result.path)' apps/ios/Sources/Features/Files/WorkspaceFilesView.swift
grep -Fq 'FileEditorView(workspaceID: workspaceID, path: result.path)' apps/ios/Sources/Features/Files/WorkspaceFilesView.swift
grep -Fq 'HostileDisplayText.sanitized(change.path)' apps/ios/Sources/Features/Git/WorkspaceGitView.swift
grep -Fq 'path: change.path, staged: staged' apps/ios/Sources/Features/Git/WorkspaceGitView.swift
grep -Fq 'terminalTitle = HostileDisplayText.sanitized' apps/ios/Sources/Terminal/TerminalSessionModel.swift
grep -Fq 'testTerminalDerivedTitlesAndCloseReasonsAreSafeDisplayText' apps/ios/Tests/TerminalSessionModelTests.swift
grep -Fq 'isServerUnavailable = Self.isServerAvailabilityFailure' apps/ios/Sources/App/AppModel.swift
grep -Fq 'Server unavailable — cached data is read only' apps/ios/Sources/App/RootView.swift
grep -Fq 'This app cannot recreate the server' apps/ios/Sources/App/RootView.swift
grep -Fq 'repository_id' apps/ios/Tests/JSONCodingContractTests.swift
grep -Fq 'content_base64' apps/ios/Tests/JSONCodingContractTests.swift
grep -Fq 'SecureField("Secret value"' apps/ios/Sources/Features/Settings/SecretsSettingsView.swift
grep -Eq 'value = ""' apps/ios/Sources/Features/Settings/SecretsSettingsView.swift
grep -Eq '\(4 \.\.\. 8192\)\.contains\(value\.utf8\.count\)' apps/ios/Sources/Features/Settings/SecretsSettingsView.swift
if grep -Eq 'SecretMetadata|WorkspaceSecretGrant|CreateSecretRequest|UpdateSecretRequest|AttachmentUpload|StagedAttachment' apps/ios/Sources/Security/EncryptedOfflineCache.swift; then
  echo "offline cache must not persist sensitive secret or attachment models" >&2
  exit 1
fi
grep -Fq 'AES.GCM.seal' apps/ios/Sources/Security/EncryptedComposerStore.swift
grep -Fq 'KeychainComposerKeyProvider' apps/ios/Sources/Security/EncryptedComposerStore.swift
grep -Eq 'maximumHistoryCount = 50' apps/ios/Sources/Security/EncryptedComposerStore.swift
grep -Fq 'PhotosPicker(' apps/ios/Sources/Features/Terminal/TerminalComposerView.swift
grep -Fq '.fileImporter(' apps/ios/Sources/Features/Terminal/TerminalComposerView.swift
grep -Fq 'try await send(value, uploads)' apps/ios/Sources/Features/Terminal/TerminalComposerView.swift
grep -Fq 'recordSuccessfulSend' apps/ios/Sources/Features/Terminal/TerminalComposerView.swift
grep -Fq 'Decoded content is capped at 8 MiB' packages/api-contract/openapi.yaml
grep -Fq 'keyEncodingStrategy = .custom' apps/ios/Sources/Networking/Coding.swift
grep -Fq 'keyDecodingStrategy = .custom' apps/ios/Sources/Networking/Coding.swift
grep -Fq 'TextViewState(text: document.content, theme: DefaultTheme(), language:' apps/ios/Sources/Editor/RunestoneAdapter.swift

first_line="$(sed -n '1p' apps/ios/Sources/PreviewSupport/FixtureAPIClient.swift)"
last_line="$(tail -n 1 apps/ios/Sources/PreviewSupport/FixtureAPIClient.swift)"
[[ "${first_line}" == '#if DEBUG' && "${last_line}" == '#endif' ]]

if grep -RIE '(ghp_[A-Za-z0-9]{20,}|github_pat_|sk-[A-Za-z0-9]{20,}|BEGIN [A-Z ]*PRIVATE KEY)' \
  apps/ios/Sources --exclude='FixtureAPIClient.swift'; then
  echo 'Potential committed credential in iOS sources.' >&2
  exit 1
fi

if grep -Eq 'addScriptMessageHandler' apps/ios/Sources/Preview/HostilePreviewWebView.swift; then
  echo 'Hostile preview must not expose a native JavaScript bridge.' >&2
  exit 1
fi
grep -Eq 'websiteDataStore = \.nonPersistent\(\)' apps/ios/Sources/Preview/HostilePreviewWebView.swift
grep -Eq 'async -> WKNavigationActionPolicy' apps/ios/Sources/Preview/HostilePreviewWebView.swift
grep -Fq 'requestMediaCapturePermissionFor' apps/ios/Sources/Preview/HostilePreviewWebView.swift
grep -Fq 'decisionHandler(.deny)' apps/ios/Sources/Preview/HostilePreviewWebView.swift
grep -Fq '#details' apps/ios/Tests/PreviewOriginPolicyTests.swift
grep -Fq 'XCTAssertTrue(policy.permits(withFragment))' apps/ios/Tests/PreviewOriginPolicyTests.swift
grep -Fq 'terminalHistories' apps/ios/Sources/Security/EncryptedOfflineCache.swift
grep -Fq 'destroyKey()' apps/ios/Sources/Security/EncryptedOfflineCache.swift
grep -Eq 'isExcludedFromBackup = true' apps/ios/Sources/Security/EncryptedOfflineCache.swift
grep -Fq 'disconnect(ifCurrent:' apps/ios/Sources/Terminal/TerminalWebSocketClient.swift
grep -Fq 'guard task === socket else { break }' apps/ios/Sources/Terminal/TerminalWebSocketClient.swift
grep -Fq 'TerminalFrameFlags.idempotentInput' apps/ios/Sources/Terminal/TerminalSessionModel.swift
grep -Fq 'TerminalFrameFlags.inputReceipt' apps/ios/Sources/Terminal/TerminalSessionModel.swift
grep -Fq 'TerminalFrameFlags.inputReceiptConfirmed' apps/ios/Sources/Terminal/TerminalSessionModel.swift
grep -Fq '(error as? ClientError) == .unauthorized' apps/ios/Sources/Terminal/TerminalSessionModel.swift
grep -Fq 'reconnectToken = nil' apps/ios/Sources/Terminal/TerminalSessionModel.swift
grep -Fq 'renderer.resetForReplay()' apps/ios/Sources/Terminal/TerminalSessionModel.swift
grep -Fq 'resetTerminalHistory' apps/ios/Sources/Terminal/TerminalSessionModel.swift
grep -Fq 'mayRefresh: request.reconnectToken == nil' apps/ios/Sources/Networking/HTTPAPIClient.swift
grep -Eq '\.task\(id: model\.network\.isConnected\)' apps/ios/Sources/Features/Terminal/TerminalWorkspaceView.swift
grep -Fq 'cp Package.resolved' scripts/generate-ios-project.sh

echo 'iOS static policy checks passed. Swift compilation requires the hosted Xcode gate; device-only behavior remains owner-gated.'
