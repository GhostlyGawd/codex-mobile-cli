$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$ios = Join-Path $root 'apps/ios'

function Assert-Contains([string]$Path, [string]$Pattern, [string]$Message) {
    $content = Get-Content -Raw $Path
    if ($content -notmatch $Pattern) { throw $Message }
}

Assert-Contains (Join-Path $ios 'project.yml') 'minimumXcodeGenVersion:\s*2\.45\.4' 'XcodeGen must remain pinned to 2.45.4.'
Assert-Contains (Join-Path $ios 'project.yml') 'xcodeVersion:\s*"26\.6"' 'Xcode must remain pinned to 26.6.'
Assert-Contains (Join-Path $ios 'project.yml') 'exactVersion:\s*1\.14\.0' 'SwiftTerm must remain pinned to 1.14.0.'
Assert-Contains (Join-Path $ios 'project.yml') 'exactVersion:\s*0\.5\.2' 'Runestone must remain pinned to 0.5.2.'
Assert-Contains (Join-Path $ios 'project.yml') 'exactVersion:\s*0\.1\.10' 'TreeSitterLanguages must remain pinned to 0.1.10.'
Assert-Contains (Join-Path $ios 'project.yml') 'SwiftOpenAPIGenerator:[\s\S]*exactVersion:\s*1\.11\.1' 'Swift OpenAPI Generator must remain pinned to 1.11.1.'
Assert-Contains (Join-Path $ios 'project.yml') 'OpenAPIRuntime:[\s\S]*exactVersion:\s*1\.11\.0' 'Swift OpenAPI Runtime must remain pinned to 1.11.0.'
Assert-Contains (Join-Path $ios 'project.yml') 'buildToolPlugins:[\s\S]*plugin:\s*OpenAPIGenerator' 'The native target must compile a generated OpenAPI client.'
Assert-Contains (Join-Path $ios 'project.yml') 'deploymentTarget:\s*"17\.0"' 'The iOS deployment target must remain 17.0.'
Assert-Contains (Join-Path $ios 'project.yml') 'PRODUCT_NAME:\s*CodexMobile' 'The executable product name must remain stable for the unit-test host.'
Assert-Contains (Join-Path $ios 'project.yml') 'CFBundleDisplayName:\s*\$\(APP_DISPLAY_NAME\)' 'The user-facing app name must remain separate from the executable product name.'
Assert-Contains (Join-Path $ios 'Package.resolved') '592434a103a4d1ab83e14f87ac6eef569dd7a99d' 'Runestone lockfile revision changed.'
Assert-Contains (Join-Path $ios 'Package.resolved') '849e8a4f3d6f79ddee07152400137f1370c32621' 'SwiftTerm lockfile revision changed.'
Assert-Contains (Join-Path $ios 'Package.resolved') '15cf3a9ec3ab95e0d058b7df9f35619123c9e02d' 'TreeSitterLanguages lockfile revision changed.'
Assert-Contains (Join-Path $ios 'Package.resolved') '73997cc62c2193d5046e431c9d546119dda14502' 'Swift OpenAPI Generator lockfile revision changed.'
Assert-Contains (Join-Path $ios 'Package.resolved') 'f039fa6d6338aab5164f3d1be16281524c9a8f89' 'Swift OpenAPI Runtime lockfile revision changed.'

$appIconContents = Join-Path $ios 'Resources/Assets.xcassets/AppIcon.appiconset/Contents.json'
$appIcon = Join-Path $ios 'Resources/Assets.xcassets/AppIcon.appiconset/AppIcon.png'
Assert-Contains $appIconContents '"filename"\s*:\s*"AppIcon\.png"' 'AppIcon Contents.json must reference AppIcon.png.'
Assert-Contains $appIconContents '"size"\s*:\s*"1024x1024"' 'AppIcon must declare the universal 1024x1024 source size.'
if (-not (Test-Path -LiteralPath $appIcon -PathType Leaf) -or (Get-Item -LiteralPath $appIcon).Length -le 24) {
    throw 'The 1024x1024 PNG app-icon asset is missing.'
}
$iconBytes = [IO.File]::ReadAllBytes($appIcon)
$pngSignature = [byte[]](0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A)
if ($iconBytes.Length -lt 33 -or (Compare-Object $pngSignature $iconBytes[0..7])) {
    throw 'AppIcon.png must be a valid PNG.'
}
function Read-PNGBigEndianUInt32([byte[]]$Bytes, [int]$Offset) {
    return ([uint32]$Bytes[$Offset] -shl 24) -bor
        ([uint32]$Bytes[$Offset + 1] -shl 16) -bor
        ([uint32]$Bytes[$Offset + 2] -shl 8) -bor
        [uint32]$Bytes[$Offset + 3]
}
if ([Text.Encoding]::ASCII.GetString($iconBytes, 12, 4) -ne 'IHDR' -or
    (Read-PNGBigEndianUInt32 $iconBytes 16) -ne 1024 -or
    (Read-PNGBigEndianUInt32 $iconBytes 20) -ne 1024 -or
    $iconBytes[24] -ne 8 -or $iconBytes[25] -ne 2 -or
    $iconBytes[26] -ne 0 -or $iconBytes[27] -ne 0 -or $iconBytes[28] -ne 0) {
    throw 'AppIcon.png must be a non-interlaced 1024x1024, 8-bit truecolor PNG without alpha.'
}
$chunkOffset = 8
while ($chunkOffset -lt $iconBytes.Length) {
    if ($chunkOffset + 12 -gt $iconBytes.Length) { throw 'AppIcon.png has a truncated PNG chunk.' }
    $chunkLength = [uint64](Read-PNGBigEndianUInt32 $iconBytes $chunkOffset)
    $chunkType = [Text.Encoding]::ASCII.GetString($iconBytes, $chunkOffset + 4, 4)
    if ($chunkType -eq 'tRNS') { throw 'AppIcon.png must not contain transparency.' }
    $nextOffset = [uint64]$chunkOffset + 12 + $chunkLength
    if ($nextOffset -gt [uint64]$iconBytes.Length) { throw 'AppIcon.png has an invalid PNG chunk length.' }
    $chunkOffset = [int]$nextOffset
}
if ($chunkOffset -ne $iconBytes.Length) { throw 'AppIcon.png has trailing or malformed PNG data.' }

$terminal = Join-Path $ios 'Sources/Terminal/TerminalProtocol.swift'
Assert-Contains $terminal 'headerLength\s*=\s*36' 'Terminal header must remain 36 bytes.'
Assert-Contains $terminal 'magic\s*=\s*Data\(\[0x43, 0x4D\]\)' 'Terminal magic must remain CM.'
Assert-Contains $terminal 'case attention\s*=\s*12' 'Terminal kinds must match terminal-v1.md.'
Assert-Contains $terminal 'idempotentInput:\s*UInt16\s*=\s*1\s*<<\s*1' 'Terminal composer input must retain its application-level idempotency flag.'
Assert-Contains $terminal 'inputReceipt:\s*UInt16\s*=\s*1\s*<<\s*2' 'Terminal input receipts must remain distinct from output acknowledgements.'
Assert-Contains $terminal 'inputReceiptConfirmed:\s*UInt16\s*=\s*1\s*<<\s*3' 'Terminal receipt confirmations must remain distinct and client directed.'

$openAPI = Join-Path $root 'packages/api-contract/openapi.yaml'
$generatedOpenAPI = Join-Path $ios 'Sources/GeneratedAPI/openapi.yaml'
if ((Get-FileHash $openAPI -Algorithm SHA256).Hash -ne (Get-FileHash $generatedOpenAPI -Algorithm SHA256).Hash) {
    throw 'The iOS build-plugin OpenAPI input is stale. Run scripts/generate-ios-project before building.'
}
Assert-Contains (Join-Path $ios 'Sources/GeneratedAPI/openapi-generator-config.yaml') 'generate:\s*[\r\n]+\s*- types[\s\S]*- client' 'The OpenAPI plugin must generate typed models and a client.'
Assert-Contains $openAPI 'maximum_frame_bytes:\s*\{[^\r\n]*maximum:\s*1048576' 'OpenAPI terminal frames must remain capped at 1 MiB.'
Assert-Contains $openAPI 'memory_gi_b:' 'OpenAPI memory_gi_b spelling changed.'
Assert-Contains $openAPI 'writable_disk_gi_b:' 'OpenAPI writable_disk_gi_b spelling changed.'
Assert-Contains $openAPI 'requested_disk_gi_b:' 'OpenAPI requested_disk_gi_b spelling changed.'
Assert-Contains $openAPI 'requested_disk_gi_b:\s*\{oneOf:\s*\[\{type:\s*integer,\s*minimum:\s*8,\s*maximum:\s*16,\s*default:\s*12\}' 'OpenAPI workspace disk bounds/default changed.'
Assert-Contains $openAPI 'expected_e_tag:' 'OpenAPI expected_e_tag spelling changed.'
Assert-Contains $openAPI 'SecretValue:\s*\{type:\s*string,\s*minLength:\s*4,\s*maxLength:\s*8192,\s*writeOnly:\s*true\}' 'Secret values must remain 4-8192 bytes so mandatory terminal redaction can fail closed.'
Assert-Contains $openAPI 'value_bytes:\s*\{type:\s*integer,\s*minimum:\s*4,\s*maximum:\s*8192\}' 'Secret metadata bounds must match the accepted plaintext contract.'
Assert-Contains $openAPI 'enum:\s*\[sandbox, production\]' 'OpenAPI APNs environments must remain sandbox and production.'

$expectedRoutes = @(
    'GET /v1/capabilities getCapabilities'
    'POST /v1/auth/passkeys/registration/options beginPasskeyRegistration'
    'POST /v1/auth/passkeys/registration/verify finishPasskeyRegistration'
    'POST /v1/auth/passkeys/authentication/options beginPasskeyAuthentication'
    'POST /v1/auth/passkeys/authentication/verify finishPasskeyAuthentication'
    'POST /v1/passkeys/registration/options beginAdditionalPasskeyRegistration'
    'POST /v1/passkeys/registration/verify finishAdditionalPasskeyRegistration'
    'GET /v1/passkeys listPasskeys'
    'DELETE /v1/passkeys/{credential_id} revokePasskey'
    'POST /v1/auth/session/refresh refreshSession'
    'DELETE /v1/auth/session revokeCurrentSession'
    'GET /v1/devices listDevices'
    'DELETE /v1/devices/{device_id} revokeDevice'
    'GET /v1/secrets listSecrets'
    'POST /v1/secrets createSecret'
    'PUT /v1/secrets/{secret_id} updateSecret'
    'DELETE /v1/secrets/{secret_id} deleteSecret'
    'GET /v1/connections getConnections'
    'DELETE /v1/connections/github/{installation_id} disconnectGitHub'
    'GET /v1/repositories listRepositories'
    'GET /v1/workspaces listWorkspaces'
    'POST /v1/workspaces createWorkspace'
    'GET /v1/workspaces/{workspace_id} getWorkspace'
    'POST /v1/workspaces/{workspace_id}/actions performWorkspaceAction'
    'GET /v1/workspaces/{workspace_id}/secret-grants listWorkspaceSecretGrants'
    'PUT /v1/workspaces/{workspace_id}/secret-grants/{secret_id} grantWorkspaceSecret'
    'DELETE /v1/workspaces/{workspace_id}/secret-grants/{secret_id} revokeWorkspaceSecret'
    'GET /v1/workspaces/{workspace_id}/connections/codex getCodexConnection'
    'DELETE /v1/workspaces/{workspace_id}/connections/codex disconnectCodex'
    'GET /v1/activity listActivity'
    'GET /v1/approvals/{approval_id} getApproval'
    'POST /v1/approvals/{approval_id}/decision resolveApproval'
    'GET /v1/workspaces/{workspace_id}/terminal-tabs listTerminalTabs'
    'POST /v1/workspaces/{workspace_id}/terminal-tabs createTerminalTab'
    'PUT /v1/workspaces/{workspace_id}/terminal-tabs/order reorderTerminalTabs'
    'PATCH /v1/workspaces/{workspace_id}/terminal-tabs/{tab_id} renameTerminalTab'
    'DELETE /v1/workspaces/{workspace_id}/terminal-tabs/{tab_id} closeTerminalTab'
    'POST /v1/workspaces/{workspace_id}/terminal-tabs/{tab_id}/connection createTerminalConnection'
    'POST /v1/workspaces/{workspace_id}/terminal-tabs/{tab_id}/attachments stageTerminalAttachments'
    'GET /v1/workspaces/{workspace_id}/files getFileTree'
    'GET /v1/workspaces/{workspace_id}/file-search searchFiles'
    'GET /v1/workspaces/{workspace_id}/file getFile'
    'PUT /v1/workspaces/{workspace_id}/file saveFile'
    'GET /v1/workspaces/{workspace_id}/git/status getGitStatus'
    'GET /v1/workspaces/{workspace_id}/git/diff getGitDiff'
    'POST /v1/workspaces/{workspace_id}/git/stage setGitStaged'
    'POST /v1/workspaces/{workspace_id}/git/commits createCommit'
    'POST /v1/workspaces/{workspace_id}/git/pull pullWorkspace'
    'POST /v1/workspaces/{workspace_id}/git/push pushWorkspace'
    'POST /v1/workspaces/{workspace_id}/git/discard discardGitChanges'
    'POST /v1/workspaces/{workspace_id}/pull-requests createPullRequest'
    'GET /v1/workspaces/{workspace_id}/checkpoints listCheckpoints'
    'POST /v1/workspaces/{workspace_id}/checkpoints/{checkpoint_id}/restore-file restoreCheckpointFile'
    'POST /v1/workspaces/{workspace_id}/checkpoints/{checkpoint_id}/restore-workspace restoreCheckpointWorkspace'
    'GET /v1/workspaces/{workspace_id}/previews listPreviews'
    'POST /v1/workspaces/{workspace_id}/previews/access createPreviewAccess'
    'DELETE /v1/workspaces/{workspace_id}/previews/{preview_id}/access revokePreviewAccess'
    'GET /v1/maintenance getMaintenance'
    'POST /v1/maintenance/schedule scheduleMaintenance'
    'DELETE /v1/maintenance/{maintenance_id} cancelMaintenance'
    'POST /v1/maintenance/{maintenance_id}/actions advanceMaintenance'
    'GET /v1/diagnostics getDiagnostics'
    'GET /v1/settings getSettings'
    'PUT /v1/settings updateSettings'
    'PUT /v1/devices/push registerPushDevice'
)
$actualRoutes = @()
$currentPath = $null
$currentMethod = $null
foreach ($line in Get-Content $openAPI) {
    if ($line -match '^  (/[^:]+):') { $currentPath = $Matches[1] }
    if ($line -match '^    (get|post|put|patch|delete):') { $currentMethod = $Matches[1].ToUpperInvariant() }
    if ($line -match '^      operationId:\s*(\S+)') {
        $actualRoutes += "$currentMethod $currentPath $($Matches[1])"
    }
}
if ($actualRoutes.Count -ne 65) {
    throw "OpenAPI must expose exactly 65 operations; found $($actualRoutes.Count)."
}
$routeDifference = Compare-Object -ReferenceObject $expectedRoutes -DifferenceObject $actualRoutes
if ($routeDifference) {
    throw "OpenAPI method/path/operationId contract changed:`n$($routeDifference | Out-String)"
}

$clientText = Get-Content -Raw (Join-Path $ios 'Sources/Networking/HTTPAPIClient.swift')
$clientRouteMatches = [regex]::Matches(
    $clientText,
    'method:\s*"(?<method>GET|POST|PUT|PATCH|DELETE)"\s*,\s*path:\s*"(?<path>v1/[^"]+)"'
)
$actualClientRoutes = @($clientRouteMatches | ForEach-Object {
    $normalizedPath = [regex]::Replace($_.Groups['path'].Value, '\\\([^)]+\)', '{}')
    "$($_.Groups['method'].Value) /$normalizedPath"
} | Sort-Object)
$expectedClientRoutes = @($expectedRoutes | ForEach-Object {
    $parts = $_.Split(' ', 3)
    "$($parts[0]) $([regex]::Replace($parts[1], '\{[^}]+\}', '{}'))"
} | Sort-Object)
if ($actualClientRoutes.Count -ne 65) {
    throw "The native HTTP client must implement all 65 contract routes; found $($actualClientRoutes.Count)."
}
$clientRouteDifference = Compare-Object -ReferenceObject $expectedClientRoutes -DifferenceObject $actualClientRoutes
if ($clientRouteDifference) {
    throw "Native HTTP client method/path coverage differs from OpenAPI:`n$($clientRouteDifference | Out-String)"
}

$codingTests = Join-Path $ios 'Tests/JSONCodingContractTests.swift'
Assert-Contains $codingTests 'memory_gi_b' 'JSON coding tests must cover memory_gi_b.'
Assert-Contains $codingTests 'writable_disk_gi_b' 'JSON coding tests must cover writable_disk_gi_b.'
Assert-Contains $codingTests 'requested_disk_gi_b' 'JSON coding tests must cover requested_disk_gi_b.'
Assert-Contains $codingTests 'expected_e_tag' 'JSON coding tests must cover expected_e_tag.'
Assert-Contains $codingTests 'websocket_url' 'JSON coding tests must cover websocket_url.'
Assert-Contains $codingTests 'client_data_json' 'JSON coding tests must cover client_data_json.'
Assert-Contains $codingTests 'allowed_credential_ids' 'JSON coding tests must cover plural ID keys.'
$newWorkspaceUI = Join-Path $ios 'Sources/Features/Workspaces/NewWorkspaceView.swift'
Assert-Contains $newWorkspaceUI 'in:\s*8\.\.\.16,\s*step:\s*4' 'Native workspace disk stepper must expose only 8-16 GiB.'
Assert-Contains $newWorkspaceUI 'autonomy\s*=\s*defaults\.autonomyDefault' 'Workspace creation must honor the saved autonomy default.'
Assert-Contains $newWorkspaceUI 'retention\s*=\s*defaults\.retentionDefault' 'Workspace creation must honor the saved retention default.'
$settingsUI = Join-Path $ios 'Sources/Features/Settings/SettingsView.swift'
Assert-Contains $settingsUI 'isShowingFullAccessDefaultConfirmation' 'Selecting Full Access as the global default must require confirmation.'
Assert-Contains $settingsUI 'Full Access lets Codex act without approval' 'Global Full Access must carry a persistent risk explanation.'
$workspaceUI = Join-Path $ios 'Sources/Features/Workspaces/WorkspaceScreen.swift'
Assert-Contains $workspaceUI 'action:\s*\.updateAutonomy' 'Workspace autonomy changes must call the dedicated server action.'
Assert-Contains $workspaceUI 'detail\.summary\.lifecycle\s*==\s*\.suspended' 'Workspace autonomy changes must be limited to the suspended boundary.'
Assert-Contains $workspaceUI 'showsFullAccessConfirmation' 'Workspace Full Access changes must require explicit confirmation.'
Assert-Contains $workspaceUI 'Button\("Use Full Access",\s*role:\s*\.destructive\)' 'Workspace Full Access confirmation must be destructive.'
Assert-Contains $workspaceUI 'matching network policy and managed Codex configuration' 'Workspace autonomy UI must explain the atomic resume boundary.'
Assert-Contains $openAPI 'update_autonomy' 'OpenAPI must expose the suspended workspace autonomy transition.'
$appModel = Join-Path $ios 'Sources/App/AppModel.swift'
Assert-Contains $appModel 'pendingDeepLinkRoute = route' 'Validated deep links must wait for authenticated navigation instead of being dropped during session restore.'
Assert-Contains $appModel 'applyPendingDeepLinkIfReady' 'Pending deep links must be applied after session bootstrap or authentication.'
$appEntry = Join-Path $ios 'Sources/App/CodexMobileApp.swift'
Assert-Contains $appEntry 'consumeColdStartDeepLink' 'The app entry point must drain retained notification links.'
Assert-Contains $appEntry 'await model.bootstrap' 'The app entry point must bootstrap the authenticated session before final deep-link delivery.'
$pushNotifications = Join-Path $ios 'Sources/Notifications/PushNotifications.swift'
Assert-Contains $pushNotifications 'remoteNotification' 'Cold-launch APNs payloads must be captured before SwiftUI subscriptions are installed.'
Assert-Contains $pushNotifications 'coldStartDeepLinks.store' 'Notification deep links must be retained until the app model can consume them.'
$coldStartTests = Join-Path $ios 'Tests/ColdStartDeepLinkTests.swift'
Assert-Contains $coldStartTests 'testValidatedLinkWaitsForSessionBootstrap' 'iOS tests must cover a deep link arriving before session bootstrap.'
Assert-Contains (Join-Path $root 'services/control-plane/internal/application/passkeys.go') 'StructuredApprovalsAvailable: true' 'The control plane must advertise its internally structured setup approvals.'
$hostileDisplay = Join-Path $ios 'Sources/Security/HostileDisplayText.swift'
Assert-Contains $hostileDisplay '0x2028...0x202E' 'Hostile display text must escape Unicode line and bidirectional override controls.'
Assert-Contains $hostileDisplay '0x2060...0x206F' 'Hostile display text must escape invisible formatting and isolate controls.'
Assert-Contains $hostileDisplay 'scalar.value == 0x5C' 'Literal backslashes must be escaped so hostile names cannot imitate visible Unicode escapes.'
$hostileDisplayTests = Join-Path $ios 'Tests/HostileDisplayTextTests.swift'
Assert-Contains $hostileDisplayTests 'testEscapesControlsBidiOverridesAndLiteralEscapePrefixes' 'iOS tests must cover hostile filename display escaping.'
Assert-Contains $hostileDisplayTests 'display sanitization must not mutate the operational path' 'Display sanitization tests must preserve raw API paths.'
$filesUI = Join-Path $ios 'Sources/Features/Files/WorkspaceFilesView.swift'
Assert-Contains $filesUI 'HostileDisplayText[.]sanitized[(]result[.]path[)]' 'Repository search paths must be sanitized only at display time.'
Assert-Contains $filesUI 'path: result[.]path' 'File API navigation must retain the raw repository path.'
$gitUI = Join-Path $ios 'Sources/Features/Git/WorkspaceGitView.swift'
Assert-Contains $gitUI 'HostileDisplayText[.]sanitized[(]change[.]path[)]' 'Git filename labels must be sanitized.'
Assert-Contains $gitUI 'path: change[.]path, staged: staged' 'Git API operations must retain the raw repository path.'
$terminalModel = Join-Path $ios 'Sources/Terminal/TerminalSessionModel.swift'
Assert-Contains $terminalModel 'terminalTitle = HostileDisplayText.sanitized' 'Terminal-controlled window titles must be sanitized before display state.'
Assert-Contains (Join-Path $ios 'Tests/TerminalSessionModelTests.swift') 'testTerminalDerivedTitlesAndCloseReasonsAreSafeDisplayText' 'Terminal tests must cover hostile title and close-reason labels.'
$rootView = Join-Path $ios 'Sources/App/RootView.swift'
Assert-Contains $appModel 'isServerUnavailable = Self.isServerAvailabilityFailure' 'Server reachability must be tracked independently from device network reachability.'
Assert-Contains $rootView 'Server unavailable — cached data is read only' 'The native app must persistently distinguish an unreachable server from device offline state.'
Assert-Contains $rootView 'This app cannot recreate the server' 'The server-unavailable surface must explain the VPS-loss recovery boundary.'
Assert-Contains $codingTests 'repository_id' 'JSON coding tests must cover secret repository scope.'
Assert-Contains $codingTests 'content_base64' 'JSON coding tests must cover attachment base64 encoding.'

$secretUI = Join-Path $ios 'Sources/Features/Settings/SecretsSettingsView.swift'
Assert-Contains $secretUI 'SecureField\("Secret value"' 'Secret values must use a secure entry field.'
Assert-Contains $secretUI 'value\s*=\s*""' 'Secret UI must clear its transient plaintext field.'
Assert-Contains $secretUI '\(4\s*\.\.\.\s*8192\)\.contains\(value\.utf8\.count\)' 'Secret UI must enforce the server 4-8192-byte boundary.'
$offlineCache = Get-Content -Raw (Join-Path $ios 'Sources/Security/EncryptedOfflineCache.swift')
if ($offlineCache -match 'SecretMetadata|WorkspaceSecretGrant|CreateSecretRequest|UpdateSecretRequest|AttachmentUpload|StagedAttachment') {
    throw 'Secret or attachment data must not enter the offline cache.'
}

$composerStore = Join-Path $ios 'Sources/Security/EncryptedComposerStore.swift'
Assert-Contains $composerStore 'AES\.GCM\.seal' 'Composer drafts and history must use authenticated encryption.'
Assert-Contains $composerStore 'KeychainComposerKeyProvider' 'Composer encryption keys must be Keychain protected.'
Assert-Contains $composerStore 'maximumHistoryCount\s*=\s*50' 'Composer history must remain bounded.'
$composer = Join-Path $ios 'Sources/Features/Terminal/TerminalComposerView.swift'
Assert-Contains $composer 'PhotosPicker\(' 'Composer must use the system Photos picker.'
Assert-Contains $composer '\.fileImporter\(' 'Composer must use the system file importer.'
Assert-Contains $composer 'try await send\(value, uploads\)[\s\S]*recordSuccessfulSend' 'Composer may clear/history a draft only after the terminal send succeeds.'
Assert-Contains $openAPI 'MaximumTotalBytes|Decoded content is capped at 8 MiB' 'OpenAPI must document the bounded attachment batch.'

$coding = Join-Path $ios 'Sources/Networking/Coding.swift'
Assert-Contains $coding 'keyEncodingStrategy\s*=\s*\.custom' 'JSON encoding must use the exact contract key mapper.'
Assert-Contains $coding 'keyDecodingStrategy\s*=\s*\.custom' 'JSON decoding must preserve Swift acronym spellings.'

$editor = Join-Path $ios 'Sources/Editor/RunestoneAdapter.swift'
Assert-Contains $editor 'TextViewState\(text:\s*document\.content,\s*theme:\s*DefaultTheme\(\),\s*language:' 'Runestone must receive a Tree-sitter language for syntax highlighting.'

$fixture = Join-Path $ios 'Sources/PreviewSupport/FixtureAPIClient.swift'
$fixtureText = Get-Content -Raw $fixture
if (-not $fixtureText.TrimStart().StartsWith('#if DEBUG') -or -not $fixtureText.TrimEnd().EndsWith('#endif')) {
    throw 'Fixture API must be DEBUG-only.'
}

$sourceFiles = Get-ChildItem (Join-Path $ios 'Sources') -Recurse -Filter '*.swift' |
    Where-Object { $_.FullName -notlike '*\PreviewSupport\*' }
$forbidden = '(ghp_[A-Za-z0-9]{20,}|github_pat_|sk-[A-Za-z0-9]{20,}|BEGIN [A-Z ]*PRIVATE KEY|api[_-]?key\s*[=:]\s*["''][^"'']+)'
foreach ($file in $sourceFiles) {
    $matches = Select-String -Path $file.FullName -Pattern $forbidden -AllMatches
    if ($matches) { throw "Potential committed credential in $($file.FullName)" }
}

$webView = Get-Content -Raw (Join-Path $ios 'Sources/Preview/HostilePreviewWebView.swift')
if ($webView -match 'addScriptMessageHandler') {
    throw 'Hostile preview must not expose a native JavaScript bridge.'
}
if ($webView -notmatch 'websiteDataStore\s*=\s*\.nonPersistent\(\)') {
    throw 'Hostile preview must use a non-persistent website data store.'
}
if ($webView -notmatch 'async\s*->\s*WKNavigationActionPolicy') {
    throw 'Hostile preview navigation must use the Swift concurrency policy callback.'
}
if ($webView -notmatch 'requestMediaCapturePermissionFor' -or $webView -notmatch 'decisionHandler\(\.deny\)') {
    throw 'Hostile preview must explicitly deny device media permissions.'
}
$previewPolicyTests = Join-Path $ios 'Tests/PreviewOriginPolicyTests.swift'
Assert-Contains $previewPolicyTests '#details' 'Preview-origin tests must cover same-origin fragment navigation.'
Assert-Contains $previewPolicyTests 'XCTAssertTrue\(policy\.permits\(withFragment\)\)' 'Same-origin preview fragments must remain permitted.'

$cache = Join-Path $ios 'Sources/Security/EncryptedOfflineCache.swift'
Assert-Contains $cache 'terminalHistories' 'Encrypted offline cache must include bounded terminal history.'
Assert-Contains $cache 'destroyKey\(\)' 'Signing out must cryptographically erase the offline-cache key.'
Assert-Contains $cache 'isExcludedFromBackup\s*=\s*true' 'Offline cache must remain excluded from device backups.'
$cacheRedactor = Join-Path $ios 'Sources/Terminal/TerminalCacheRedactor.swift'
Assert-Contains $cacheRedactor 'private var pending = Data\(\)' 'Terminal cache redaction must retain split output until a safe record boundary.'
Assert-Contains $cacheRedactor 'sensitiveSignals\.contains' 'Terminal cache redaction must fail closed on credential-labelled records.'
Assert-Contains $cacheRedactor '\[A-Za-z0-9_\+/=-\]\{32,' 'Terminal cache redaction must conservatively remove long opaque token shapes.'
$terminalSession = Join-Path $ios 'Sources/Terminal/TerminalSessionModel.swift'
Assert-Contains $terminalSession 'cacheRedactor\.process\(output\)' 'Raw terminal bytes must pass through the cache-only redactor before persistence.'
Assert-Contains $terminalSession 'renderer\.receiveOutput\(safeOutput\)[\s\S]*recordCachedOutput\(sequence:\s*frame\.sequence,\s*output:\s*safeOutput\)' 'Cache redaction must not alter the authoritative live terminal renderer.'
Assert-Contains $terminalSession 'TerminalFrameFlags\.idempotentInput' 'Composer input must request application-level idempotency.'
Assert-Contains $terminalSession 'TerminalFrameFlags\.inputReceipt' 'Composer drafts must wait for a server input receipt.'
Assert-Contains $terminalSession 'TerminalFrameFlags\.inputReceiptConfirmed[\s\S]*rememberInputReceipt' 'The app must confirm receipt before treating composer delivery as complete.'
Assert-Contains $terminalSession 'requestedReconnectToken\s*!=\s*nil[\s\S]*ClientError\)\s*==\s*\.unauthorized[\s\S]*reconnectToken\s*=\s*nil' 'A rejected rotating reconnect token must fall back to the authenticated owner session.'
Assert-Contains $terminalSession 'renderer\.resetForReplay\(\)[\s\S]*resetTerminalHistory' 'Replay gaps must reset both the live renderer and encrypted cached history.'
$httpClient = Join-Path $ios 'Sources/Networking/HTTPAPIClient.swift'
Assert-Contains $httpClient 'mayRefresh:\s*request\.reconnectToken\s*==\s*nil' 'A stale reconnect token must reach the model after one authentication rejection.'

$socket = Join-Path $ios 'Sources/Terminal/TerminalWebSocketClient.swift'
Assert-Contains $socket 'disconnect\(ifCurrent:' 'Stale WebSocket termination must not close a newer connection.'
Assert-Contains $socket 'guard task === socket else \{ break \}' 'Stale WebSocket bytes must not enter a newer stream.'
$terminalWorkspace = Join-Path $ios 'Sources/Features/Terminal/TerminalWorkspaceView.swift'
Assert-Contains $terminalWorkspace '\.task\(id:\s*model\.network\.isConnected\)' 'Terminal tabs must resynchronize when connectivity changes.'

Assert-Contains (Join-Path $root 'scripts/generate-ios-project.ps1') 'Copy-Item\s+''Package\.resolved''' 'PowerShell generation must install the pinned Swift package lockfile.'
$iosWorkflow = Join-Path $root '.github/workflows/ios.yml'
Assert-Contains $iosWorkflow '-onlyUsePackageVersionsFromResolvedFile' 'Hosted Xcode must use only the checked-in resolved package versions.'
Assert-Contains $iosWorkflow '-skipPackagePluginValidation' 'Hosted Xcode must non-interactively enable the pinned OpenAPI build plugin.'

Write-Host 'iOS static policy checks passed. Swift compilation requires the hosted Xcode gate; device-only behavior remains owner-gated.'
