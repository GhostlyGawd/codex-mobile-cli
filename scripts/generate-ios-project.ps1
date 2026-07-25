$ErrorActionPreference = 'Stop'

$expectedXcodeGen = '2.45.4'
$root = Split-Path -Parent $PSScriptRoot
$xcodegen = Get-Command xcodegen -ErrorAction SilentlyContinue
if (-not $xcodegen) {
    throw "xcodegen $expectedXcodeGen is required. Project generation and Xcode builds are Mac-gated."
}

$versionText = & xcodegen --version
if ($versionText -notmatch [regex]::Escape($expectedXcodeGen)) {
    throw "Expected XcodeGen $expectedXcodeGen, found: $versionText"
}

Push-Location (Join-Path $root 'apps/ios')
try {
    Copy-Item (Join-Path $root 'packages/api-contract/openapi.yaml') 'Sources/GeneratedAPI/openapi.yaml' -Force
    & xcodegen generate --spec project.yml
    if ($LASTEXITCODE -ne 0) { throw "XcodeGen failed with exit code $LASTEXITCODE" }
    $resolvedDirectory = Join-Path (Get-Location) 'CodexMobile.xcodeproj/project.xcworkspace/xcshareddata/swiftpm'
    New-Item -ItemType Directory -Path $resolvedDirectory -Force | Out-Null
    Copy-Item 'Package.resolved' (Join-Path $resolvedDirectory 'Package.resolved') -Force
} finally {
    Pop-Location
}
