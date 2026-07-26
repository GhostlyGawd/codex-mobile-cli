$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Push-Location $root
try {
    New-Item -ItemType Directory -Force -Path 'coverage' | Out-Null
    go work sync
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    # Go 1.26 rejects a workspace-relative module pattern from the repository
    # root. Run the equivalent module-local package pattern so verification also
    # works from a checkout outside GOPATH.
    go -C services/control-plane fmt ./...
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    go vet ./services/control-plane/...
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $cgoEnabled = (& go env CGO_ENABLED).Trim()
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $cc = (& go env CC).Trim()
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $ccCommand = if ($cc) { Get-Command (($cc -split '\s+')[0].Trim('"')) -ErrorAction SilentlyContinue } else { $null }
    if ($cgoEnabled -eq '1' -and $null -ne $ccCommand) {
        go test -race ./services/control-plane/...
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    } else {
        Write-Host 'SKIP: Go race detector requires CGO and an installed C compiler on Windows; the Linux CI job runs it.'
    }
    go test ./services/control-plane/... '-coverprofile=coverage/control-plane.out'
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    go test -tags=integration ./services/control-plane/... -run '^$'
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $goEnvironment = @{
        GOOS = [Environment]::GetEnvironmentVariable('GOOS', 'Process')
        GOARCH = [Environment]::GetEnvironmentVariable('GOARCH', 'Process')
        CGO_ENABLED = [Environment]::GetEnvironmentVariable('CGO_ENABLED', 'Process')
    }
    try {
        $env:GOOS = 'linux'
        $env:CGO_ENABLED = '0'
        foreach ($architecture in @('amd64', 'arm64')) {
            $env:GOARCH = $architecture
            go build -trimpath -buildvcs=false -o "coverage/control-plane-linux-$architecture" ./services/control-plane/cmd/control-plane
            if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
            go build -trimpath -buildvcs=false '-ldflags=-s -w' -o "coverage/workspace-helper-linux-$architecture" ./services/control-plane/cmd/workspace-helper
            if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        }
    } finally {
        foreach ($name in $goEnvironment.Keys) {
            if ($null -eq $goEnvironment[$name]) {
                Remove-Item "Env:$name" -ErrorAction SilentlyContinue
            } else {
                Set-Item "Env:$name" $goEnvironment[$name]
            }
        }
    }
    python ./scripts/verify-workspace-helper-checksums.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    python -I ./scripts/verify-envbuilder-source.py --static-only
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    & ./infra/tests/run-static-tests.ps1
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    & ./scripts/test-ios-static.ps1
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    python ./scripts/generate-supply-chain.py --check
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    python ./scripts/validate-release-artifacts.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Write-Host 'SKIP: Xcode 26.6/XcodeGen 2.45.4 iOS build requires a configured macOS host.'
} finally {
    Pop-Location
}
