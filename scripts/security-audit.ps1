$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$output = if ($env:OUTPUT_DIRECTORY) { $env:OUTPUT_DIRECTORY } else { Join-Path $root 'artifacts/supply-chain' }
New-Item -ItemType Directory -Force -Path $output | Out-Null

foreach ($tool in @('syft', 'trivy', 'gitleaks', 'go', 'python')) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "$tool is required at the version pinned in .tool-versions"
    }
}

$trivyVersion = (trivy --version --format json | ConvertFrom-Json).Version
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
if ($trivyVersion -ne '0.72.0') {
    throw "trivy 0.72.0 is required; found $trivyVersion"
}
$syftVersion = (syft version --output json | ConvertFrom-Json).version
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
if ($syftVersion -ne '1.46.0') {
    throw "syft 1.46.0 is required; found $syftVersion"
}

Push-Location $root
try {
    python scripts/generate-supply-chain.py --check
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    gitleaks dir . --no-banner --redact --exit-code 1
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    trivy filesystem --scanners 'misconfig,secret,license' --license-full `
        --ignorefile .trivyignore.yaml --skip-dirs .git `
        --skip-dirs tmp --skip-dirs artifacts --skip-dirs coverage `
        --skip-dirs infra/tests/__pycache__ `
        --skip-files infra/workspace/Dockerfile.dockerignore `
        --skip-dirs infra/coder/templates/codex-mobile-envbuilder/.terraform `
        --exit-code 1 --severity 'HIGH,CRITICAL' .
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    syft scan dir:. --exclude '**/.git/**' --exclude '**/.terraform/**' `
        --exclude '**/__pycache__/**' --exclude '**/.cache/**' --exclude '**/artifacts/**' `
        --exclude '**/tmp/**' --exclude '**/coverage/**' `
        --output "cyclonedx-json=$output/syft-source.cdx.json"
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Push-Location services/control-plane
    try {
        go run github.com/google/go-licenses/v2@v2.0.1 report ./... |
            Set-Content -Encoding utf8 (Join-Path $output 'go-licenses.csv')
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    } finally {
        Pop-Location
    }
    Write-Host "Security and supply-chain audit passed. Ephemeral detailed reports: $output"
    Write-Host 'Built OCI images still require a separate trivy image scan on a Docker/Podman host.'
} finally {
    Pop-Location
}
