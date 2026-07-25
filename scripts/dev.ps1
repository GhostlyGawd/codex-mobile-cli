[CmdletBinding()]
param(
    [string]$EnvFile = ""
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not $EnvFile) { $EnvFile = Join-Path $repoRoot '.codex-mobile-development.env' }
$resolvedParent = (Resolve-Path (Split-Path -Parent $EnvFile) -ErrorAction Stop).Path
if (-not $resolvedParent.StartsWith($repoRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'EnvFile must stay beneath the repository for local development.'
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw 'Docker with Compose v2 is required.' }
docker compose version | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Docker Compose v2 is required.' }

if (-not (Test-Path -LiteralPath $EnvFile)) {
    Copy-Item -LiteralPath (Join-Path $repoRoot 'infra/env/development.env.example') -Destination $EnvFile
    Write-Host "Created ignored local configuration: $EnvFile"
}

$dataRoot = Join-Path $repoRoot '.data'
$secretsDir = Join-Path $repoRoot '.secrets'
@('postgres', 'coder', 'caddy/data', 'caddy/config') | ForEach-Object {
    New-Item -ItemType Directory -Force -Path (Join-Path $dataRoot $_) | Out-Null
}
New-Item -ItemType Directory -Force -Path $secretsDir | Out-Null

function New-Secret([int]$Bytes) {
    $buffer = [byte[]]::new($Bytes)
    [Security.Cryptography.RandomNumberGenerator]::Fill($buffer)
    return [Convert]::ToHexString($buffer).ToLowerInvariant()
}
function Write-NewSecret([string]$Name, [string]$Value) {
    $path = Join-Path $secretsDir $Name
    if (-not (Test-Path -LiteralPath $path)) {
        [IO.File]::WriteAllText($path, $Value + "`n", [Text.UTF8Encoding]::new($false))
    }
}

Write-NewSecret 'postgres_admin_password' (New-Secret 32)
$appPasswordPath = Join-Path $secretsDir 'app_db_password'
if (-not (Test-Path -LiteralPath $appPasswordPath)) {
    Write-NewSecret 'app_db_password' (New-Secret 32)
}
$appPassword = (Get-Content -Raw -LiteralPath $appPasswordPath).Trim()
Write-NewSecret 'coder_db_password' (New-Secret 32)
Write-NewSecret 'app_database_url' "postgresql://codex_app:$appPassword@postgres:5432/codex_app?sslmode=disable"
$key = [byte[]]::new(32)
[Security.Cryptography.RandomNumberGenerator]::Fill($key)
Write-NewSecret 'control_plane_master_key' ([Convert]::ToBase64String($key))
[Security.Cryptography.RandomNumberGenerator]::Fill($key)
Write-NewSecret 'session_pepper' ([Convert]::ToBase64String($key))
[Array]::Clear($key, 0, $key.Length)

$coderToken = Join-Path $secretsDir 'coder_api_token'
$env:REPO_ROOT = $repoRoot
$env:ENV_FILE = $EnvFile
$compose = @('compose', '--env-file', $EnvFile, '--file', (Join-Path $repoRoot 'infra/compose.yaml'))
if (-not (Test-Path -LiteralPath $coderToken) -or (Get-Item -LiteralPath $coderToken).Length -eq 0) {
    if (-not (Test-Path -LiteralPath $coderToken)) { [IO.File]::WriteAllText($coderToken, '') }
    & docker @compose up --detach postgres coder --wait --wait-timeout 180
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Write-Host 'Coder is available at http://127.0.0.1:7080 for its one-time local owner setup.'
    Write-Host "Create a least-privilege API token, write only that token to $coderToken,"
    Write-Host "set CODER_ORGANIZATION_ID and CODER_TEMPLATE_ID in $EnvFile, then rerun this command."
    Write-Host 'This browser ceremony cannot be automated without creating or disclosing a password.'
    exit 3
}

& docker @compose up --detach --build --wait --wait-timeout 300
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& docker @compose ps
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host 'Codex Mobile local stack is ready at http://localhost.'
