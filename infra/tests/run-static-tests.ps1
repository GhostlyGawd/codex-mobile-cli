$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

Push-Location $repoRoot
try {
    python -m unittest discover -s infra/tests -p "test_*.py" -v
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    python scripts/check-billing-policy.py --repo-root $repoRoot --deployment-profile owner_pc_beta
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    Pop-Location
}
