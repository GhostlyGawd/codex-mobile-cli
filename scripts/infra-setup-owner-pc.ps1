[CmdletBinding()]
param(
    [string]$Distribution = "Ubuntu",
    [string]$LinuxRepository = "/home/rhenm/src/codex-mobile-cli"
)

$ErrorActionPreference = "Stop"

$distributionRecord = Get-ChildItem -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss" |
    ForEach-Object { Get-ItemProperty -LiteralPath $_.PSPath } |
    Where-Object { $_.DistributionName -eq $Distribution }
if (@($distributionRecord).Count -ne 1) {
    throw "Expected exactly one registered WSL distribution named $Distribution."
}
$basePath = [System.IO.Path]::GetFullPath([string]$distributionRecord.BasePath)
$requiredRoot = [System.IO.Path]::GetFullPath("D:\Codex\WSL")
if (-not $basePath.StartsWith($requiredRoot + "\", [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "$Distribution is not stored beneath $requiredRoot (found $basePath)."
}
$vhd = Join-Path $basePath "ext4.vhdx"
if (-not (Test-Path -LiteralPath $vhd -PathType Leaf)) {
    throw "The D-backed WSL virtual disk is missing: $vhd"
}
if ((Get-Item -LiteralPath $vhd -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
    throw "The WSL virtual disk must not be a reparse point."
}

$computer = Get-CimInstance -ClassName Win32_ComputerSystem
if ([int64]$computer.TotalPhysicalMemory -lt 11GB) {
    throw "owner_pc_beta requires at least 11 GiB of usable physical host memory."
}
$d = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='D:'"
if ($null -eq $d -or [int64]$d.FreeSpace -lt 192GB) {
    throw "D: must have at least 192 GiB free before the 64 GiB image is initialized."
}

$probe = & wsl.exe -d $Distribution -u root -- test -f `
    "$LinuxRepository/scripts/infra-setup-owner-pc-wsl.sh"
if ($LASTEXITCODE -ne 0) {
    throw "The Linux-native repository is missing or stale at $LinuxRepository."
}
& wsl.exe -d $Distribution -u root -- env "REPO_ROOT=$LinuxRepository" `
    /bin/sh "$LinuxRepository/scripts/infra-setup-owner-pc-wsl.sh" --initialize
if ($LASTEXITCODE -ne 0) {
    throw "Owner-PC WSL initialization failed."
}

Write-Host "Owner-PC D-backed WSL foundation: PASS"
