<#
ClamAV 1.5.1 MSI install + config setup + freshclam
- Downloads MSI
- Installs to C:\Program Files\ClamAV (default)
- Converts conf_examples\*.conf.sample -> ClamAV\*.conf (removes Example line)
- Runs freshclam
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run PowerShell as Administrator."
    }
}

function Ensure-Dir([string]$Path) {
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Remove-ExampleLineAndWrite([string]$Source, [string]$Dest) {
    if (-not (Test-Path $Source)) { throw "Missing file: $Source" }

    $lines = Get-Content -Path $Source -ErrorAction Stop

    # Remove lines that are exactly "Example" or "# Example" (any whitespace allowed)
    $lines = $lines | Where-Object { $_ -notmatch '^\s*#?\s*Example\s*$' }

    Set-Content -Path $Dest -Value $lines -Encoding UTF8
}

# ---------------- MAIN ----------------
Assert-Admin

$msiUrl  = "https://www.clamav.net/downloads/production/clamav-1.5.1.win.x64.msi"
$tempDir = Join-Path $env:TEMP "clamav_msi"
$msiPath = Join-Path $tempDir "clamav-1.5.1.win.x64.msi"

$installDir = Join-Path ${env:ProgramFiles} "ClamAV"
$confExamplesDir = Join-Path $installDir "conf_examples"

Write-Host "[*] Preparing temp folder..."
Ensure-Dir $tempDir

Write-Host "[*] Downloading ClamAV MSI..."
Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath -UseBasicParsing

Write-Host "[*] Installing ClamAV (silent)..."
$proc = Start-Process -FilePath "msiexec.exe" -ArgumentList @(
    "/i", "`"$msiPath`"",
    "/qn",
    "/norestart"
) -Wait -PassThru

if ($proc.ExitCode -ne 0) {
    throw "MSI install failed. msiexec exit code: $($proc.ExitCode)"
}

# Confirm install path exists
if (-not (Test-Path $installDir)) {
    throw "Expected install directory not found: $installDir"
}

Write-Host "[+] ClamAV install directory: $installDir"

# Locate sample configs
$clamdSample  = Join-Path $confExamplesDir "clamd.conf.sample"
$freshSample  = Join-Path $confExamplesDir "freshclam.conf.sample"

if (-not (Test-Path $confExamplesDir)) {
    throw "conf_examples folder not found: $confExamplesDir"
}
if (-not (Test-Path $clamdSample)) { throw "Missing: $clamdSample" }
if (-not (Test-Path $freshSample)) { throw "Missing: $freshSample" }

# Write final configs into the ClamAV folder (remove .sample)
$clamdConfOut = Join-Path $installDir "clamd.conf"
$freshConfOut = Join-Path $installDir "freshclam.conf"

Write-Host "[*] Creating clamd.conf and freshclam.conf in $installDir ..."
Remove-ExampleLineAndWrite -Source $clamdSample -Dest $clamdConfOut
Remove-ExampleLineAndWrite -Source $freshSample -Dest $freshConfOut

Write-Host "[+] Wrote:"
Write-Host "    $clamdConfOut"
Write-Host "    $freshConfOut"

# Run freshclam
$freshclamExe = Join-Path $installDir "freshclam.exe"
if (-not (Test-Path $freshclamExe)) {
    throw "freshclam.exe not found at: $freshclamExe"
}

Write-Host "[*] Running freshclam..."
Start-Process -FilePath $freshclamExe -ArgumentList @("--config-file=$freshConfOut") -Wait

Write-Host "`n[✔] Done: Installed ClamAV, created configs, and ran freshclam."
