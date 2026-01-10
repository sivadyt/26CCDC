<#
================================================================================
AUTO ClamAV ZIP INSTALL + CONFIG SCRIPT (NO ARGUMENTS)
================================================================================
- Downloads ClamAV 1.5.1 ZIP
- Extracts to C:\ClamAV
- Creates database folder
- Copies conf_examples files INTO database folder
- Fixes clamd.conf + freshclam.conf
- Removes "Example" line
- Runs freshclam
================================================================================
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------- ADMIN CHECK ----------------
function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run PowerShell as Administrator."
    }
}
Assert-Admin

Write-Host "[*] Starting ClamAV ZIP installation..."

# ---------------- VARIABLES ----------------
$zipUrl     = "https://www.clamav.net/downloads/production/clamav-1.5.1.win.x64.zip"
$tempDir   = "$env:TEMP\clamav"
$zipPath   = "$tempDir\clamav.zip"
$installDir = "C:\ClamAV"
$dbDir     = "$installDir\database"
$confExamples = "$installDir\conf_examples"

# ---------------- DOWNLOAD ZIP ----------------
if (-not (Test-Path $tempDir)) {
    New-Item -ItemType Directory -Path $tempDir | Out-Null
}

if (-not (Test-Path $zipPath)) {
    Write-Host "[*] Downloading ClamAV ZIP..."
    Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing
} else {
    Write-Host "[*] ZIP already downloaded."
}

# ---------------- EXTRACT ----------------
Write-Host "[*] Extracting ZIP to $installDir..."
if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir | Out-Null
}

Expand-Archive -Path $zipPath -DestinationPath $installDir -Force

# ---------------- DATABASE DIR ----------------
if (-not (Test-Path $dbDir)) {
    Write-Host "[*] Creating database directory..."
    New-Item -ItemType Directory -Path $dbDir | Out-Null
}

# ---------------- COPY conf_examples INTO database ----------------
if (Test-Path $confExamples) {
    Write-Host "[*] Copying conf_examples files into database folder..."
    Copy-Item -Path "$confExamples\*" -Destination $dbDir -Recurse -Force
} else {
    Write-Warning "conf_examples directory not found."
}

# ---------------- CONFIG FILES ----------------
$clamdSample  = "$confExamples\clamd.conf.sample"
$freshSample  = "$confExamples\freshclam.conf.sample"
$clamdConf    = "$installDir\clamd.conf"
$freshConf    = "$installDir\freshclam.conf"

Copy-Item $clamdSample  $clamdConf  -Force
Copy-Item $freshSample  $freshConf  -Force

function Fix-Config {
    param ($file)

    $content = Get-Content $file

    # Remove Example line
    $content = $content | Where-Object { $_ -notmatch '^\s*#?\s*Example\s*$' }

    # Fix DatabaseDirectory
    $content = $content | Where-Object { $_ -notmatch '^\s*#?\s*DatabaseDirectory' }
    $content += "DatabaseDirectory `"$dbDir`""

    Set-Content -Path $file -Value $content -Encoding UTF8
}

Fix-Config $clamdConf
Fix-Config $freshConf

# ---------------- RUN FRESHCLAM ----------------
$freshclamExe = "$installDir\freshclam.exe"
if (Test-Path $freshclamExe) {
    Write-Host "[*] Running freshclam to download signatures..."
    Start-Process $freshclamExe -Wait
} else {
    Write-Warning "freshclam.exe not found."
}

Write-Host ""
Write-Host "[✔] ClamAV ZIP installation and configuration complete."
