<#
================================================================================
AUTO ClamAV INSTALL + CONFIG SCRIPT (NO ARGUMENTS REQUIRED)
================================================================================
- Downloads ClamAV Windows x64 automatically
- Installs silently
- Fixes config files
- Creates database folder
- Removes "Example" line
- Runs freshclam
================================================================================
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

Assert-Admin

Write-Host "[*] Starting ClamAV automated installation..."

# ---------------- DOWNLOAD ----------------
$downloadUrl = "https://www.clamav.net/downloads/production/clamav-1.4.2.win.x64.msi"
$tempDir = "$env:TEMP\clamav"
$msiPath = "$tempDir\clamav.msi"

if (-not (Test-Path $tempDir)) {
  New-Item -ItemType Directory -Path $tempDir | Out-Null
}

if (-not (Test-Path $msiPath)) {
  Write-Host "[*] Downloading ClamAV..."
  Invoke-WebRequest -Uri $downloadUrl -OutFile $msiPath -UseBasicParsing
} else {
  Write-Host "[*] ClamAV MSI already downloaded."
}

# ---------------- INSTALL ----------------
Write-Host "[*] Installing ClamAV..."
Start-Process msiexec.exe -ArgumentList "/i `"$msiPath`" /qn /norestart" -Wait

# ---------------- LOCATE INSTALL ----------------
$installDir = "C:\Program Files\ClamAV"
if (-not (Test-Path $installDir)) {
  throw "ClamAV install directory not found."
}

Write-Host "[+] ClamAV installed at: $installDir"

# ---------------- DATABASE DIR ----------------
$dbDir = "$installDir\database"
if (-not (Test-Path $dbDir)) {
  Write-Host "[*] Creating database directory..."
  New-Item -ItemType Directory -Path $dbDir | Out-Null
}

# ---------------- REGISTRY ----------------
$regPath = "HKLM:\SOFTWARE\ClamAV"
if (-not (Test-Path $regPath)) {
  New-Item -Path $regPath | Out-Null
}

Set-ItemProperty -Path $regPath -Name ConfDir -Value $installDir -Force
Set-ItemProperty -Path $regPath -Name DataDir -Value $dbDir -Force

# ---------------- CONFIG FILES ----------------
$confExamples = "$installDir\conf_examples"
$clamdSample = "$confExamples\clamd.conf.sample"
$freshSample = "$confExamples\freshclam.conf.sample"

$clamdConf = "$installDir\clamd.conf"
$freshConf = "$installDir\freshclam.conf"

Copy-Item $clamdSample $clamdConf -Force
Copy-Item $freshSample $freshConf -Force

function Fix-Config($file) {
  $content = Get-Content $file
  $content = $content | Where-Object { $_ -notmatch '^\s*#?\s*Example\s*$' }

  if ($content -notmatch '^DatabaseDirectory') {
    $content += "DatabaseDirectory `"$dbDir`""
  }

  Set-Content -Path $file -Value $content -Encoding UTF8
}

Fix-Config $clamdConf
Fix-Config $freshConf

# ---------------- UPDATE SIGNATURES ----------------
$freshclamExe = "$installDir\freshclam.exe"
if (Test-Path $freshclamExe) {
  Write-Host "[*] Running freshclam..."
  Start-Process $freshclamExe -Wait
}

Write-Host ""
Write-Host "[✔] ClamAV installed and configured successfully."
