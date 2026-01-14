# clamav-windows-install.ps1
# Downloads ONLY Windows ClamAV (MSI or ZIP) and installs/extracts it.

$ErrorActionPreference = "Stop"

$WIN_MSI_URL = "https://www.clamav.net/downloads/production/clamav-1.5.1.win.x64.msi"
$WIN_ZIP_URL = "https://www.clamav.net/downloads/production/clamav-1.5.1.win.x64.zip"

function Is-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Download-File([string]$Url, [string]$OutFile) {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  New-Item -ItemType Directory -Force -Path (Split-Path $OutFile) | Out-Null
  Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing
}

Write-Host "Choose:"
Write-Host "  1) Install via MSI (recommended)"
Write-Host "  2) Download ZIP and extract"
$choice = Read-Host "Selection [1-2]"

$tmp = Join-Path $env:TEMP ("clamav_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

switch ($choice) {
  "1" {
    if (-not (Is-Admin)) { throw "Run PowerShell as Administrator for MSI install." }

    $msi = Join-Path $tmp "clamav.msi"
    Write-Host "Downloading MSI..."
    Download-File $WIN_MSI_URL $msi

    Write-Host "Installing MSI..."
    $log = Join-Path $tmp "clamav-install.log"
    $args = "/i `"$msi`" /qn /norestart /l*v `"$log`""
    $p = Start-Process -FilePath "msiexec.exe" -ArgumentList $args -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw "MSI install failed. ExitCode=$($p.ExitCode). Log: $log" }

    Write-Host "Done. Log: $log"
  }

  "2" {
    $zip = Join-Path $tmp "clamav.zip"
    Write-Host "Downloading ZIP..."
    Download-File $WIN_ZIP_URL $zip

    $dest = Read-Host "Extract to (default: C:\ClamAV)"
    if ([string]::IsNullOrWhiteSpace($dest)) { $dest = "C:\ClamAV" }

    Write-Host "Extracting to $dest ..."
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    Expand-Archive -Path $zip -DestinationPath $dest -Force

    Write-Host "Done. Extracted to: $dest"
  }

  default { throw "Invalid selection." }
}

Write-Host "Temp: $tmp"
