<#
================================================================================
Install-ClamAV.ps1
================================================================================
WHAT YOU NEED TO DO (built into this script):
1) Run PowerShell as Administrator.
2) Get a ClamAV Windows x64 MSI installer.
   - Either download it yourself, or provide a direct MSI download URL.
3) Run ONE of these:

   A) Install from local MSI:
      .\Install-ClamAV.ps1 -InstallerPath "C:\Temp\clamav.msi" -RunFreshclam

   B) Download MSI then install:
      .\Install-ClamAV.ps1 -DownloadUrl "https://example.com/clamav.msi" -InstallerPath "C:\Temp\clamav.msi" -RunFreshclam

   C) If ClamAV is already installed and you ONLY want configs fixed:
      .\Install-ClamAV.ps1 -SkipInstall -RunFreshclam

WHAT THIS SCRIPT DOES:
- Installs ClamAV (MSI) (unless -SkipInstall)
- Locates ClamAV install folder
- Creates <InstallDir>\database if missing
- Copies clamd.conf.sample + freshclam.conf.sample to clamd.conf + freshclam.conf
- Removes the line "Example" (and "# Example") from configs
- Ensures DatabaseDirectory is set to the database folder
- Sets HKLM:\SOFTWARE\ClamAV ConfDir and DataDir (helps ClamAV locate files)
- Optionally runs freshclam to download signatures
================================================================================
#>

[CmdletBinding()]
param(
  [string]$InstallerPath = "",
  [string]$DownloadUrl   = "",
  [switch]$SkipInstall,
  [switch]$RunFreshclam
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Show-WhatToDo {
@"
================================================================================
WHAT YOU NEED TO DO
================================================================================
1) Run PowerShell as Administrator.
2) Get a ClamAV Windows x64 MSI installer.
3) Run ONE of these:

   A) Install from local MSI:
      .\Install-ClamAV.ps1 -InstallerPath "C:\Temp\clamav.msi" -RunFreshclam

   B) Download MSI then install:
      .\Install-ClamAV.ps1 -DownloadUrl "https://example.com/clamav.msi" -InstallerPath "C:\Temp\clamav.msi" -RunFreshclam

   C) If ClamAV is already installed (only fix configs):
      .\Install-ClamAV.ps1 -SkipInstall -RunFreshclam
================================================================================
"@ | Write-Host
}

function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Please run PowerShell as Administrator."
  }
}

function Download-File([string]$Url, [string]$OutFile) {
  Write-Host "[*] Downloading: $Url"
  $dir = Split-Path -Parent $OutFile
  if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }

  if (Get-Command Start-BitsTransfer -ErrorAction SilentlyContinue) {
    Start-BitsTransfer -Source $Url -Destination $OutFile
  } else {
    Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing
  }
}

function Install-MSI([string]$Path) {
  if (-not (Test-Path $Path)) { throw "Installer not found: $Path" }
  Write-Host "[*] Installing MSI: $Path"
  $args = "/i `"$Path`" /qn /norestart"
  $p = Start-Process -FilePath "msiexec.exe" -ArgumentList $args -Wait -PassThru
  if ($p.ExitCode -ne 0) { throw "MSI install failed. msiexec exit code: $($p.ExitCode)" }
}

function Find-ClamAVInstallDir {
  $candidates = @(
    "$env:ProgramFiles\ClamAV",
    "${env:ProgramFiles(x86)}\ClamAV",
    "C:\ClamAV"
  ) | Where-Object { $_ -and $_.Trim() -ne "" } | Select-Object -Unique

  foreach ($c in $candidates) {
    if (Test-Path (Join-Path $c "clamscan.exe")) { return $c }
    if (Test-Path (Join-Path $c "clamd.exe"))   { return $c }
    if (Test-Path (Join-Path $c "freshclam.exe")) { return $c }
  }

  $pathDirs = ($env:Path -split ';' | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique)
  foreach ($d in $pathDirs) {
    if (Test-Path (Join-Path $d "clamscan.exe")) { return (Split-Path $d -Parent) }
  }

  $uninstallRoots = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
  )
  foreach ($root in $uninstallRoots) {
    if (-not (Test-Path $root)) { continue }
    foreach ($k in Get-ChildItem $root) {
      try {
        $p = Get-ItemProperty $k.PSPath
        if ($p.DisplayName -match "ClamAV") {
          if ($p.InstallLocation -and (Test-Path $p.InstallLocation)) {
            if (Test-Path (Join-Path $p.InstallLocation "clamscan.exe")) { return $p.InstallLocation }
            if (Test-Path (Join-Path $p.InstallLocation "clamd.exe")) { return $p.InstallLocation }
            if (Test-Path (Join-Path $p.InstallLocation "freshclam.exe")) { return $p.InstallLocation }
          }
        }
      } catch {}
    }
  }

  throw "Could not locate ClamAV install directory. Is ClamAV installed?"
}

function Ensure-RegKeyValues([string]$InstallDir, [string]$DataDir) {
  $base = "HKLM:\SOFTWARE\ClamAV"
  if (-not (Test-Path $base)) { New-Item -Path $base -Force | Out-Null }

  New-ItemProperty -Path $base -Name "ConfDir" -PropertyType String -Value $InstallDir -Force | Out-Null
  New-ItemProperty -Path $base -Name "DataDir" -PropertyType String -Value $DataDir    -Force | Out-Null

  Write-Host "[*] Set registry:"
  Write-Host "    ConfDir = $InstallDir"
  Write-Host "    DataDir = $DataDir"
}

function Get-ConfExamplesDir([string]$InstallDir) {
  $candidates = @(
    (Join-Path $InstallDir "conf_examples"),
    (Join-Path $InstallDir "etc"),
    (Join-Path $InstallDir "conf")
  )
  foreach ($c in $candidates) {
    if (Test-Path $c) { return $c }
  }
  throw "Could not find conf_examples folder under: $InstallDir"
}

function Copy-And-FixConfig([string]$SourceSample, [string]$DestConf, [string]$DataDir) {
  Write-Host "[*] Preparing config: $(Split-Path -Leaf $DestConf)"
  Copy-Item -Path $SourceSample -Destination $DestConf -Force

  $lines = Get-Content -Path $DestConf -Encoding UTF8

  # Delete Example line(s)
  $lines = $lines | Where-Object { $_ -notmatch '^\s*Example\s*$' }
  $lines = $lines | Where-Object { $_ -notmatch '^\s*#\s*Example\s*$' }

  # Ensure DatabaseDirectory points to our DataDir (uncomment if present, otherwise add)
  $dbPattern = '^\s*#?\s*DatabaseDirectory\s+'
  $hasDb = $false
  $newLines = New-Object System.Collections.Generic.List[string]
  foreach ($l in $lines) {
    if ($l -match $dbPattern) {
      $newLines.Add("DatabaseDirectory `"$DataDir`"")
      $hasDb = $true
    } else {
      $newLines.Add($l)
    }
  }
  if (-not $hasDb) {
    $newLines.Add("")
    $newLines.Add("DatabaseDirectory `"$DataDir`"")
  }

  Set-Content -Path $DestConf -Value $newLines -Encoding UTF8
}

function Try-RunFreshclam([string]$InstallDir) {
  $freshclam = Join-Path $InstallDir "freshclam.exe"
  if (-not (Test-Path $freshclam)) {
    Write-Warning "freshclam.exe not found at $freshclam (skipping)."
    return
  }
  Write-Host "[*] Running freshclam to download/update signatures..."
  Start-Process -FilePath $freshclam -ArgumentList @() -Wait
}

# ---------------- MAIN ----------------
Show-WhatToDo
Assert-Admin

# If they didn't provide enough info and aren't skipping install, show instructions and stop
if (-not $SkipInstall) {
  if (-not $InstallerPath) {
    throw "Missing -InstallerPath. See the WHAT YOU NEED TO DO section above."
  }
  if (-not $InstallerPath.ToLower().EndsWith(".msi")) {
    throw "InstallerPath must be an .msi. See the WHAT YOU NEED TO DO section above."
  }
}

if (-not $SkipInstall) {
  if ($DownloadUrl) {
    Download-File -Url $DownloadUrl -OutFile $InstallerPath
  }
  Install-MSI -Path $InstallerPath
} else {
  Write-Host "[*] SkipInstall set: not installing ClamAV."
}

$installDir = Find-ClamAVInstallDir
Write-Host "[+] ClamAV install directory: $installDir"

# Create database directory (you asked for this)
$dataDir = Join-Path $installDir "database"
if (-not (Test-Path $dataDir)) {
  Write-Host "[*] Creating database directory: $dataDir"
  New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
}

# Set registry values (helps ClamAV find configs/DB)
Ensure-RegKeyValues -InstallDir $installDir -DataDir $dataDir

# Copy sample configs -> active configs in install dir
$confExamples = Get-ConfExamplesDir -InstallDir $installDir

$freshSample = Get-ChildItem -Path $confExamples -File -ErrorAction Stop |
  Where-Object { $_.Name -match '^freshclam\.conf\.(sample|example)$' } |
  Select-Object -First 1

$clamdSample = Get-ChildItem -Path $confExamples -File -ErrorAction Stop |
  Where-Object { $_.Name -match '^clamd\.conf\.(sample|example)$' } |
  Select-Object -First 1

if (-not $freshSample) { throw "Could not find freshclam.conf.sample (or .example) in $confExamples" }
if (-not $clamdSample)  { throw "Could not find clamd.conf.sample (or .example) in $confExamples" }

$freshDest = Join-Path $installDir "freshclam.conf"
$clamdDest = Join-Path $installDir "clamd.conf"

Copy-And-FixConfig -SourceSample $freshSample.FullName -DestConf $freshDest -DataDir $dataDir
Copy-And-FixConfig -SourceSample $clamdSample.FullName  -DestConf $clamdDest  -DataDir $dataDir

Write-Host "[+] Configs written:"
Write-Host "    $freshDest"
Write-Host "    $clamdDest"
Write-Host "[+] Database directory:"
Write-Host "    $dataDir"

if ($RunFreshclam) {
  Try-RunFreshclam -InstallDir $installDir
}

Write-Host "`n[+] Done."
