<#
CCDC Disk Space Monitor
- Alerts at 50%, 80%, 90% used
- Writes to Windows Application Event Log (Source: CCDC-DiskMonitor)
- Optional email alerts (if SMTP params provided)
- State + cooldown to prevent spam
#>

[CmdletBinding()]
param(
  [int]$CooldownMinutes = 240,

  # Optional email settings (leave blank to disable email)
  [string]$SmtpServer,
  [int]$SmtpPort = 25,
  [switch]$UseSsl,
  [string]$To,
  [string]$From,
  [string]$SubjectPrefix = "[CCDC DiskMonitor]"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ----------------------------
# Paths / State
# ----------------------------
$stateDir  = Join-Path $env:ProgramData "CCDC\DiskMonitor"
$stateFile = Join-Path $stateDir "state.json"

if (-not (Test-Path $stateDir)) {
  New-Item -Path $stateDir -ItemType Directory -Force | Out-Null
}

$state = @{}
if (Test-Path $stateFile) {
  try {
    $raw = Get-Content -Path $stateFile -Raw -Encoding UTF8
    if ($raw.Trim().Length -gt 0) {
      $state = ($raw | ConvertFrom-Json -ErrorAction Stop)
    }
  } catch {
    $state = @{} # corrupt state -> reset
  }
}

# Ensure we can treat it like a dictionary
if ($state -isnot [System.Collections.IDictionary]) { $state = @{} }

# ----------------------------
# Event Log Setup
# ----------------------------
$eventSource = "CCDC-DiskMonitor"
$eventLog    = "Application"

try {
  if (-not [System.Diagnostics.EventLog]::SourceExists($eventSource)) {
    New-EventLog -LogName $eventLog -Source $eventSource
  }
} catch {
  # If no permission to create source, Write-EventLog may fail later.
}

function Write-DiskEvent {
  param(
    [int]$EventId,
    [ValidateSet("Information","Warning","Error")]
    [string]$EntryType,
    [string]$Message
  )
  Write-EventLog -LogName $eventLog -Source $eventSource -EventId $EventId -EntryType $EntryType -Message $Message
}

function Send-DiskEmail {
  param([string]$Subject, [string]$Body)

  if ([string]::IsNullOrWhiteSpace($SmtpServer) -or
      [string]::IsNullOrWhiteSpace($To) -or
      [string]::IsNullOrWhiteSpace($From)) {
    return
  }

  $mailParams = @{
    SmtpServer = $SmtpServer
    Port       = $SmtpPort
    To         = $To
    From       = $From
    Subject    = $Subject
    Body       = $Body
  }
  if ($UseSsl) { $mailParams.UseSsl = $true }

  Send-MailMessage @mailParams
}

function Get-Tier {
  param([int]$PercentUsed)
  if ($PercentUsed -ge 90) { return 90 }
  if ($PercentUsed -ge 80) { return 80 }
  if ($PercentUsed -ge 50) { return 50 }
  return 0
}

function Should-Alert {
  param([string]$DriveKey, [int]$NewTier, [int]$CooldownMinutes)

  if ($NewTier -eq 0) { return $false }

  $now = [DateTime]::UtcNow

  if (-not $state.Contains($DriveKey)) { return $true }

  $lastTier = 0
  $lastUtc  = $null

  try { $lastTier = [int]$state[$DriveKey].lastTier } catch { $lastTier = 0 }
  try { $lastUtc  = [DateTime]::Parse($state[$DriveKey].lastAlertUtc).ToUniversalTime() } catch { $lastUtc = $null }

  # Crossed into higher tier -> alert now
  if ($NewTier -gt $lastTier) { return $true }

  # Same tier -> only alert after cooldown
  if ($NewTier -eq $lastTier -and $lastUtc) {
    return (($now - $lastUtc).TotalMinutes -ge $CooldownMinutes)
  }

  return $true
}

function Save-State {
  $json = ($state | ConvertTo-Json -Depth 5)
  Set-Content -Path $stateFile -Value $json -Encoding UTF8
}

# ----------------------------
# Collect fixed disks + alert
# ----------------------------
$disks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" |
  Select-Object DeviceID, VolumeName, Size, FreeSpace

foreach ($d in $disks) {
  if (-not $d.Size -or $d.Size -le 0) { continue }

  $usedBytes = [double]($d.Size - $d.FreeSpace)
  $pctUsed   = [int][Math]::Round(($usedBytes / [double]$d.Size) * 100, 0)
  $tier      = Get-Tier -PercentUsed $pctUsed

  $driveKey = "$($d.DeviceID)"
  $volName  = if ([string]::IsNullOrWhiteSpace($d.VolumeName)) { "(no label)" } else { $d.VolumeName }

  $sizeGB = [Math]::Round(($d.Size / 1GB), 2)
  $freeGB = [Math]::Round(($d.FreeSpace / 1GB), 2)
  $usedGB = [Math]::Round(($usedBytes / 1GB), 2)

  # Below 50%: clear state so future threshold crossings re-alert
  if ($tier -eq 0) {
    if ($state.Contains($driveKey)) {
      $state.Remove($driveKey) | Out-Null
      Save-State
    }
    continue
  }

  if (-not (Should-Alert -DriveKey $driveKey -NewTier $tier -CooldownMinutes $CooldownMinutes)) {
    continue
  }

  $eventId = switch ($tier) {
    50 { 5050 }
    80 { 5080 }
    90 { 5090 }
    default { 5000 }
  }

  $entryType = switch ($tier) {
    50 { "Information" }
    80 { "Warning" }
    90 { "Error" }
    default { "Warning" }
  }

  $msg = @"
Disk usage threshold reached.

Drive:      $driveKey ($volName)
Used:       $pctUsed% ($usedGB GB used of $sizeGB GB)
Free:       $freeGB GB
Threshold:  $tier%
Host:       $env:COMPUTERNAME
Time (UTC): $([DateTime]::UtcNow.ToString("o"))
"@

  try { Write-DiskEvent -EventId $eventId -EntryType $entryType -Message $msg } catch { }

  $subject = "$SubjectPrefix $env:COMPUTERNAME $driveKey at $pctUsed% (Tier $tier%)"
  try { Send-DiskEmail -Subject $subject -Body $msg } catch { }

  $state[$driveKey] = @{
    lastTier     = $tier
    lastAlertUtc = [DateTime]::UtcNow.ToString("o")
  }
  Save-State
}

exit 0
