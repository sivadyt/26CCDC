<#
CCDC Disk Space Monitor (Event Log ONLY)
- Alerts at 50%, 80%, 90% used
- Writes to Windows Application Event Log (Source: CCDC-DiskMonitor)
- State + cooldown to prevent spam
#>

[CmdletBinding()]
param(
  [int]$CooldownMinutes = 240,
  [switch]$VerboseOutput,
  [switch]$ForceAlert
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
  } catch { $state = @{} }
}
if ($state -isnot [System.Collections.IDictionary]) { $state = @{} }

# ----------------------------
# Event Log Setup
# ----------------------------
$eventSource = "CCDC-DiskMonitor"
$eventLog    = "Application"

function Ensure-EventSource {
  # Creating an event source generally requires Admin the first time.
  if (-not [System.Diagnostics.EventLog]::SourceExists($eventSource)) {
    New-EventLog -LogName $eventLog -Source $eventSource
  }
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

function Get-Tier([int]$PercentUsed) {
  if ($PercentUsed -ge 90) { return 90 }
  if ($PercentUsed -ge 80) { return 80 }
  if ($PercentUsed -ge 50) { return 50 }
  return 0
}

function Should-Alert([string]$DriveKey,[int]$NewTier,[int]$CooldownMinutes) {
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
    return ((($now - $lastUtc).TotalMinutes) -ge $CooldownMinutes)
  }

  return $true
}

function Save-State {
  ($state | ConvertTo-Json -Depth 5) | Set-Content -Path $stateFile -Encoding UTF8
}

# ----------------------------
# Collect fixed disks + alert
# ----------------------------
$disks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" |
  Select-Object DeviceID, VolumeName, Size, FreeSpace

$eventSourceReady = $true
try {
  Ensure-EventSource
} catch {
  $eventSourceReady = $false
  if ($VerboseOutput) {
    Write-Host "WARNING: Could not create/use Event Source '$eventSource' in '$eventLog'. Run once as Administrator to register the source."
    Write-Host "Error: $($_.Exception.Message)"
  }
}

foreach ($d in $disks) {
  if (-not $d.Size -or $d.Size -le 0) { continue }

  $usedBytes = [double]($d.Size - $d.FreeSpace)
  $pctUsed   = [int][Math]::Round(($usedBytes / [double]$d.Size) * 100, 0)
  $tier      = Get-Tier $pctUsed

  # Testing mode: force an alert at 50 tier even if under 50
  if ($ForceAlert -and $tier -eq 0) { $tier = 50 }

  $driveKey = "$($d.DeviceID)"
  $volName  = if ([string]::IsNullOrWhiteSpace($d.VolumeName)) { "(no label)" } else { $d.VolumeName }

  $sizeGB = [Math]::Round(($d.Size / 1GB), 2)
  $freeGB = [Math]::Round(($d.FreeSpace / 1GB), 2)
  $usedGB = [Math]::Round(($usedBytes / 1GB), 2)

  if ($VerboseOutput) {
    Write-Host ("{0} {1}  Used={2}%  UsedGB={3}  FreeGB={4}  SizeGB={5}" -f $driveKey, $volName, $pctUsed, $usedGB, $freeGB, $sizeGB)
  }

  # Below 50%: clear state so future threshold crossings re-alert
  if (-not $ForceAlert -and $tier -eq 0) {
    if ($state.Contains($driveKey)) {
      $state.Remove($driveKey) | Out-Null
      Save-State
    }
    continue
  }

  if (-not $ForceAlert) {
    if (-not (Should-Alert $driveKey $tier $CooldownMinutes)) { continue }
  }

  $eventId = switch ($tier) { 50 {5050} 80 {5080} 90 {5090} default {5000} }
  $entryType = switch ($tier) { 50 {"Information"} 80 {"Warning"} 90 {"Error"} default {"Warning"} }

  $msg = @"
Disk usage threshold reached.

Drive:      $driveKey ($volName)
Used:       $pctUsed% ($usedGB GB used of $sizeGB GB)
Free:       $freeGB GB
Threshold:  $tier%
Host:       $env:COMPUTERNAME
Time (UTC): $([DateTime]::UtcNow.ToString("o"))
"@

  if ($eventSourceReady) {
    try {
      Write-DiskEvent -EventId $eventId -EntryType $entryType -Message $msg
      if ($VerboseOutput) { Write-Host "EventLog written: Source=$eventSource ID=$eventId Level=$entryType" }
    } catch {
      if ($VerboseOutput) { Write-Host "WARNING: Write-EventLog failed: $($_.Exception.Message)" }
    }
  } elseif ($VerboseOutput) {
    Write-Host "WARNING: EventLog not available (source not registered). Run script once as Administrator."
  }

  # Update state
  $state[$driveKey] = @{ lastTier = $tier; lastAlertUtc = [DateTime]::UtcNow.ToString("o") }
  Save-State
}

exit 0
