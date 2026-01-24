<# 
Web Server Firewall Baseline (Windows Server 2019)
- Inbound: allow only HTTP/HTTPS (80/443)
- Outbound: Default BLOCK; allows DNS/NTP + web (80/443) + optional internal service ports you choose
- Explicitly blocks RDP and SSH
Run as Administrator.
#>

$ErrorActionPreference = "Stop"

function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script as Administrator."
  }
}

function Read-PortsList([string]$prompt) {
  $raw = Read-Host $prompt
  if ([string]::IsNullOrWhiteSpace($raw)) { return @() }
  $ports = @()
  foreach ($p in ($raw -split "[,\s]+" | Where-Object { $_ -ne "" })) {
    if ($p -notmatch "^\d+$") { throw "Invalid port: '$p' (must be a number)" }
    $n = [int]$p
    if ($n -lt 1 -or $n -gt 65535) { throw "Invalid port range: $n" }
    $ports += $n
  }
  return ($ports | Sort-Object -Unique)
}

function Split-Addr([string]$s) {
  if ([string]::IsNullOrWhiteSpace($s)) { return @() }
  return ($s -split "[,\s]+" | Where-Object { $_ -ne "" } | Sort-Object -Unique)
}

function Ensure-RuleGroupOff([string]$groupName) {
  $rules = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayGroup -eq $groupName }
  if ($rules) { $rules | Disable-NetFirewallRule | Out-Null }
}

Assert-Admin

Write-Host ""
Write-Host "=== Web Server 2019 Firewall Setup ===" -ForegroundColor Cyan
Write-Host "Inbound: ONLY TCP 80/443 allowed. Everything else blocked."
Write-Host "Outbound: Default BLOCK; allows DNS/NTP + TCP 80/443 + your internal service ports."
Write-Host ""

# Inputs
$dnsServers = Read-Host "Enter DNS server IPs (comma-separated) (example: 172.20.240.202,8.8.8.8)"
$ntpServers = Read-Host "Enter NTP server IPs (comma-separated) (example: 172.20.240.202) (blank = allow any NTP)"

$internalSubnets = Read-Host "Enter internal subnet(s) the web server must talk to (comma-separated CIDR) (example: 172.20.240.0/24,10.0.0.0/8)"
if ([string]::IsNullOrWhiteSpace($internalSubnets)) {
  Write-Host "No internal subnets entered. Internal outbound rules will be limited to IPs you specify later (or skipped)." -ForegroundColor Yellow
}

$tcpInternalPorts = Read-PortsList "Enter INTERNAL TCP ports the web server must reach (example: 1433 389 636) or blank"
$udpInternalPorts = Read-PortsList "Enter INTERNAL UDP ports the web server must reach (example: 514 123) or blank"

$dnsList    = Split-Addr $dnsServers
$ntpList    = Split-Addr $ntpServers
$subnetList = Split-Addr $internalSubnets

# --- Apply policy ---
Write-Host ""
Write-Host "Applying firewall policy..." -ForegroundColor Cyan

# Strong defaults
Set-NetFirewallProfile -Profile Domain,Private,Public `
  -DefaultInboundAction Block `
  -DefaultOutboundAction Block `
  -NotifyOnListen $true | Out-Null

# Logging (optional but helpful)
$logPath = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
Set-NetFirewallProfile -Profile Domain,Private,Public `
  -LogFileName $logPath `
  -LogMaxSizeKilobytes 16384 `
  -LogBlocked $true `
  -LogAllowed $true | Out-Null

# Remove old rules we created before
Get-NetFirewallRule -ErrorAction SilentlyContinue |
  Where-Object { $_.Group -eq "CCDC-WebServer" } |
  Remove-NetFirewallRule -ErrorAction SilentlyContinue | Out-Null

# Disable built-in RDP rule group if present
Ensure-RuleGroupOff "Remote Desktop"

# ---- INBOUND ----
New-NetFirewallRule -DisplayName "WS IN Allow HTTP 80"  -Group "CCDC-WebServer" -Direction Inbound  -Action Allow -Protocol TCP -LocalPort 80  -Profile Domain,Private,Public | Out-Null
New-NetFirewallRule -DisplayName "WS IN Allow HTTPS 443" -Group "CCDC-WebServer" -Direction Inbound  -Action Allow -Protocol TCP -LocalPort 443 -Profile Domain,Private,Public | Out-Null

# Explicitly block RDP/SSH inbound
New-NetFirewallRule -DisplayName "WS IN Block RDP 3389" -Group "CCDC-WebServer" -Direction Inbound -Action Block -Protocol TCP -LocalPort 3389 -Profile Domain,Private,Public | Out-Null
New-NetFirewallRule -DisplayName "WS IN Block SSH 22"   -Group "CCDC-WebServer" -Direction Inbound -Action Block -Protocol TCP -LocalPort 22   -Profile Domain,Private,Public | Out-Null

# ---- OUTBOUND ----
# DNS
if ($dnsList.Count -gt 0) {
  New-NetFirewallRule -DisplayName "WS OUT Allow DNS UDP 53 to DNS servers" -Group "CCDC-WebServer" -Direction Outbound -Action Allow -Protocol UDP -RemotePort 53 -RemoteAddress $dnsList -Profile Domain,Private,Public | Out-Null
  New-NetFirewallRule -DisplayName "WS OUT Allow DNS TCP 53 to DNS servers" -Group "CCDC-WebServer" -Direction Outbound -Action Allow -Protocol TCP -RemotePort 53 -RemoteAddress $dnsList -Profile Domain,Private,Public | Out-Null
} else {
  New-NetFirewallRule -DisplayName "WS OUT Allow DNS UDP 53 (any)" -Group "CCDC-WebServer" -Direction Outbound -Action Allow -Protocol UDP -RemotePort 53 -Profile Domain,Private,Public | Out-Null
  New-NetFirewallRule -DisplayName "WS OUT Allow DNS TCP 53 (any)" -Group "CCDC-WebServer" -Direction Outbound -Action Allow -Protocol TCP -RemotePort 53 -Profile Domain,Private,Public | Out-Null
}

# NTP
if ($ntpList.Count -gt 0) {
  New-NetFirewallRule -DisplayName "WS OUT Allow NTP UDP 123 to NTP servers" -Group "CCDC-WebServer" -Direction Outbound -Action Allow -Protocol UDP -RemotePort 123 -RemoteAddress $ntpList -Profile Domain,Private,Public | Out-Null
} else {
  New-NetFirewallRule -DisplayName "WS OUT Allow NTP UDP 123 (any)" -Group "CCDC-WebServer" -Direction Outbound -Action Allow -Protocol UDP -RemotePort 123 -Profile Domain,Private,Public | Out-Null
}

# Outbound web (updates, cert checks, downloads)
New-NetFirewallRule -DisplayName "WS OUT Allow HTTP 80"  -Group "CCDC-WebServer" -Direction Outbound -Action Allow -Protocol TCP -RemotePort 80  -Profile Domain,Private,Public | Out-Null
New-NetFirewallRule -DisplayName "WS OUT Allow HTTPS 443" -Group "CCDC-WebServer" -Direction Outbound -Action Allow -Protocol TCP -RemotePort 443 -Profile Domain,Private,Public | Out-Null

# Internal service ports (scoped to your internal subnets)
if ($subnetList.Count -gt 0) {
  if ($tcpInternalPorts.Count -gt 0) {
    New-NetFirewallRule -DisplayName "WS OUT Allow INTERNAL TCP ports" -Group "CCDC-WebServer" -Direction Outbound -Action Allow -Protocol TCP -RemotePort ($tcpInternalPorts -join ",") -RemoteAddress $subnetList -Profile Domain,Private,Public | Out-Null
  }
  if ($udpInternalPorts.Count -gt 0) {
    New-NetFirewallRule -DisplayName "WS OUT Allow INTERNAL UDP ports" -Group "CCDC-WebServer" -Direction Outbound -Action Allow -Protocol UDP -RemotePort ($udpInternalPorts -join ",") -RemoteAddress $subnetList -Profile Domain,Private,Public | Out-Null
  }
} else {
  Write-Host "Skipped internal outbound rules because no internal subnet(s) were provided." -ForegroundColor Yellow
}

# Reduce lateral movement: block SMB outbound
New-NetFirewallRule -DisplayName "WS OUT Block SMB TCP 445" -Group "CCDC-WebServer" -Direction Outbound -Action Block -Protocol TCP -RemotePort 445 -Profile Domain,Private,Public | Out-Null
New-NetFirewallRule -DisplayName "WS OUT Block SMB TCP 139" -Group "CCDC-WebServer" -Direction Outbound -Action Block -Protocol TCP -RemotePort 139 -Profile Domain,Private,Public | Out-Null

Write-Host ""
Write-Host "Done." -ForegroundColor Green
Write-Host "Firewall log: $logPath"
Write-Host ""
Write-Host "Show rules:"
Write-Host "  Get-NetFirewallRule -Group 'CCDC-WebServer' | ft DisplayName,Enabled,Direction,Action -Auto"
