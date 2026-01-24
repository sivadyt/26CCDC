<# 
Web Server Firewall Baseline (Windows Server 2019)
- Inbound: allow only HTTP/HTTPS (80/443)
- Outbound: allow DNS/NTP + web (80/443) + optional internal service ports you choose
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

# Ask for internal dependencies
$dnsServers = Read-Host "Enter DNS server IPs (comma-separated) (example: 172.20.240.202,8.8.8.8)"
$ntpServers = Read-Host "Enter NTP server IPs (comma-separated) (example: 172.20.240.202) (blank = allow any NTP)"

$internalSubnets = Read-Host "Enter internal subnet(s) the web server must talk to (comma-separated CIDR) (example: 172.20.240.0/24,10.0.0.0/8)"
if ([string]::IsNullOrWhiteSpace($internalSubnets)) {
  Write-Host "No internal subnets entered. Internal outbound rules will be limited to IPs you specify later (or skipped)." -ForegroundColor Yellow
}

$tcpInternalPorts = Read-PortsList "Enter INTERNAL TCP ports the web server must reach (comma/space separated) (example: 1433 389 636 5985) or blank"
$udpInternalPorts = Read-PortsList "Enter INTERNAL UDP ports the web server must reach (comma/space separated) (example: 514 123) or blank"

# Normalize address lists
function Split-Addr([string]$s) {
  if ([string]::IsNullOrWhiteSpace($s)) { return @() }
  return ($s -split "[,\s]+" | Where-Object { $_ -ne "" } | Sort-Object -Unique)
}

$dnsList = Split-Addr $dnsServers
$ntpList = Split-Addr $ntpServers
$subnetList = Split-Addr $internalSubnets

# --- Start changes ---
Write-Host ""
Write-Host "Applying firewall policy..." -ForegroundColor Cyan

# Set default policy: inbound block, outbound block (strong)
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -DefaultOutboundAction Block -NotifyOnListen True -LogAllowed True -LogBlocked True | Out-Null

# Optional: enable logging (path may differ; this is typical)
$logPath = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
Set-NetFirewallProfile -Profile Domain,Private,Public -LogFileName $logPath -LogMaxSizeKilobytes 16384 -LogBlocked True -LogAllowed True | Out-Null

# Clean old rules from our group
Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayGroup -eq "CCDC-WebServer" } | Remove-NetFirewallRule -ErrorAction SilentlyContinue | Out-Null

# Disable built-in Remote Desktop & OpenSSH rules if present
Ensure-RuleGroupOff "Remote Desktop"
# OpenSSH rules aren't always in a consistent group name, so we also explicitly block ports below.

# ---- INBOUND RULES ----
New-NetFirewallRule -DisplayName "WS IN Allow HTTP 80" -DisplayGroup "CCDC-WebServer" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 80 -Profile Domain,Private,Public | Out-Null
New-NetFirewallRule -DisplayName "WS IN Allow HTTPS 443" -DisplayGroup "CCDC-WebServer" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 443 -Profile Domain,Private,Public | Out-Null

# Explicitly block RDP and SSH inbound (even if someone changes defaults later)
New-NetFirewallRule -DisplayName "WS IN Block RDP 3389" -DisplayGroup "CCDC-WebServer" -Direction Inbound -Action Block -Protocol TCP -LocalPort 3389 -Profile Domain,Private,Public | Out-Null
New-NetFirewallRule -DisplayName "WS IN Block SSH 22" -DisplayGroup "CCDC-WebServer" -Direction Inbound -Action Block -Protocol TCP -LocalPort 22 -Profile Domain,Private,Public | Out-Null

# ---- OUTBOUND RULES ----

# DNS outbound (to specific DNS servers if provided; otherwise allow any DNS)
if ($dnsList.Count -gt 0) {
  New-NetFirewallRule -DisplayName "WS OUT Allow DNS UDP 53 to DNS servers" -DisplayGroup "CCDC-WebServer" -Direction Outbound -Action Allow -Protocol UDP -RemotePort 53 -RemoteAddress $dnsList -Profile Domain,Private,Public | Out-Null
  New-NetFirewallRule -DisplayName "WS OUT Allow DNS TCP 53 to DNS servers" -DisplayGroup "CCDC-WebServer" -Direction Outbound -Action Allow -Protocol TCP -RemotePort 53 -RemoteAddress $dnsList -Profile Domain,Private,Public | Out-Null
} else {
  New-NetFirewallRule -DisplayName "WS OUT Allow DNS UDP 53 (any)" -DisplayGroup "CCDC-WebServer" -Direction Outbound -Action Allow -Protocol UDP -RemotePort 53 -Profile Domain,Private,Public | Out-Null
  New-NetFirewallRule -DisplayName "WS OUT Allow DNS TCP 53 (any)" -DisplayGroup "CCDC-WebServer" -Direction Outbound -Action Allow -Protocol TCP -RemotePort 53 -Profile Domain,Private,Public | Out-Null
}

# NTP outbound (to specific NTP servers if provided; otherwise allow any NTP)
if ($ntpList.Count -gt 0) {
  New-NetFirewallRule -DisplayName "WS OUT Allow NTP UDP 123 to NTP servers" -DisplayGroup "CCDC-WebServer" -Direction Outbound -Action Allow -Protocol UDP -RemotePort 123 -RemoteAddress $ntpList -Profile Domain,Private,Public | Out-Null
} else {
  New-NetFirewallRule -DisplayName "WS OUT Allow NTP UDP 123 (any)" -DisplayGroup "CCDC-WebServer" -Direction Outbound -Action Allow -Protocol UDP -RemotePort 123 -Profile Domain,Private,Public | Out-Null
}

# Allow outbound web (updates, CRL/OCSP, downloads, etc.)
New-NetFirewallRule -DisplayName "WS OUT Allow HTTP 80" -DisplayGroup "CCDC-WebServer" -Direction Outbound -Action Allow -Protocol TCP -RemotePort 80 -Profile Domain,Private,Public | Out-Null
New-NetFirewallRule -DisplayName "WS OUT Allow HTTPS 443" -DisplayGroup "CCDC-WebServer" -Direction Outbound -Action Allow -Protocol TCP -RemotePort 443 -Profile Domain,Private,Public | Out-Null

# Allow outbound to internal services (scoped to your internal subnets)
if ($subnetList.Count -gt 0) {
  if ($tcpInternalPorts.Count -gt 0) {
    New-NetFirewallRule -DisplayName "WS OUT Allow INTERNAL TCP ports" -DisplayGroup "CCDC-WebServer" -Direction Outbound -Action Allow -Protocol TCP -RemotePort ($tcpInternalPorts -join ",") -RemoteAddress $subnetList -Profile Domain,Private,Public | Out-Null
  }
  if ($udpInternalPorts.Count -gt 0) {
    New-NetFirewallRule -DisplayName "WS OUT Allow INTERNAL UDP ports" -DisplayGroup "CCDC-WebServer" -Direction Outbound -Action Allow -Protocol UDP -RemotePort ($udpInternalPorts -join ",") -RemoteAddress $subnetList -Profile Domain,Private,Public | Out-Null
  }
} else {
  Write-Host "Skipped internal outbound rules because no internal subnet(s) were provided." -ForegroundColor Yellow
}

# Optional: explicitly block outbound SMB to reduce lateral movement risk
New-NetFirewallRule -DisplayName "WS OUT Block SMB TCP 445" -DisplayGroup "CCDC-WebServer" -Direction Outbound -Action Block -Protocol TCP -RemotePort 445 -Profile Domain,Private,Public | Out-Null
New-NetFirewallRule -DisplayName "WS OUT Block SMB TCP 139" -DisplayGroup "CCDC-WebServer" -Direction Outbound -Action Block -Protocol TCP -RemotePort 139 -Profile Domain,Private,Public | Out-Null

Write-Host ""
Write-Host "Done." -ForegroundColor Green
Write-Host "Firewall log: $logPath"
Write-Host ""
Write-Host "Quick checks:"
Write-Host "  - Inbound allowed: TCP 80, 443 only"
Write-Host "  - Inbound blocked: TCP 3389 (RDP), TCP 22 (SSH)"
Write-Host "  - Outbound allowed: DNS 53, NTP 123, HTTP 80, HTTPS 443, plus your internal ports/subnets"
Write-Host ""
Write-Host "To view rules created:"
Write-Host "  Get-NetFirewallRule -DisplayGroup 'CCDC-WebServer' | ft DisplayName,Enabled,Direction,Action -Auto"
