# wazuh-install.ps1
$ErrorActionPreference = "Stop"

# --- Admin check ---
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run as Administrator"
}

# --- Vars ---
$MSI_URL  = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.13.1-1.msi"
$TMP      = $env:TEMP
$MSI_PATH = Join-Path $TMP "wazuh-agent-4.13.1-1.msi"

# --- Input ---
$managerIp = Read-Host "Wazuh Manager IP"
$agentName = Read-Host "Wazuh Agent Name"

# --- TLS (common Windows fix) ---
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Host "[*] Downloading MSI..."
Invoke-WebRequest -Uri $MSI_URL -OutFile $MSI_PATH -UseBasicParsing

Write-Host "[*] Installing..."
$msiArgs = @(
    "/i `"$MSI_PATH`"",
    "/qn",
    "WAZUH_MANAGER=$managerIp",
    "WAZUH_AGENT_NAME=$agentName"
)

Start-Process msiexec.exe -ArgumentList $msiArgs -Wait

# --- Start service ---
Write-Host "[*] Starting service..."
Start-Sleep -Seconds 3
Get-Service wazuhsvc -ErrorAction Stop | Start-Service