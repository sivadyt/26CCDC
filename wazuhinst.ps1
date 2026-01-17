# wazuh-install.ps1
$ErrorActionPreference = "Stop"

$MSI_URL  = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.13.1-1.msi"
$TMP      = $env:TEMP
$MSI_PATH = Join-Path $TMP "wazuh-agent-4.13.1-1.msi"

$managerIp = Read-Host "Wazuh Manager IP"
$agentName = Read-Host "Wazuh Agent Name (ej: HOSTNAME o el nombre que quieras)"

Write-Host "[*] Downloading MSI..."
Invoke-WebRequest -Uri $MSI_URL -OutFile $MSI_PATH

Write-Host "[*] Installing..."
$msiArgs = @(
  "/i", "`"$MSI_PATH`"",
  "/q",
  "WAZUH_MANAGER=`"$managerIp`"",
  "WAZUH_AGENT_NAME=`"$agentName`""
)

Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -NoNewWindow

Write-Host "[*] Starting service..."
net start Wazuh
