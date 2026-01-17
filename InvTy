Write-Host "===== OS LEVEL / UPGRADE ASSESSMENT =====`n"

# Device name
$DeviceName = $env:COMPUTERNAME
Write-Host "Device Name:"
Write-Host " - $DeviceName`n"

# IP address(es)
$IPAddresses = Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object {
        $_.IPAddress -notlike "169.254*" -and
        $_.IPAddress -ne "127.0.0.1"
    } |
    Select-Object -ExpandProperty IPAddress -Unique

Write-Host "Device IP Address(es):"
if ($IPAddresses) {
    $IPAddresses | ForEach-Object { Write-Host " - $_" }
} else {
    Write-Host " - No IPv4 address found"
}
Write-Host ""

# OS installed
$OS = Get-CimInstance Win32_OperatingSystem
$Build = $OS.BuildNumber
$UBR = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").UBR
$DisplayVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").DisplayVersion

Write-Host "Current OS Level Installed:"
Write-Host " - OS Name: $($OS.Caption)"
Write-Host " - Version: $DisplayVersion"
Write-Host " - Build: $Build.$UBR`n"

# Check available updates (manufacturer / Microsoft)
Write-Host "Current Production OS Level Available:"
try {
    $Session = New-Object -ComObject Microsoft.Update.Session
    $Searcher = $Session.CreateUpdateSearcher()
    $Results = $Searcher.Search("IsInstalled=0 and IsHidden=0")

    if ($Results.Updates.Count -gt 0) {
        Write-Host " - Pending updates detected: $($Results.Updates.Count)"
        foreach ($Update in $Results.Updates) {
            if ($Update.Title -match "Feature update") {
                Write-Host "   * FEATURE UPGRADE AVAILABLE: $($Update.Title)"
            }
        }
    } else {
        Write-Host " - OS is fully up to date"
    }
}
catch {
    Write-Host " - Unable to query Windows Update"
}
Write-Host ""

# Assessment
Write-Host "Assessment:"
if ($Results.Updates.Count -gt 0) {
    Write-Host " - System is missing updates."
    Write-Host " - Missing patches may represent significant vulnerabilities."
    Write-Host " - Recommendation: Apply updates and upgrade OS if a feature update is available."
} else {
    Write-Host " - OS is current."
    Write-Host " - No significant OS-level vulnerabilities related to missing updates detected."
}

Write-Host "`n========================================"
