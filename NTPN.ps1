# Variables
$defaultNewHost = "172.20.242.104"
$publicPool = "0.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org"
$input = "0"

# Print a menulist
function Menu {
  Write-Host "====== Select an option for NTP hosting: ======"
  Write-Host "0 - Cancel"
  Write-Host "1 - Use default Newhost (Ecom: 172.20.242.104)"
  Write-Host "2 - Use default Public-Pools (pool.ntp.org)"
  Write-Host "3 - Enter newhost IP or Public-Pool"
  Write-Host "4 - Host on this machine"
  Write-Host "===============================================`n"
}

# Loop through menu
Write-Host "Configuring w32time...`n"
do {
  Menu
  $input = Read-Host -Prompt "Enter"

  switch ($input) {
    # Exit
    "0" { break }
    # Set default
    "1" { 
      Write-Host "`nSetting default newhost..."
      w32tm /config /manualpeerlist:"$defaultNewHost" /update
      Write-Host "Done."
    }
    # Enter new host
    "2" {
      $newhost = Read-Host -Prompt "Enter newhost IP"
      w32tm /config /manualpeerlist:"$newhost" /update
      Write-Host "Done."
    }
    # Host on this machine
    "3" {
      $newhost = Read-Host -Prompt "Enter newhost IP"
      w32tm /config /manualpeerlist:"$publicpool" /update
      Write-Host "Done."
    } 
    "4" {
      Write-Host "Hosting NTP Server with w32tm...`n"
      Write-Host "Setting registery values:"
      Write-Host "Enabling NTP Server hosting..."
      Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer" -Name "Enabled" -Value 1
      Write-Host "Done`n"

      # This should be set automatically, but we set it in case of edge cases.
      Write-Host "Setting announce flags..."
      Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -Name "AnnounceFlags" -Value 5
      Write-Host "Done`n"

      # Defaulting to popular public pool
      Write-Host "Setting peerlist..."
      w32tm /config /manualpeerlist:"$publicPool" /syncfromflags:MANUAL /reliable:YES /update
      Write-Host "Done"
    }     
  } 
} until ($input -eq "0" -or $input -eq "1" -or $input -eq "2" -or $input -eq "3")

# Refresh settings after updating variables, or exit script
if ($input -eq "0") {
  Write-Host "`nShutting Down..."
} else {
  Write-Host "`nRestarting service..."
  Restart-Service w32time
  Write-Host "Done`n"

  Write-Host "Resyncing..."
  w32tm /resync /rediscover
  w32tm /resync /force
  Write-Host "Done`n"

  Write-Host "w32tm setup completed."
}

Write-Host "Printing NTP peers...`n"
w32tm /query /peers

Read-Host "`nPress enter to exit..."
