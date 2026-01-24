<#
CCDC Blue Team Lockdown (Domain-Joined Member Server / Workstation) - Windows

HARDENING ACTIONS:
- Prompts for: DC IP, new local admin username + password, inbound TCP/UDP ports to allow.
- Creates/ensures local admin user and adds to local Administrators.
- Disables all other local accounts (but NEVER disables the account currently running the script).
- Sets local password + lockout policy (note: domain GPO may override on domain-joined systems).
- Firewall: disables all inbound rules, sets default inbound/outbound = Block, then:
    - Allows ONLY the inbound TCP/UDP ports you enter
    - Allows outbound DNS (53), HTTP/HTTPS (80/443)
    - Allows outbound AD/DC traffic to the DC IP (Kerberos/LDAP/SMB/RPC/NTP)
- Disables: Print Spooler, RemoteRegistry, SMBv1, RDP
- Enables Defender + real-time + cloud (best effort)

NOTES:
- Refuses to run on a Domain Controller.
- Run from console/VM access. This can cut off remote access.
#>

#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# -------------------------
# Quiet helpers
# -------------------------
function Write-Info([string]$msg) { Write-Host $msg }
function Try-Ignore([scriptblock]$sb) { try { & $sb | Out-Null } catch {} }

# -------------------------
# GUARD: refuse to run on a Domain Controller
# -------------------------
try {
    $cs = Get-CimInstance Win32_ComputerSystem
    if ($cs.DomainRole -ge 4) { throw "Refusing to run on a Domain Controller (DomainRole=$($cs.DomainRole))." }
} catch {
    Write-Error $_
    exit 1
}

# -------------------------
# Input functions
# -------------------------
function Read-NonEmpty([string]$Prompt) {
    while ($true) {
        $v = Read-Host $Prompt
        if (-not [string]::IsNullOrWhiteSpace($v)) { return $v.Trim() }
    }
}

function Read-Ports([string]$Prompt) {
    while ($true) {
        $raw = Read-Host $Prompt
        if ([string]::IsNullOrWhiteSpace($raw)) { continue }

        $parts = $raw -split '[,\s]+' | Where-Object { $_ -and $_.Trim() -ne "" }

        $ports = @()
        $ok = $true
        foreach ($p in $parts) {
            if ($p -notmatch '^\d+$') { $ok = $false; break }
            $n = [int]$p
            if ($n -lt 1 -or $n -gt 65535) { $ok = $false; break }
            $ports += $n
        }

        if (-not $ok -or -not $ports) { continue }
        return ($ports | Sort-Object -Unique)
    }
}

# -------------------------
# PROMPTS
# -------------------------
$DomainControllerIP = Read-NonEmpty "Domain Controller IP (DC/DNS)"
$NewAdminUser       = Read-NonEmpty "NEW local admin username"
$SecurePassword     = Read-Host "Password for $NewAdminUser" -AsSecureString

$InboundTcpPorts    = Read-Ports "Inbound TCP ports to ALLOW (e.g., 80,443)"
$InboundUdpPorts    = Read-Ports "Inbound UDP ports to ALLOW (e.g., 53,123)"

$CurrentUserName = $env:USERNAME

# Policies (best effort; domain GPO may override)
$MinPwLen               = 14
$MaxPwAgeDays           = 90
$LockoutThreshold       = 5
$LockoutDurationMinutes = 15
$LockoutWindowMinutes   = 15

# -------------------------
# Account functions
# -------------------------
function Ensure-LocalAdminUser {
    param(
        [Parameter(Mandatory)] [string]$Username,
        [Parameter(Mandatory)] [securestring]$Password
    )

    $existing = Get-LocalUser -Name $Username -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-LocalUser -Name $Username -Password $Password -FullName $Username `
            -Description "CCDC Blue Team Local Admin" -PasswordNeverExpires:$false | Out-Null
    } else {
        $existing | Set-LocalUser -Password $Password
        if ($existing.Enabled -eq $false) { Enable-LocalUser -Name $Username }
    }

    $isMember = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match "\\$Username$" -or $_.Name -ieq $Username }

    if (-not $isMember) { Add-LocalGroupMember -Group "Administrators" -Member $Username }
}

function Disable-AllOtherLocalAccounts {
    param(
        [Parameter(Mandatory)] [string]$KeepUser,
        [Parameter(Mandatory)] [string]$AlsoKeepUser
    )

    foreach ($u in Get-LocalUser) {
        if ($u.Name -ieq $KeepUser) { continue }
        if ($u.Name -ieq $AlsoKeepUser) { continue }
        if ($u.Enabled) { Try-Ignore { Disable-LocalUser -Name $u.Name } }
    }
}

function Set-LocalAccountPolicies {
    param(
        [int]$MinLength,
        [int]$MaxAgeDays,
        [int]$LockThreshold,
        [int]$LockDurationMinutes,
        [int]$LockWindowMinutes
    )

    Try-Ignore { & net accounts /minpwlen:$MinLength }
    Try-Ignore { & net accounts /maxpwage:$MaxAgeDays }
    Try-Ignore { & net accounts /lockoutthreshold:$LockThreshold }
    Try-Ignore { & net accounts /lockoutduration:$LockDurationMinutes }
    Try-Ignore { & net accounts /lockoutwindow:$LockWindowMinutes }

    # Complexity via secedit (best effort)
    Try-Ignore {
        $tmp = Join-Path $env:TEMP "ccdc_secpol.inf"
        $db  = Join-Path $env:TEMP "ccdc_secpol.sdb"
        & secedit /export /cfg $tmp | Out-Null
        $content = Get-Content $tmp -Raw

        if ($content -notmatch "\[System Access\]") { $content += "`r`n[System Access]`r`n" }

        if ($content -match "PasswordComplexity\s*=") {
            $content = [regex]::Replace($content, "PasswordComplexity\s*=\s*\d+", "PasswordComplexity = 1")
        } else {
            $content = $content -replace "(\[System Access\]\s*)", "`$1`r`nPasswordComplexity = 1`r`n"
        }

        Set-Content -Path $tmp -Value $content -Encoding Unicode
        & secedit /configure /db $db /cfg $tmp /areas SECURITYPOLICY | Out-Null
        & gpupdate /force | Out-Null
    }
}

# -------------------------
# Firewall
# -------------------------
function Set-CCDCFirewallLockdown {
    param(
        [Parameter(Mandatory)] [string]$DCIP,
        [Parameter(Mandatory)] [int[]]$AllowInboundTcpPorts,
        [Parameter(Mandatory)] [int[]]$AllowInboundUdpPorts
    )

    # Disable all inbound rules
    Try-Ignore { Get-NetFirewallRule -Direction Inbound -ErrorAction SilentlyContinue | Disable-NetFirewallRule -ErrorAction SilentlyContinue }

    # Default block all
    Try-Ignore {
        Set-NetFirewallProfile -Profile Domain,Public,Private `
            -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block
    }

    $tcpLabel = ($AllowInboundTcpPorts -join ",")
    $udpLabel = ($AllowInboundUdpPorts -join ",")

    # Allow ONLY specified inbound ports
    Try-Ignore {
        New-NetFirewallRule -DisplayName "CCDC ALLOW IN TCP ($tcpLabel)" `
            -Direction Inbound -Action Allow -Protocol TCP -LocalPort $AllowInboundTcpPorts -Profile Any | Out-Null
    }
    Try-Ignore {
        New-NetFirewallRule -DisplayName "CCDC ALLOW IN UDP ($udpLabel)" `
            -Direction Inbound -Action Allow -Protocol UDP -LocalPort $AllowInboundUdpPorts -Profile Any | Out-Null
    }

    # Outbound baseline
    Try-Ignore {
        New-NetFirewallRule -DisplayName "CCDC ALLOW OUT DNS UDP 53" `
            -Direction Outbound -Action Allow -Protocol UDP -RemotePort 53 -Profile Any | Out-Null
    }
    Try-Ignore {
        New-NetFirewallRule -DisplayName "CCDC ALLOW OUT DNS TCP 53" `
            -Direction Outbound -Action Allow -Protocol TCP -RemotePort 53 -Profile Any | Out-Null
    }
    Try-Ignore {
        New-NetFirewallRule -DisplayName "CCDC ALLOW OUT HTTP/HTTPS" `
            -Direction Outbound -Action Allow -Protocol TCP -RemotePort 80,443 -Profile Any | Out-Null
    }

    # Outbound to DC only (AD essentials)
    $dc = $DCIP
    $rules = @(
        @{N="Kerberos TCP 88"; P="TCP"; R=88}
        @{N="Kerberos UDP 88"; P="UDP"; R=88}
        @{N="Kerberos TCP 464"; P="TCP"; R=464}
        @{N="Kerberos UDP 464"; P="UDP"; R=464}
        @{N="LDAP TCP 389"; P="TCP"; R=389}
        @{N="LDAP UDP 389"; P="UDP"; R=389}
        @{N="LDAPS TCP 636"; P="TCP"; R=636}
        @{N="GC TCP 3268"; P="TCP"; R=3268}
        @{N="GC SSL TCP 3269"; P="TCP"; R=3269}
        @{N="SMB TCP 445"; P="TCP"; R=445}
        @{N="RPC TCP 135"; P="TCP"; R=135}
        @{N="NTP UDP 123"; P="UDP"; R=123}
    )

    foreach ($r in $rules) {
        Try-Ignore {
            New-NetFirewallRule -DisplayName ("CCDC ALLOW OUT {0} to DC" -f $r.N) `
                -Direction Outbound -Action Allow -Protocol $r.P -RemoteAddress $dc -RemotePort $r.R -Profile Any | Out-Null
        }
    }

    # RPC dynamic ports to DC
    Try-Ignore {
        New-NetFirewallRule -DisplayName "CCDC ALLOW OUT RPC Dynamic TCP 49152-65535 to DC" `
            -Direction Outbound -Action Allow -Protocol TCP -RemoteAddress $dc -RemotePort 49152-65535 -Profile Any | Out-Null
    }

    # Allow outbound ICMPv4 (ping)
    Try-Ignore {
        New-NetFirewallRule -DisplayName "CCDC ALLOW OUT ICMPv4" `
            -Direction Outbound -Action Allow -Protocol ICMPv4 -Profile Any | Out-Null
    }
}

# -------------------------
# Disable services/features
# -------------------------
function Disable-Services-And-Features {
    Try-Ignore { Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue }
    Try-Ignore { Set-Service  -Name Spooler -StartupType Disabled }

    Try-Ignore { Stop-Service -Name RemoteRegistry -Force -ErrorAction SilentlyContinue }
    Try-Ignore { Set-Service  -Name RemoteRegistry -StartupType Disabled }

    Try-Ignore { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force | Out-Null }
    Try-Ignore { Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null }

    # RDP off
    Try-Ignore { Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1 }
    Try-Ignore { Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue | Disable-NetFirewallRule -ErrorAction SilentlyContinue }
}

# -------------------------
# Defender
# -------------------------
function Enable-DefenderProtections {
    Try-Ignore { Set-Service -Name WinDefend -StartupType Automatic -ErrorAction SilentlyContinue }
    Try-Ignore { Start-Service -Name WinDefend -ErrorAction SilentlyContinue }

    Try-Ignore { Set-MpPreference -DisableRealtimeMonitoring $false }
    Try-Ignore { Set-MpPreference -MAPSReporting 2 }
    Try-Ignore { Set-MpPreference -SubmitSamplesConsent 1 }
    Try-Ignore { Set-MpPreference -DisableBehaviorMonitoring $false }
}

# -------------------------
# RUN (minimal output)
# -------------------------
Write-Info "Running CCDC lockdown..."

Ensure-LocalAdminUser -Username $NewAdminUser -Password $SecurePassword
Disable-AllOtherLocalAccounts -KeepUser $NewAdminUser -AlsoKeepUser $CurrentUserName
Set-LocalAccountPolicies -MinLength $MinPwLen -MaxAgeDays $MaxPwAgeDays `
    -LockThreshold $LockoutThreshold -LockDurationMinutes $LockoutDurationMinutes -LockWindowMinutes $LockoutWindowMinutes
Set-CCDCFirewallLockdown -DCIP $DomainControllerIP -AllowInboundTcpPorts $InboundTcpPorts -AllowInboundUdpPorts $InboundUdpPorts
Disable-Services-And-Features
Enable-DefenderProtections

Write-Info "Done. Reboot recommended."
