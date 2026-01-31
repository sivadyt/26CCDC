Import-Module GroupPolicy 
Import-Module ActiveDirectory
$TargetDn = (Get-ADDomain).DistinguishedName
$GpoName = "GP Refresh" 
$gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue 
if (-not $gpo) { $gpo = New-GPO -Name $GpoName } 
New-GPLink -Name $GpoName -Target $TargetDn -LinkEnabled Yes -ErrorAction SilentlyContinue | Out-Null 
$k = "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" 
Set-GPRegistryValue -Name $GpoName -Key $k -ValueName "GroupPolicyRefreshTime" -Type DWord -Value 2 
Set-GPRegistryValue -Name $GpoName -Key $k -ValueName "GroupPolicyRefreshTimeOffset" -Type DWord -Value 0 
Set-GPRegistryValue -Name $GpoName -Key $k -ValueName "GroupPolicyRefreshTimeDC" -Type DWord -Value 2 
Set-GPRegistryValue -Name $GpoName -Key $k -ValueName "GroupPolicyRefreshTimeOffsetDC" -Type DWord -Value 0 
Write-Host "Created/updated GPO '$GpoName' and linked to '$TargetDn' with refresh=2 and offset=0 (computers + domain controllers)."