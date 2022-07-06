function scan-windows {
# Will scan for common misconfigurations in Windows as a non-priv user.
# Things it looks for:
# PowerShell console command history, Environment variables, stored wireless credentials, Symantec reg values (some require admin privs to see), 
# Kerberos tickets, dump powershell profiles, dump sysprep configs\admin creds, search both "Program Files" directories for writable files,
# Find services that can be overwritten
# Output is mostly to console.

$outfile = "$home\Documents\Temp\"

Write-host "Checking history: "
Get-History

Write-Host "Getting ENV Variables: "
Get-ChildItem env:\

write-host "Dumping wireless creds"
netsh wlan export profile key=clear

# Check Symantec
Write-Host "Checking Symantect reg keys: "
Get-ItemProperty  HKLM:\"SOFTWARE\Symantec\Symantec Endpoint Protection\SMC\SSHelper\" -Name "message"
Get-Content HKLM:"\Symantec\Symantec Endpoint Protection\AV\Exclusions\ScanningEngines\Directory"
Get-Content HKLM:"\SOFTWARE\Symantec\Symantec Endpoint Protection\AV\Exclusions\ScanningEngines\FileName"
Get-Content HKLM:"\SOFTWARE\Symantec\Symantec Endpoint Protection\AV\Exclusions\ScanningEngines\Extensions\"

Write-Host "List Kerberos tickets"
klist

Write-Host "List RDP sessions"
qwinsta

Write-Host "List Processes"
Get-Process | select name,id


# Check contents of PowerShell Profiles
Write-Host "Show PowerShell profile for all users and shells: "
$profile1 = "$env:windir\system32\WindowsPowerShell\1.0\profile.ps1"
Write-Host "$profile1"
Get-Content $profile1

Write-Host "Show PowerShell profile (applies to all users but only Microsoft.PowerShell shell): "
$profile2 = "$env:windir\system32\WindowsPowerShell\1.0\Microsoft.PowerShell_profile.ps1"
Write-Host "$profile2"
Get-Content $profile2

Write-Host "Show PowerShell profile for current user and all shells: "
$profile3 = "$env:USERPROFILE\My Documents\WindowsPowerShell\profile.ps1"
Write-Host "$profile3"
Get-Content $profile3

# Check for Sysprep files
Write-Host "Searching sysprep files: "

gc "c:\sysprep.inf" -ErrorAction SilentlyContinue | Select-String -SimpleMatch "AdminPassword=" 
gc "c:\sysprep.inf" -ErrorAction SilentlyContinue | Select-String -SimpleMatch "DomainAdmin="
gc "c:\sysprep.inf" -ErrorAction SilentlyContinue | Select-String -SimpleMatch "DomainAdminPassword="

Write-host "Checking c:\sysprep\sysprep.xml"
$sysprep1 = Select-Xml //UserAccounts  "c:\sysprep\sysprep.xml" -ErrorAction SilentlyContinue | ForEach-Object {$_.Node.InnerText}
Write-Host -ForegroundColor Red "$sysprep1"

Write-host "Checking $env:windir\Panther\Unattend\Unattended.xml"
$sysprep2 = Select-Xml //UserAccounts  "$env:windir\Panther\Unattend\Unattended.xml" -ErrorAction SilentlyContinue | ForEach-Object {$_.Node.InnerText}
Write-Host -ForegroundColor Red "$sysprep2"

Write-host "Checking $env:windir\Panther\Unattended.xml"
$sysprep3 = Select-Xml //UserAccounts  "$env:windir\Panther\Unattended.xml" -ErrorAction SilentlyContinue | ForEach-Object {$_.Node.InnerText}
Write-Host -ForegroundColor Red "$sysprep3"

#Get powershell history
Write-host "Checking for PowerShell history"
# $users = (gci -Path c:\users).Name; foreach($user in $users){$user;gc "c:\users\$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"}
$users = (gci -Path c:\users).Name
foreach($user in $users){
    $user
    gc "c:\users\$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
}

# Look for Az token files
foreach($user in $users){$user; cd "c:\users\$user\.Azure\"; ls; gc AzureRmContext.json}
foreach($user in $users){$user; cd "c:\users\$user\.Azure\"; ls; gc accessTokens.json}

$childs = Get-ChildItem 'C:\Program Files*' -Recurse -ErrorAction SilentlyContinue
$Cim = Get-CimInstance -class win32_service
$line = $Cim.PathName | Where-Object {$_ -notlike "*svchost.exe*" } | where-object {$_ -notlike "*dllhost.exe*"}
$ServiceStrings = $line -replace '"', ""
$ServiceStrings = $ServiceStrings -replace "(?<=.exe ).*"

# Search Program Files for bad ACLs
Write-host "File/folder with bad ACLs: "
foreach ($child in $childs){
$childfile = Convert-Path $child.PSPath
$ErrorActionPreference = "SilentlyContinue"
$Path = %{Get-Acl -filter * -Path "$childfile"} 
$finder = $Path.Access | where {$_.IdentityReference -like "NT AUTHORITY\Authenticated Users" -or $_.IdentityReference -like "BUILTIN\Users" -and $_.FileSystemRights -like "FullControl"} | Select-Object FileSystemRights,IdentityReference,IsInherited | ft -Wrap -HideTableHeaders
    if ($finder){
        Write-host "$childfile" -ForegroundColor red | out-file $outfile\BadACLs.txt -Append
       
    }

}
Write-Host ""

# Match services with exe's that are world writable
Write-Host "Scanning for writable/replacable services due to bad ACLs: "
Write-host "Should take about 8 minutes to run against C:\Program Files and C:\Program Files (x86)."

foreach ($child in $childs){
$childfile = Convert-Path $child.PSPath
$ErrorActionPreference = "SilentlyContinue"
$Path = %{Get-Acl -filter * -Path "$childfile"} 
$finder = $Path.Access | where {$_.IdentityReference -like "NT AUTHORITY\Authenticated Users" -or $_.IdentityReference -like "BUILTIN\Users" -and $_.FileSystemRights -like "FullControl"} | Select-Object FileSystemRights,IdentityReference,IsInherited | ft -Wrap -HideTableHeaders

   
    if ($finder){

        foreach ($service1 in $ServiceStrings){
 
            $compare = Compare-Object -DifferenceObject $service1 -ReferenceObject $childfile -IncludeEqual -ExcludeDifferent | select InputObject | ft -HideTableHeaders 
            $compare

        }

    }

}


write-host ""
write-host "Checking for unquoted services:"
if ($unquoted = $cim | select name,startmode,pathname | where {($_.startmode -eq "Auto") -and ($_.pathname -notlike "*C:\Windows*") -and ($_.pathname -notlike "`"*")}){
    $unquoted
    }
    else{
    write-host "-No results-"
    }

# Scan for common config files
$commonfiles = Get-ChildItem -Path c:\ -include ('*.ica', '*.ora', '*.bat', '*.ps1', '*.sql', '*.rdp', 'Applicationhost.config', 'accessTokens.json', '*.config', '*.xml', '*.cer', '*.pem', '*.pfx') -Exclude "c:\Windows.old" -Recurse -File -Name
foreach ($commonfile in $commonfiles){write-host "c:\$commonfile" -ForegroundColor Red; gc "c:\$commonfile" | Select-String "password"}

}
