function Get-DCSyncRights { 
<# 
.SYNOPSIS 
 
This script returns a list of objects in Active Directory that have been granted the DS-Get-Replication-Changes and DS-Get-Replication-Changes-All ExtendedRights on the Domain-DNS, Configuration, and Schema (Schema) objects. 
Objects returned in the output of this script have the privileges required to carry out the DCSync post exploitation technique found in tools like Mimikatz. 
 
Function: Get-DCSyncRights 
Author: Josh M. Bryant 
Required Dependencies: Active Directory Module 
Optional Dependencies: None 
Version: 1.2 
Last Updated: 8/6/2019 1:38PM CST
 
.DESCRIPTION 
 
Lists objects in Active Directory that have been granted the DS-Replication-Get-Changes and DS-Replication-Get-Changes-All ExtendedRight on the Domain-DNS object from all domains in the forest. 
 
.EXAMPLE 
 
Get-DCSyncRights | Export-CSV DCSyncRights.csv -NoType 
 
Exports a list of objects that have the DS-Replication-Get-Changes and DS-Replication-Get-Changes-All ExtendedRight on the Domain-DNS object from all domains in the forest. 
 
.NOTES 
 
This script is designed to help discover non-default ACLs that grant the level of permissions required to carry out attacks like DCSync found in Mimikatz. 
Both the DS-Replication-Get-Changes and DS-Replication-Get-Changes-ALL are required to carry out this type of attack. It can't be done with only 1 of the 2.  
 
.LINK 
 
Blog: http://www.fixtheexchange.com 
Securing Privileged Access: http://aka.ms/privsec 
 
#> 
 
    $Domains = (Get-ADForest).Domains 
    $ReturnInfo = @() 
    ForEach ($Domain in $Domains) { 
        $NetBIOSName = (Get-ADDomain $Domain).NetBIOSName 
        If (-not(Get-PSDrive $NetBIOSName -ErrorAction SilentlyContinue)) { 
            $DC = (Get-ADDomainController -Discover -Domain $Domain -MinimumDirectoryServiceVersion Windows2008 ).hostname -join ("") 
            $PSDrive = New-PSDrive $NetBIOSName -PSProvider ActiveDirectory -Server $DC -Root "//RootDSE/" -Scope Global 
        } 
        $DomainDN = (Get-ADDomain $Domain).DistinguishedName 
        $DSReplicationGetChanges = Get-Acl -Path $NetBIOSName":\$DomainDN" | Select -ExpandProperty Access | Where {($_.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" -and $_.AccessControlType -eq "Allow") -or ($_.ActiveDirectoryRights -eq "GenericAll" -and $_.AccessControlType -eq "Allow")} 
        $DSReplicationGetChangesALL = Get-Acl -Path $NetBIOSName":\$DomainDN" | Select -ExpandProperty Access | Where {($_.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" -and $_.AccessControlType -eq "Allow") -or ($_.ActiveDirectoryRights -eq "GenericAll" -and $_.AccessControlType -eq "Allow")}
        $DSReplicationGetChangesRights = @() 
        $DSReplicationGetChangesALLRights = @() 
        ForEach ($DSReplicationGetChangesRight in $DSReplicationGetChanges) { 
            $DSReplicationGetChangesRights += $DSReplicationGetChangesRight.IdentityReference 
            } 
        ForEach ($DSReplicationGetChangesALLRight in $DSReplicationGetChangesALL) { 
            $DSReplicationGetChangesALLRights += $DSReplicationGetChangesALLRight.IdentityReference 
            } 
        $Properties = @{ 
            "Domain" = $Domain 
            "DS-Replication-Get-Changes" = $DSReplicationGetChangesRights -join(", ") 
            "DS-Replication-Get-Changes-ALL" = $DSReplicationGetChangesALLRights -join(", ") 
            } 
        $Item = New-Object PSObject -Property $Properties 
        $ReturnInfo = $ReturnInfo + $Item 
    } 
    Return $ReturnInfo | Select Domain,DS-Replication-Get-Changes,DS-Replication-Get-Changes-ALL 
} 
