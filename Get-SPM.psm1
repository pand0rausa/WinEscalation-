# Kudos to Scott S. This is modded from origonal. 
function Get-SPM
{	

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Credentials to use when connecting to a Domain Controller.")]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory=$false,
        HelpMessage="Domain controller for Domain and Site that you want to query against.")]
        [string]$DomCon,

        [Parameter(Mandatory=$false,
        HelpMessage="Maximum number of Objects to pull from AD, limit is 1,000 .")]
        [int]$Limit = 1000,

        [Parameter(Mandatory=$false,
        HelpMessage="scope of a search as either a base, one-level, or subtree search, default is subtree.")]
        [ValidateSet("Subtree","OneLevel","Base")]
        [string]$SearchScope = "Subtree",

        [Parameter(Mandatory=$false,
        HelpMessage="Distinguished Name Path to limit search to.")]
        [string]$SearchDN,

        [Parameter(Mandatory=$True,
        HelpMessage="Search by domain user, domain group, or SPN service name to search for.")]
        [string]$Type,

        [Parameter(Mandatory=$True,
        HelpMessage="Define search for user, group, or SPN service name. Wildcards are accepted")]
        [string]$Search,

        [Parameter(Mandatory=$false,
        HelpMessage="View minimal information that includes the accounts,affected systems,and registered services.  Nice for getting quick list of DAs.")]
        [string]$List
    )

    Begin
    {        
        
        if ($DomCon -and $Credential.GetNetworkCredential().Password)
        {
            $ObjDomain = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomCon)", $Credential.UserName,$Credential.GetNetworkCredential().Password
            $ObjSearch = New-Object System.DirectoryServices.DirectorySearcher $ObjDomain
        }
        else
        {
            $ObjDomain = [ADSI]""  
            $ObjSearch = New-Object System.DirectoryServices.DirectorySearcher $ObjDomain
        }
    }

    Process
    {	
        
        $CurrDom = $ObjDomain.distinguishedName
        $QGrp = "(&(objectCategory=user)(memberOf=CN=$Search,CN=Users,$CurrDom))"
        $QUsr = "(samaccountname=$Search)"
        $QueryService = "(ServicePrincipalName=$Search)"
        
         
        if(($Type -eq "group") -or ($Type -eq "user") -or ($Type -eq "service")){

            
            switch ($Type) 
            { 
                "group" {$MyFilter = $QGrp} 
                "user" {$MyFilter = $QUsr} 
                "service" {$MyFilter = $QueryService} 
                default {"Invalid query type."}
            }
        }
		
        
        $ObjSearch.PageSize = $Limit
        $ObjSearch.Filter = $Myfilter
        $ObjSearch.SearchScope = $SearchScope

        if ($SearchDN)
        {
            $ObjSearch.SearchDN = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($SearchDN)")
        }

        
        $Records = $ObjSearch.FindAll()
        $RecordCount = $Records.count

        
        if ($RecordCount -gt 0){
                
            
            $DataTable = New-Object System.Data.DataTable 

            
            $DataTable.Columns.Add("Account") | Out-Null
            $DataTable.Columns.Add("Server") | Out-Null
            $DataTable.Columns.Add("Service") | Out-Null            

                            
            $ObjSearch.FindAll() | ForEach-Object {

                                    
                $UserProps = [ordered]@{}                    
                $UserProps.Add('Name', "$($_.properties.name)")
                $UserProps.Add('SAMAccount', "$($_.properties.samaccountname)")
                $UserProps.Add('Description', "$($_.properties.description)")
                $UserProps.Add('UserPrincipal', "$($_.properties.userprincipalname)")
                $UserProps.Add('DN', "$($_.properties.distinguishedname)")
                $UserProps.Add('Created', [dateTime]"$($_.properties.whencreated)")
                $UserProps.Add('LastModified', [dateTime]"$($_.properties.whenchanged)")
                $UserProps.Add('PasswordLastSet', [dateTime]::FromFileTime("$($_.properties.pwdlastset)"))                    
                $UserProps.Add('AccountExpires',( &{$exval = "$($_.properties.accountexpires)"
                    If (($exval -eq 0) -or ($exval -gt [DateTime]::MaxValue.Ticks))
                    {
                        $AcctExpires = "<Never>"
                        $AcctExpires
                    }Else{
                        $Date = [DateTime]$exval
                        $AcctExpires = $Date.AddYears(1600).ToLocalTime()
                        $AcctExpires
                    }
                }))
                $UserProps.Add('LastLogon', [dateTime]::FromFileTime("$($_.properties.lastlogon)"))
                $UserProps.Add('GroupMembership', "$($_.properties.memberof)")
                $UserProps.Add('SPN Count', "$($_.properties['ServicePrincipalName'].count)")                 

                
                If (!$list){

                    
                    Write-Verbose " "
                    [pscustomobject]$UserProps 
                }

                
                $SPN_Count = $_.properties['ServicePrincipalName'].count
                if ($SPN_Count -gt 0)
                {
                        
                    
                    If (!$list){
                        Write-Output "ServicePrincipalNames (SPN):"
                            $_.properties['ServicePrincipalName']
                    }
                        
                    
                    foreach ($item in $_.properties['ServicePrincipalName'])
                    {
                        $SpnServer =  $item.split("/")[1].split(":")[0]	
                        $SpnService =  $item.split("/")[0]                                                    
                        $DataTable.Rows.Add($($_.properties.samaccountname), $SpnServer, $SpnService) | Out-Null  
                    }
                }            
                    
                
                If (!$list){
                    Write-Verbose " "
                    Write-Verbose "-------------------------------------------------------------"
                }
            } 

            
            If (!$list){

                
                Write-Verbose "Found $RecordCount accounts that matched your search."   
                Write-Verbose "-------------------------------------------------------------"
                Write-Verbose " "                                    
            }else{

                
                $DataTable |  Sort-Object Account,Server,Service | select account,server,service -Unique
            }
        }else{

            
            Write-Verbose " " 
            Write-Verbose "No records were found that match your search."
            Write-Verbose ""
        }        
    }
}
