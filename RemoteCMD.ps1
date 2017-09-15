function Run-RemoteCMD { 
 
    param( 
    [Parameter(Mandatory=$true,valuefrompipeline=$true)] 
    [string]$compname) 
    begin { 
        $command = Read-Host " Enter command to run" 
        [string]$cmd = "CMD.EXE /C " +$command 
                        } 
    process { 
        $newproc = Invoke-WmiMethod -class Win32_process -name Create -ArgumentList ($cmd) -ComputerName $compname 
        if ($newproc.ReturnValue -eq 0 ) 
                { Write-Output " Command $($command) invoked Sucessfully on $($compname)" } 
                # if command is sucessfully invoked it doesn't mean that it did what its supposed to do 
                #it means that the command only sucessfully ran on the cmd.exe of the server 
                #syntax errors can occur due to user input  
     
     
     
     
    } 
    End{Write-Output "Script ...END"} 
                 } 
