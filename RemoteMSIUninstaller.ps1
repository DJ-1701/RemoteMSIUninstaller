# Enter the Display Name for the product you wish to uninstall"
#
# Display Names for MSI products installed can be found under the curly bracket registry keys in
# HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall and
# HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall
#
$DisplayName = "Quicktime"

function funcAdminCheck ()
{
    # Admin Check Function: http://blogs.technet.com/b/heyscriptingguy/archive/2011/05/11/check-for-admin-credentials-in-a-powershell-script.aspx
    If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
        [Security.Principal.WindowsBuiltInRole] "Administrator"))
    {
        Write-Warning "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!"
        Write-Host
        Write-Host "Ending Script in 10 seconds."
        Start-Sleep -s 10
        Break
    }
}

function funcQueryNewMachine ()
{
    Write-Host
    $ynNewSearch = Read-Host "Would you like to uninstall $DisplayName from another computer? (Y/N)"
    if ($ynNewSearch -eq 'n')
    {
        Break
    }
}

function funcRemoteUninstall ()
{
    Invoke-Command -ComputerName $computer -ArgumentList $DisplayName -ScriptBlock `
    {
        param($DisplayName)
        $SoftwareDetected = 0
        Write-Host "What we want to remove: $DisplayName"
        Write-Host "Computer Name: $env:COMPUTERNAME"
        function CheckUninstall ()
        {
            ForEach ($Record in $NUninstall)
            {
                $CurrentKey = Get-ItemProperty ($Record.Name.Replace("HKEY_LOCAL_MACHINE","HKLM:"))
                If ($CurrentKey.DisplayName -ne $null)
                {
                    If ($CurrentKey.DisplayName.ToLower().Contains($DisplayName.ToLower()))
                    {
                        $SoftwareDetected = 1
                        Write-Host "Software Publisher: $($CurrentKey.Publisher)"
                        Write-Host "Software Name: $($CurrentKey.DisplayName)"
                        If ($CurrentKey.UninstallString.ToLower().Contains("msiexec.exe"))
                        {
                            Write-Host "Registry Uninstall String: $($CurrentKey.UninstallString)"
                            $UninstallString = $CurrentKey.UninstallString.Replace("/I","/X")
                            If (!($UninstallString.ToLower().Contains("/qn")))
                            {
                                $UninstallString = "$UninstallString /qn"
                                $MsiExec = "C:\Windows\System32\msiexec.exe"
                                $Arg = $UninstallString -ireplace [regex]::Escape("msiexec.exe "), ""
                                Write-Host "Corrected Silent Uninstall String: $MsiExec $Arg"
                                Start-Process $MsiExec $Arg -NoNewWindow -Wait
                                Write-Host "Uninstall Executed."
                            }
                        }
                    }
                }
            }
        }
        $NUninstall = Get-ChildItem HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall -Recurse -Include `{*`} -ErrorAction SilentlyContinue
        . CheckUninstall
        $NUninstall = Get-ChildItem HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall -Recurse -Include `{*`} -ErrorAction SilentlyContinue
        . CheckUninstall
        If ($SoftwareDetected -eq 0)
        {
            Write-Host "$DisplayName was not found on $($env:ComputerName)."
        }
    }
    . funcQueryNewMachine
}

function funcDNSVerify ()
{
    # This function is used to ensure:
    #
    # A) The computer requested is turned on.
    # B) WMI can connect to the computer.
    # C) The computer returns the correct name (just in case of DNS issues).
    #
    # This function also returns relevant information from the computer, such as username and domain.
    #
    # Please note, if an IP 4 address is used instead of a computer name, item C
    # (DNS Check) would then obviously not be checked (as IPs are not names).

    $PingSuccessful = 0
    $WMISuccessful = 0
    $CorrectName = 0
    $ConnectionInfo = Test-Connection -ComputerName $computer -count 1 -ErrorAction "SilentlyContinue"
    if ($?)
    {
        # If there is a response using the computer name specified.
        $PingSuccessful = 1
        $ComputerInfo = Get-WmiObject -class Win32_ComputerSystem -computer $ConnectionInfo.IPV4Address -ErrorAction "SilentlyContinue"
        if ($?)
        {
            # If WMI can be accessed using the computer name specified.
            $WMISuccessful = 1
            if (($computer -eq $ComputerInfo.Name) -or ($computer -eq $ComputerInfo.Name + "." + $ComputerInfo.Domain) -or ($computer -eq $ConnectionInfo.IPV4Address))
            {
                # If the computer name specified matches the name record in WMI (confirmation that DNS resolved correctly).
                $CorrectName = 1
                . funcRemoteUninstall
            }
            else
            {
                # If the computer name specified does not match the name record in WMI (potential DNS resolution failure).
                $CorrectName = 0
                Write-Warning "The computer name returned via WMI is different to the name searched for. There may be a conflict in DNS."
                . funcQueryNewMachine
            }
        }
        else
        {
            # If WMI is inaccessible using the computer name specified.
            $WMISuccessful = 0
            Write-Warning "The WMI query to the computer request has failed. Please ensure the computer you are trying to access has WMI enabled and your account is an Administrator of that machine."
            . funcQueryNewMachine
        }
    }
    else
    {
        # If there is no response using the computer name specified.
        $PingSuccessful = 0
        Write-Warning "Ping was unsuccessful to the computer requested. Please ensure the computer is turned on and try again."
        . funcQueryNewMachine
    }
}

function funcNewMachine ()
{
    $computer = Read-Host "Which computer would you like to remove $DisplayName from?"
    if ($computer -eq '')
    {
        $computer = $env:COMPUTERNAME
    }
    . funcDNSVerify
}

<#
****************
* Main Program *
****************
#>

Clear-Host
. funcAdminCheck
Do
{
    Clear-Host
    . funcNewMachine
}
While (1)
