Function Remove-OldADProfiles
{
    <#
    .SYNOPSIS
        Removes old AD profiles from local computer.

    .DESCRIPTION
        Searches local accounts for domain users and removes profiles that are not longer
        present in AD or that have not been logged into with the specified retentiontime.

    .PARAMETER RemoveOldProfiles
        Switch.  Removes profiles by date, not just by AD presence.

    .PARAMETER RetentionTime
        Integer. Time, in days, that classifies a profile for removal.  Defaults to 90.

    .PARAMETER LogPath
        String.  Enables logging to path specified.

    .PARAMETER Whatif
        Dry Run.

    .EXAMPLE
        Remove-OldADProfiles -RemoveOldProfiles

        Removes any AD Profile that has been removed from AD.  Removes any AD profile that has not been used in 90 Days.
    #>
    [CmdletBinding(SupportsShouldProcess)]

        Param (
            [switch]$RemoveOldProfiles,
            [int]$RetentionTime = 90,
            [string]$LogPath = $null
        )
    Begin
    {
        # Start Logging.
        if($LogPath)
        {
            try
            {
                $logFolder = Split-Path $LogPath -Parent
                if (!(Test-Path $logFolder))
                {
                    New-Item -ItemType Directory -Force -Path $logFolder
                }
                # Lets attempt a stop, just in case you hit Ctrl+C as soon as you started the first time around.
                try
                {
                    Stop-Transcript | Out-Null
                }
                catch{}
                finally
                {
                    $oVP = $VerbosePreference
                    $VerbosePreference = 'continue'
                    $oWP = $WarningPreference
                    $WarningPreference = 'continue'
                    $transcript = Start-Transcript -Path $LogPath -Force
                }
            }
            catch
            {
                Write-Verbose $_.Exception.Message
                $LogPath = $null
            }
        }
        # Make sure we have admin permissions
        if (!([bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")))
        {
            Write-Verbose "Cannot run in System mode without administrative permissions."
            Exit 126
        }
        Write-Verbose "Cleaning AD user accounts from system."
        # Get Local Accounts
        $LocalUsers = Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount = 'True'"
        Write-Verbose "Ignoring local users:"
        $LocalUsers.Caption | Write-Verbose
        # Get non-Admin AD Accounts
        $ADUsers = Get-CimInstance -ClassName Win32_UserProfile -Filter "Special = 'False'"| Where-Object { $_.SID -notmatch '-500$' -and $_.SID -notin $localUsers.SID }
        Write-Verbose "The following SIDs are for AD users:"
        $ADUsers.SID | Write-Verbose
        # Vars for remote commands to AD Server
        $session = New-PSSession -Computer $ENV:LOGONSERVER.Replace('\\','')
        $scriptBlock = {
            $userSIDsToRemove =@();
            foreach ($arg in $args) {
                try { Get-ADUser -Identity $arg }
                catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] { $userSIDsToRemove += $arg }
            }
            return $userSIDsToRemove
        }
    }
    Process
    {
        # Get profiles for AD accounts that were deleted.
        if($session -ne $null){
            $userSIDsToRemove = Invoke-Command -session $session -scriptBlock $scriptBlock -Args $ADUsers.SID
            Write-Verbose "The following AD SIDs not found:"
            $userSIDsToRemove | Write-Verbose
            Remove-PSSession -Session $session
        }
        # Get Profiles for AD accounts that have not been used locally for a long time.
        if ($RemoveOldProfiles){
            $oldADUsers = $ADUsers | Where-Object { $ADUsers.SID -notin $userSIDsToRemove -and (Get-Date $_.LastUseTime) -lt (Get-Date).AddDays(-$RetentionTime) }
            Write-Verbose "The following AD SIDs have not logged in within $($RetentionTime):"
            Write-Verbose $oldADUsers

            $userSIDsToRemove += $oldADUsers
        }
        # Remove the selected profiles
        Get-CimInstance -ClassName Win32_UserProfile | Where-Object { $_.SID -in $userSIDsToRemove } | Where-Object {
            $PSCmdlet.ShouldProcess("$($_.SID)",'Remove Profile') } | Remove-CimInstance
    }
    End
    {
        # Stop Logging if it was started.
        if($transcript)
        {
            try
            {
                if ($oVP -ne $null -or $oWP -ne $null)
                {
                    $VerbosePreference = $oVP
                    $WarningPreference = $oWP
                }
                Stop-Transcript
            }
            catch
            {
                Write-Verbose $_.Exception.Message
            }
        }
    }
}