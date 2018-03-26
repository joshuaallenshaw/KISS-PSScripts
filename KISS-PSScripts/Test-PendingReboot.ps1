function Test-PendingReboot
{
	<#
	.SYNOPSIS
		Checks for known flags to see if a windows machine or list of remote machines is in need of restart to apply changes.

	.DESCRIPTION
		Looks in the windows registry for component changes, pending windows updates, pending file renames, and checks WMI for a pending SCCM Reboot.

		Author - Joshua Allen Shaw

	.PARAMETER ComputerName
		String array of remote computers names or IPs.

	.PARAMETER Credential
		Credintial to be used to execute commands.

	.PARAMETER RequiredOnly
		Switch to return true only if Reboot IS required.

	.PARAMETER PassThru
		Switch to return result as Object.

	.EXAMPLE
		Test-PendingReboot
		Returns true if there a system change pending a reboot on the local machine.

	.EXAMPLE
		Test-PendingReboot -ReturnFullResult
		Returns an object containing the result of each value that is checked on the local machine.

	.EXAMPLE
		Test-PendingReboot -ComputerName Machine01,Machine02
		Checks Machine01 and Machine02 for a pending restart and returns the list.

	.EXAMPLE
		Test-PendingReboot -ComputerName Machine01,Machine02 -RequiredOnly -PassThru
		Returns an object containing the results from Machine01 and Machine02 only if they Require a Reboot.

	.EXAMPLE
		Test-PendingReboot -ComputerName Machine01,Machine02 | Restart-Computer
		Checks Machine01 and Machine02 for a pending restart and triggers a remote restart for the machines in need.

	.INPUTS
		String[]
			You can pipe computernames to this function.

		PSCredential
			You can pipe credentials to this function.

	.OUTPUTS
		Bool
			Run on local host returns bool by default.

		String[]
			Run on a list of hosts returns a list of hosts by default.

		PSCustomObject
			A custom object showing all result details is returned when using PassThru.

	.LINKS
		https://joshuaallenshaw.com/kiss/
		https://github.com/joshuaallenshaw/KISS-PSScripts

	.NOTES
		Requires a Minimum PowerShell Version 3.0.
		Adapted from https://gist.github.com/altrive/5329377
	#>
	[CmdletBinding(DefaultParameterSetName='All')]

	Param (
		[parameter(ValueFromPipeLineByPropertyName = $true)]
		[Alias('IPAddress','__Server','CN')]
		[string[]]
		$ComputerName = @($env:COMPUTERNAME),
		[parameter(ValueFromPipeLineByPropertyName = $true)]
		[System.Management.Automation.PSCredential]
		[System.Management.Automation.Credential()]
		$Credential = [System.Management.Automation.PSCredential]::Empty,
		[switch]
		$RequiredOnly,
		[switch]
		$PassThru
	)

	Begin
	{
		[PSCustomObject[]]$rebootResultCollection = @()
		$localHost = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName
		[bool]$localOnly = ($ComputerName.Count -eq 1 -and [System.Net.Dns]::Resolve(($ComputerName[0])).HostName -eq $localHost)

		#Put the working code in a reusable scriptblock
		[ScriptBlock] $scriptBlock = {
			$result = @{
				CBSRebootPending = $false
				FileRenamePending = $false
				SCCMRebootPending = $false
				WURebootRequired = $false
			}
			#Check CBS Registry
			$cbsKey = Get-ChildItem "HKLM:Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -ErrorAction Ignore
			if ($cbsKey -ne $null)
			{
				$result.CBSRebootPending = $true
			}

			#Check PendingFileRenameOperations
			$pendProp = Get-ItemProperty "HKLM:SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -ErrorAction Ignore
			if($pendProp -ne $null)
			{
				$result.FileRenamePending = $true
			}
			else
			{
				Write-Verbose "No Pending File Renames found."
			}

			#Check SCCM Client <http://gallery.technet.microsoft.com/scriptcenter/Get-PendingReboot-Query-bdb79542/view/Discussions#content>
			try
			{
				$sccmStatus = ([wmiclass]"\\.\root\ccm\clientsdk:CCM_ClientUtilities").DetermineIfRebootPending()
			}
			catch
			{
				Write-Verbose "SCCM not found."
			}

			if(($sccmStatus -ne $null) -and $sccmStatus.RebootPending)
			{
				$result.SCCMRebootPending = $true
			}
			#Check Windows Update
			$wuKey = Get-Item "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction Ignore
			if($wuKey -ne $null)
			{
				$result.WURebootRequired = $true
			}
			return $result
		}
	}

	Process
	{
		foreach($name in $ComputerName)
		{
			try
			{
				$resolvedName = [System.Net.Dns]::Resolve(($name)).HostName
			}
			catch
			{
				Write-Verbose $_.Exception.Message
			}
			if($resolvedName -ne $localHost -and $Credential -ne [System.Management.Automation.PSCredential]::Empty -and [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544"))
			{
				#Attempt PSSession
				try
				{
					$session = New-PSSession -ComputerName $resolvedName -Credential $Credential -ErrorAction Stop
				}
				catch
				{
					Write-Verbose $_.Exception.Message
				}
				if($session -ne $null)
				{
					$commandResult = Invoke-Command -Session $session -ScriptBlock $scriptBlock
					Remove-PSSession -Session $session
				}
				else
				{
					Write-Verbose "No Data Collected"
				}
			}
			#Special Handling for localhost
			else
			{
				if($Credential -ne [System.Management.Automation.PSCredential]::Empty -and $resolvedName -eq $localHost -and !([bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")))
				{
					Write-Verbose "Session is not run as administrator.  Provided credentials will be ignored for localhost."
				}
				$commandResult = Invoke-Command -ScriptBlock $scriptBlock
			}
			#Process the results
			$rebootResult = [ordered]@{
					ComputerName = $resolvedName
					CBSRebootPending = $commandResult.CBSRebootPending
					FileRenamePending = $commandResult.FileRenamePending
					SCCMRebootPending = $commandResult.SCCMRebootPending
					WURebootRequired = $commandResult.WURebootRequired
			}
			$rebootResultCollection += New-Object  PSCustomObject -Property $rebootResult
		}
	}

	#Output the Results
	end
	{
		if($rebootResultCollection -ne $null)
		{
			if($requiredOnly)
			{
				$rebootResultCollection = $rebootResultCollection | Where-Object {$_.WURebootRequired -eq $true}
			}

			if($PassThru -and $localOnly)
			{
				return $rebootResultCollection | Select-Object -Property * -ExcludeProperty ComputerName
			}
			elseif($PassThru)
			{
				return $rebootResultCollection
			}
			elseif($localOnly)
			{
				if($rebootResultCollection -match $true)
				{
					return $true
				}
				else
				{
					return $false
				}
			}
			else
			{
				return $rebootResultCollection | Where-Object {$_ -match $true} | Select-Object ComputerName
			}
		}
		else
		{
			Write-Output "Failed to collect any results"
		}
	}
}