$MessageString = ""
$ExitCode = 0
Get-VmReplication | get-vm | Where-Object {$_.state -eq "Running"} | get-VmReplication | foreach-object {
    $MessageString += "Replication on $($_.Name) is in $($_.Health) Condition "
	if ($_.Health -like "Warning") { 
		if ($ExitCode -lt 1) { $ExitCode = 1}
	} elseif ($_.Health -like "Critical" -and $_.State -notlike "Resynchronizing") { 
		if ($ExitCode -lt 2) { $ExitCode = 2}
	}
}
write-host $MessageString
exit $ExitCode
