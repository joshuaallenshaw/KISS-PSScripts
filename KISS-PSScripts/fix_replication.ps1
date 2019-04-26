Get-VmReplication | get-vm | Where-Object {$_.state -eq "Running"} | Get-VMReplication | Where-Object { $_.Health -like "Critical"} | Foreach-Object { Resume-VMReplication $_.Name -Resynchronize }

