$objShell = New-Object -com "Wscript.Shell"
$messages= @()
$messages += "I see that you have a web browser open... `n`nPlease be careful!"
$messages += "This computer was recently infected with a root kit virus... `n`nI bet you are responsible for that."
$messages += "Make sure that link is safe before you click on it!"
$messages += "Shall I run a virus scan for you?....It hasn't been scanned in the last 10 minutes."
$messages += "I'm Watching you!"
$messages += "Be careful!  The web is not for the faint of heart!"
$messages += "Do you know what you did to me?... `n`n I was so sick I nearly died!"
$messages += "Go eat your pop-corn!"
$count = 15
Do {
	If (get-process chrome*,firefox*,iexplorer*){
		0..$($Messages.length - 1) | Get-Random -Count 35 | select -first 1 | ForEach {
			$objShell.Popup($messages[$_],60,"Careful",48)
		}
	}
	$count--
	sleep 1800
} while ($count -gt 0)