# KISS-PSScripts
A collection of PowerShell Scripts published through my Keep IT Simple Blog, see https://joshuaallenshaw.com/kiss/. 

## About These Scripts
I use most of these scripts in my day-to-day IT work.  I hope you find them useful.  Please let me know if you find any problems.

### Prerequisites
Nearly all of these scripts require Windows PowerShell 3.0 or better.  Each script has the minimum PS version in the comments.

### Installing

[A Simple PowerShell Module](http://joshuaallenshaw.com/kiss/powershell/a-simple-powershell-module/) - One easy way to add these to a module for easy use.

If you prefer to run them outright you can do that to.  Almost all of my scripts are functions.  You just need to dot source them.
```powershell
. Function-Name.ps1 #Loads the function.
Function-Name -FunctionParameters #Executes the function
```

## Directory

* **Test-PendingReboot** - Used to determine is a machine has changes pending a reboot or changes requiring a reboot.  Pipeline input and output supported.

* **Clean-Disk** - Used to free space by removing temporary, outdated, and junk files.
