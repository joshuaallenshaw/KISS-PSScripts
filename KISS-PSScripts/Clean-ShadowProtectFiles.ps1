set-location \\netswap\backup
start-transcript CleanUp-Log.txt -Append
# Set Limit
$DateLimit = (Get-Date).AddDays(-30)
# Set Network Drive Size
$DriveSize = 3815445MB

# Get Space Used
$DriveUsedBefore = (Get-ChildItem .\ -recurse | Measure-Object -property length -sum)

# Clean out ShadowProtect Write Buffer Files
(Get-ChildItem *.spwb -File -Recurse).where({$_.CreationTime -lt (Get-Date).AddDays(-1)}) | Remove-Item -Force

# Find Full Backups
$FullBackups = get-childitem *.spf -Recurse
write-host "Number of Full Backups: $($FullBackups.Count)"

# Clean Full Backups Older than Limit
$FilesToRemove = $FullBackups.where({$_.CreationTime -lt $DateLimit})
Write-Host "Full Backups Older than 30 Days to be Removed:`n$($FilesToRemove -join "`n")"
write-host "Number of Full Backup Files to Remove: $($FilesToRemove.Count)"
$FilesToRemove | Remove-Item -Force

# Refresh Full Backup Details
$FullBackups = get-childitem *.spf -Recurse
write-host "Number of Full Backups Remaining: $($FullBackups.Count)"

# Find Incremental backups and MD5s
$DepFiles = Get-ChildItem *.spi,*.md5 -Recurse
write-host "Number of Incremental Backups and MD5 Files: $($DepFiles.Count)"

# Find Incrementals with Full Backups still present
$Match = @()
foreach ($backup in $FullBackups) {
    $MatchString = $backup.FullName.Substring(0, $backup.FullName.LastIndexOf('.'))
    $Match += $DepFiles.where({$_.FullName -like "$MatchString*.*"})
}
write-host "Number of Matched Incremental-Full Backups: $($Match.Count)"
# Find Incrementals without Full Backups
if ($Match.Count -gt 0) {
    $FilesToRemove = Compare-Object $DepFiles $Match -SyncWindow 3000 -PassThru
    write-host "Number of Unmatched Incremental-Full Backups and MD5 Files: $($DepFiles.Count - $Match.Count)"
    Write-Host "Incremental Backups and MD5 Files to be Removed:`n$($FilesToRemove -join "`n")"
    write-host "Number of Unmatched Incremental/MD5 Files to Remove: $($FilesToRemove.Count)"
    $FilesToRemove | Remove-Item -Force
} Else { 
    write-host "No Dependent files left behind to Remove"
}
$DriveUsedAfter = (Get-ChildItem .\ -recurse | Measure-Object -property length -sum)
"Drive Size: {0:N2} TB" -f ($DriveSize / 1TB)
"Space Freed: {0:N2} GB" -f (($DriveUsedBefore.sum - $DriveUsedAfter.sum) / 1GB)
"Remaining Free Space: {0:N2} GB" -f (($DriveSize - $DriveUsedAfter.sum) / 1GB)
Stop-Transcript