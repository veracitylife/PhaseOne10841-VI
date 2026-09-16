# Register daily backup + retention for PhaseOne10841 (run as Administrator once)
# Veracity Integrity LLC
$ErrorActionPreference = 'Stop'
$Root = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$Backup = Join-Path $Root 'scripts\backup.sh'
$Retention = Join-Path $Root 'scripts\retention-cleanup.ts'

# Prefer Git Bash for .sh; retention via npm
$GitBash = @(
  "$env:ProgramFiles\Git\bin\bash.exe",
  "$env:ProgramFiles\Git\usr\bin\bash.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

$BackupAction = if ($GitBash) {
  New-ScheduledTaskAction -Execute $GitBash -Argument "`"$Backup`"" -WorkingDirectory $Root
} else {
  Write-Warning 'Git Bash not found; backup task will use wsl bash if available'
  New-ScheduledTaskAction -Execute 'wsl' -Argument "-e bash `"$Backup`"" -WorkingDirectory $Root
}
$RetentionAction = New-ScheduledTaskAction -Execute 'npm' -Argument 'run retention' -WorkingDirectory $Root
# fallback if script missing in package.json: npx tsx
if (-not (Select-String -Path (Join-Path $Root 'package.json') -Pattern '"retention"' -Quiet)) {
  $RetentionAction = New-ScheduledTaskAction -Execute 'npx' -Argument 'tsx scripts/retention-cleanup.ts' -WorkingDirectory $Root
}

$Trigger = New-ScheduledTaskTrigger -Daily -At 2am
Register-ScheduledTask -TaskName 'PhaseOne10841-Backup' -Action $BackupAction -Trigger $Trigger -Description 'PhaseOne DB/policy backup' -Force | Out-Null
Register-ScheduledTask -TaskName 'PhaseOne10841-Retention' -Action $RetentionAction -Trigger $Trigger -Description 'PhaseOne event retention cleanup' -Force | Out-Null
Write-Host 'Registered: PhaseOne10841-Backup and PhaseOne10841-Retention (daily 2am)'
Write-Host "Root: $Root"
