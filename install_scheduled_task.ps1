param(
    [string]$TaskName = "UniFi Syslog Collector",
    [string]$PythonExe = "C:\Python311\python.exe",
    [string]$AppPath = "C:\UnifiCollector\unifi_log_collector.py",
    [string]$ConfigPath = "C:\UnifiCollector\config.ini",
    [string]$RunAsUser = "SYSTEM"
)

$action = New-ScheduledTaskAction -Execute $PythonExe -Argument "`"$AppPath`" --config `"$ConfigPath`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

if ($RunAsUser -eq "SYSTEM") {
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -User "SYSTEM" -RunLevel Highest -Force
} else {
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -User $RunAsUser -RunLevel Highest -Force
}

Write-Host "Scheduled task '$TaskName' installed."
