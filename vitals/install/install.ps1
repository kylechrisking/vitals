# Installs the Vitals agent and tray icon on Windows. Served by your Vitals server
# with its address and agent token filled in. In PowerShell run as Administrator:
#   irm "http://vitals:8098/install.ps1?token=AGENT_TOKEN" | iex
# Run it again any time to repair or update. It also removes an older "Brock agent".
# Uninstall:
#   Unregister-ScheduledTask 'Vitals agent' -Confirm:$false; Unregister-ScheduledTask 'Vitals tray' -Confirm:$false
#   Remove-Item -Recurse "$env:ProgramData\Vitals", "$env:ProgramData\VitalsTray"
$ErrorActionPreference = 'Stop'
$Server = '__SERVER__'
$Token = '__TOKEN__'

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Write-Error 'Run PowerShell as Administrator, then run this again.'; return }
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

function Sid([string]$s) { New-Object Security.Principal.SecurityIdentifier($s) }
$SYSTEM = Sid 'S-1-5-18'; $ADMINS = Sid 'S-1-5-32-544'; $USERS = Sid 'S-1-5-32-545'

# A folder with exactly these rules (by SID: account names vary by language).
function Set-Folder([string]$Path, [array]$Rules) {
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($r in $Rules) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($r[0], $r[1],
            'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    }
    Set-Acl -Path $Path -AclObject $acl
}

# Before the rename this was "Brock": take the old agent out first.
foreach ($old in 'Brock agent') {
    if (Get-ScheduledTask -TaskName $old -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $old -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $old -Confirm:$false
        Write-Host "Removed the old '$old'."
    }
}
Remove-Item -Recurse -Force (Join-Path $env:ProgramData 'Brock') -ErrorAction SilentlyContinue

# The agent and its token: SYSTEM and Administrators only.
$Dir = Join-Path $env:ProgramData 'Vitals'
Set-Folder $Dir @(@($SYSTEM, 'FullControl'), @($ADMINS, 'FullControl'))
# The tray icon's files: users can read them...
$TrayDir = Join-Path $env:ProgramData 'VitalsTray'
Set-Folder $TrayDir @(@($SYSTEM, 'FullControl'), @($ADMINS, 'FullControl'), @($USERS, 'ReadAndExecute'))
# ...and drop a "check in now" request here, which is all they can write.
Set-Folder (Join-Path $TrayDir 'wake') @(@($SYSTEM, 'FullControl'), @($ADMINS, 'FullControl'), @($USERS, 'Modify'))

$q = "token=$([uri]::EscapeDataString($Token))"
Invoke-WebRequest -UseBasicParsing -Uri "$Server/agent.ps1?$q" -OutFile (Join-Path $Dir 'agent.ps1')
Invoke-WebRequest -UseBasicParsing -Uri "$Server/tray.ps1?$q" -OutFile (Join-Path $TrayDir 'tray.ps1')
@{ server = $Server; token = $Token; every = 60 } | ConvertTo-Json | Set-Content -Encoding UTF8 (Join-Path $Dir 'config.json')

# The agent: at startup, as SYSTEM, restarted if it ever stops.
$name = 'Vitals agent'
Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$Dir\agent.ps1`""
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $name -Action $action -Trigger (New-ScheduledTaskTrigger -AtStartup) `
    -Settings $settings -Principal $principal | Out-Null
Start-ScheduledTask -TaskName $name

# The tray icon: at sign-in, as whoever signs in, with no extra rights.
$tray = 'Vitals tray'
Unregister-ScheduledTask -TaskName $tray -Confirm:$false -ErrorAction SilentlyContinue
$usersName = $USERS.Translate([Security.Principal.NTAccount]).Value
$trayAction = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$TrayDir\tray.ps1`""
$traySettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $tray -Action $trayAction -Trigger (New-ScheduledTaskTrigger -AtLogOn) -Settings $traySettings `
    -Principal (New-ScheduledTaskPrincipal -GroupId $usersName -RunLevel Limited) | Out-Null
try { Start-ScheduledTask -TaskName $tray } catch { Write-Host 'The tray icon appears at your next sign-in.' }

Write-Host "Vitals agent installed and reporting to $Server as $env:COMPUTERNAME. Look for the dot in the tray."
