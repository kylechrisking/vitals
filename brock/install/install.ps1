# Installs the Brock agent on Windows. Served by your Brock server with its
# address and agent token filled in. In PowerShell run as Administrator:
#   irm "http://brock:8098/install.ps1?token=AGENT_TOKEN" | iex
# Uninstall: Unregister-ScheduledTask 'Brock agent' -Confirm:$false; Remove-Item -Recurse "$env:ProgramData\Brock"
$ErrorActionPreference = 'Stop'
$Server = '__SERVER__'
$Token = '__TOKEN__'

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Write-Error 'Run PowerShell as Administrator, then run this again.'; return }

[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$Dir = Join-Path $env:ProgramData 'Brock'
New-Item -ItemType Directory -Force -Path $Dir | Out-Null

# Only SYSTEM and Administrators can read the folder: it holds the agent token.
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {   # SYSTEM, Administrators (by SID: names vary by language)
    $who = New-Object Security.Principal.SecurityIdentifier($sid)
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($who, 'FullControl',
        'ContainerInherit,ObjectInherit', 'None', 'Allow')))
}
Set-Acl -Path $Dir -AclObject $acl

Invoke-WebRequest -UseBasicParsing -Uri "$Server/agent.ps1?token=$Token" -OutFile (Join-Path $Dir 'agent.ps1')
@{ server = $Server; token = $Token; every = 60 } | ConvertTo-Json | Set-Content -Encoding UTF8 (Join-Path $Dir 'config.json')

$name = 'Brock agent'
Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$Dir\agent.ps1`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Settings $settings -Principal $principal | Out-Null
Start-ScheduledTask -TaskName $name
Write-Host "Brock agent installed and reporting to $Server as $env:COMPUTERNAME."
