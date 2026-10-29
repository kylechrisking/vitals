# Vitals agent for Windows: reports this PC's disks, memory, crashed services,
# pending Windows updates, a pending reboot and Defender's state to a Vitals
# server every minute, and updates itself when the server has a newer agent.
# Windows PowerShell 5.1 or PowerShell 7; nothing to install.
#
# Normally installed by the server's install.ps1, which runs it at startup as
# SYSTEM. By hand: powershell -ExecutionPolicy Bypass -File agent.ps1 [-Once]
param([switch]$Once)

$ErrorActionPreference = 'Stop'
$Version = '0.3.0'
$Dir = Join-Path $env:ProgramData 'Vitals'
$Config = Get-Content -Raw (Join-Path $Dir 'config.json') | ConvertFrom-Json
$Server = $Config.server.TrimEnd('/')
$Every = 60
if ($Config.every) { $Every = [int]$Config.every }
$UpdatesEvery = 6 * 3600
$TaskName = 'Vitals agent'
$TrayDir = Join-Path $env:ProgramData 'VitalsTray'    # readable by users: the tray icon's status
$Wake = Join-Path $TrayDir 'wake'                     # writable by users: "check in now" requests
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

function Get-Disks {
    @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | Where-Object { $_.Size -gt 0 } | ForEach-Object {
        @{ mount = $_.DeviceID; total = [int64]$_.Size; free = [int64]$_.FreeSpace
           used_pct = [math]::Round(100 * ($_.Size - $_.FreeSpace) / $_.Size, 1) }
    })
}

function Get-Memory {
    $os = Get-CimInstance Win32_OperatingSystem
    @{ total = [int64]$os.TotalVisibleMemorySize * 1024
       used_pct = [math]::Round(100 * ($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize, 1) }
}

# Automatic services that stopped with an error. Plenty of automatic services are
# stopped on purpose (trigger-start, delayed start that finished), and those exit 0;
# 1077 means "never started since boot", also normal.
function Get-FailedServices {
    @(Get-CimInstance Win32_Service -Filter "StartMode='Auto' AND State='Stopped'" |
        Where-Object { $_.ExitCode -ne 0 -and $_.ExitCode -ne 1077 } | ForEach-Object { $_.Name })
}

function Test-RebootRequired {
    (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or
    (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
}

function Get-Defender {
    try {
        $s = Get-MpComputerStatus
        @{ realtime = [bool]$s.RealTimeProtectionEnabled; antivirus = [bool]$s.AntivirusEnabled
           signature_age_days = [int]$s.AntivirusSignatureAge }
    } catch { $null }   # another antivirus product, or Defender removed
}

# Searching Windows Update can take minutes, so it runs as a background job and
# the answer is picked up on a later round.
$UpdatesJob = $null
$Updates = $null
$UpdatesAt = [datetime]::MinValue
function Update-PendingUpdates {
    if ($script:UpdatesJob -and $script:UpdatesJob.State -ne 'Running') {
        try { $script:Updates = [int](Receive-Job $script:UpdatesJob | Select-Object -Last 1) } catch { $script:Updates = $null }
        Remove-Job $script:UpdatesJob -Force
        $script:UpdatesJob = $null
    }
    if (-not $script:UpdatesJob -and ((Get-Date) - $script:UpdatesAt).TotalSeconds -gt $UpdatesEvery) {
        $script:UpdatesAt = Get-Date
        $script:UpdatesJob = Start-Job {
            $searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
            $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'").Updates.Count
        }
    }
}

function Get-Report {
    $os = Get-CimInstance Win32_OperatingSystem
    $load = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
    $name = $env:COMPUTERNAME
    if ($Config.name) { $name = $Config.name }
    @{
        agent = $Version; os = 'windows'
        name = $name
        time = [double]([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000)
        uptime = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalSeconds)
        os_version = "$($os.Caption) $($os.Version)"
        cpu_pct = $load; cpus = [Environment]::ProcessorCount
        memory = Get-Memory; disks = Get-Disks; temps = @()
        failed_services = Get-FailedServices
        updates = $Updates; reboot_required = [bool](Test-RebootRequired)
        defender = Get-Defender
    }
}

# A newer agent from the server: download it, make sure it parses and is the version
# offered, swap it in, and have the scheduled task start again with it. Anything
# off and this copy keeps running.
$Tried = @{}
function Update-Agent([string]$Want) {
    if ($script:Tried.ContainsKey($Want) -and ((Get-Date) - $script:Tried[$Want]).TotalHours -lt 1) { return }
    $script:Tried[$Want] = Get-Date
    $me = Join-Path $Dir 'agent.ps1'
    $new = Join-Path $Dir 'agent.ps1.new'
    try {
        Invoke-WebRequest -UseBasicParsing -Uri "$Server/agent.ps1?token=$([uri]::EscapeDataString($Config.token))" -OutFile $new -TimeoutSec 60
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($new, [ref]$null, [ref]$errors) | Out-Null
        if ($errors.Count -gt 0) { throw "downloaded agent doesn't parse: $($errors[0].Message)" }
        if (-not (Select-String -Path $new -SimpleMatch "`$Version = '$Want'" -Quiet)) { throw "downloaded agent isn't version $Want" }
        Move-Item -Force $new $me
        # The tray icon too, best effort (it picks the new one up at next sign-in).
        try {
            Invoke-WebRequest -UseBasicParsing -Uri "$Server/tray.ps1?token=$([uri]::EscapeDataString($Config.token))" `
                -OutFile (Join-Path $TrayDir 'tray.ps1') -TimeoutSec 60
        } catch { }
    } catch {
        Write-Warning "vitals-agent: not updating to ${Want}: $_"
        Remove-Item -Force $new -ErrorAction SilentlyContinue
        return
    }
    # Start the task again a few seconds after this copy has exited.
    Start-Process -WindowStyle Hidden -FilePath 'powershell.exe' -ArgumentList @(
        '-NoProfile', '-NonInteractive', '-Command', "Start-Sleep -Seconds 5; Start-ScheduledTask -TaskName '$TaskName'")
    exit 0
}

# What the tray icon shows. Written where users can read but not write.
function Write-TrayStatus([bool]$Ok, [string]$Err) {
    if (-not (Test-Path $TrayDir)) { return }
    try {
        @{ time = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); ok = $Ok; error = $Err; every = $Every
           server = $Server; name = $env:COMPUTERNAME; version = $Version } |
            ConvertTo-Json -Compress | Set-Content -Encoding UTF8 (Join-Path $TrayDir 'status.json')
    } catch { }
}

# Sleep until the next round, or until the tray icon asks for a check-in now.
function Wait-NextRound {
    for ($i = 0; $i -lt $Every; $i++) {
        if (Test-Path $Wake) {
            $asks = @(Get-ChildItem -Path $Wake -File -ErrorAction SilentlyContinue)
            if ($asks.Count -gt 0) {
                $asks | Remove-Item -Force -ErrorAction SilentlyContinue
                return
            }
        }
        Start-Sleep -Seconds 1
    }
}

while ($true) {
    try {
        Update-PendingUpdates
        $body = Get-Report | ConvertTo-Json -Depth 5 -Compress
        $answer = Invoke-RestMethod -Method Post -Uri "$Server/api/report" -Body ([Text.Encoding]::UTF8.GetBytes($body)) `
            -ContentType 'application/json' -Headers @{ Authorization = "Bearer $($Config.token)" } -TimeoutSec 20
        Write-TrayStatus $true ''
        if ($Once) { $body; exit 0 }
        if ($answer.agent_version -and $answer.agent_version -ne $Version -and -not $Config.no_update) {
            Update-Agent $answer.agent_version
        }
    } catch {
        Write-Warning "vitals-agent: could not report: $_"
        Write-TrayStatus $false "$_"
        if ($Once) { exit 1 }
    }
    Wait-NextRound
}
