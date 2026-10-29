# Brock agent for Windows: reports this PC's disks, memory, crashed services,
# pending Windows updates, a pending reboot and Defender's state to a Brock
# server every minute. Windows PowerShell 5.1 or PowerShell 7; nothing to install.
#
# Normally installed by the server's install.ps1, which runs it at startup as
# SYSTEM. By hand: powershell -ExecutionPolicy Bypass -File agent.ps1 [-Once]
param([switch]$Once)

$ErrorActionPreference = 'Stop'
$Version = '0.2.0'
$Dir = Join-Path $env:ProgramData 'Brock'
$Config = Get-Content -Raw (Join-Path $Dir 'config.json') | ConvertFrom-Json
$Server = $Config.server.TrimEnd('/')
$Every = 60
if ($Config.every) { $Every = [int]$Config.every }
$UpdatesEvery = 6 * 3600
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

while ($true) {
    try {
        Update-PendingUpdates
        $body = Get-Report | ConvertTo-Json -Depth 5 -Compress
        Invoke-RestMethod -Method Post -Uri "$Server/api/report" -Body ([Text.Encoding]::UTF8.GetBytes($body)) `
            -ContentType 'application/json' -Headers @{ Authorization = "Bearer $($Config.token)" } -TimeoutSec 20 | Out-Null
        if ($Once) { $body; exit 0 }
    } catch {
        Write-Warning "brock-agent: could not report: $_"
        if ($Once) { exit 1 }
    }
    Start-Sleep -Seconds $Every
}
