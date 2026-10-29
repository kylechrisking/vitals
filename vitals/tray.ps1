# Vitals tray icon for Windows: a dot that's green when this PC's agent checked
# in recently, with "Check in now" and "Open Vitals". Runs as the signed-in user
# (started at logon by the task install.ps1 registers); talks to the agent only
# through files in ProgramData\VitalsTray, so it never sees the agent's token.
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
$ErrorActionPreference = 'Continue'
$Dir = Join-Path $env:ProgramData 'VitalsTray'
$StatusFile = Join-Path $Dir 'status.json'
$Wake = Join-Path $Dir 'wake'
$Mine = Join-Path $env:LOCALAPPDATA 'Vitals'          # this user's: the log, and "hidden until sign-in"
New-Item -ItemType Directory -Force -Path $Mine | Out-Null
$Log = Join-Path $Mine 'tray.log'
$HiddenFile = Join-Path $Mine 'hidden'

function Write-Log([string]$Msg) {
    try {
        if ((Test-Path $Log) -and (Get-Item $Log).Length -gt 256KB) { Remove-Item $Log -Force }
        Add-Content -Path $Log -Value "$(Get-Date -Format s)  $Msg"
    } catch { }
}

# The current sign-in, told apart by when this session's Explorer started.
function Get-SessionMark {
    $sid = [Diagnostics.Process]::GetCurrentProcess().SessionId
    $e = Get-Process explorer -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $sid } |
        Sort-Object StartTime | Select-Object -First 1
    if ($e) { $e.StartTime.ToUniversalTime().ToString('o') } else { '' }
}

# One dot per sign-in: the task re-runs this every few minutes in case it stopped.
$created = $false
$mutex = New-Object Threading.Mutex($true, 'Local\VitalsTray', [ref]$created)
if (-not $created) { exit 0 }
# "Hide this icon" holds until the next sign-in.
if ((Test-Path $HiddenFile) -and ((Get-Content -Raw $HiddenFile).Trim() -eq (Get-SessionMark))) { exit 0 }

function New-DotIcon([string]$Hex) {
    $bmp = New-Object Drawing.Bitmap 16, 16
    $g = [Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.Clear([Drawing.Color]::Transparent)
    $g.FillEllipse((New-Object Drawing.SolidBrush ([Drawing.ColorTranslator]::FromHtml($Hex))), 2, 2, 12, 12)
    $g.Dispose()
    [Drawing.Icon]::FromHandle($bmp.GetHicon())
}
$Icons = @{ ok = (New-DotIcon '#22c55e'); bad = (New-DotIcon '#ef4444'); idle = (New-DotIcon '#94a3b8') }

function Read-Status {
    try { Get-Content -Raw $StatusFile -ErrorAction Stop | ConvertFrom-Json } catch { $null }
}

$tray = New-Object Windows.Forms.NotifyIcon
$tray.Icon = $Icons.idle
$tray.Text = 'Vitals'
$tray.Visible = $true

$menu = New-Object Windows.Forms.ContextMenuStrip
$info = $menu.Items.Add('Vitals')
$info.Enabled = $false
$checkIn = $menu.Items.Add('Check in now')
$open = $menu.Items.Add('Open Vitals')
[void]$menu.Items.Add((New-Object Windows.Forms.ToolStripSeparator))
$hide = $menu.Items.Add('Hide this icon (until next sign-in)')
$tray.ContextMenuStrip = $menu

$script:Asked = $null    # when "Check in now" was clicked, to confirm when it lands
$script:Last = 0

$script:Explorer = Get-SessionMark
function Update-View {
    # Explorer restarted (crash, update): it forgot every tray icon, so put ours back.
    $mark = Get-SessionMark
    if ($mark -and $mark -ne $script:Explorer) {
        $script:Explorer = $mark
        $tray.Visible = $false
        $tray.Visible = $true
        Write-Log 'Explorer restarted; icon shown again'
    }
    $s = Read-Status
    if (-not $s) {
        $tray.Icon = $Icons.idle
        $tray.Text = 'Vitals: agent not running'
        $info.Text = 'The Vitals agent has not reported yet'
        return
    }
    $age = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - [double]$s.time
    $every = 60
    if ($s.every) { $every = [double]$s.every }
    $when = [DateTimeOffset]::FromUnixTimeSeconds([int64]$s.time).LocalDateTime.ToString('HH:mm')
    if ($s.ok -and $age -lt 3 * $every) {
        $tray.Icon = $Icons.ok
        $info.Text = "Checked in at $when"
    } elseif ($s.ok) {
        $tray.Icon = $Icons.bad
        $info.Text = "Last check-in $when (agent stopped?)"
    } else {
        $tray.Icon = $Icons.bad
        $info.Text = "Can't reach Vitals since $when"
    }
    $text = "Vitals: $($info.Text)"
    if ($text.Length -gt 63) { $text = $text.Substring(0, 63) }    # the tray's limit
    $tray.Text = $text
    if ($script:Asked -and [double]$s.time -gt $script:Last -and [double]$s.time -ge $script:Asked) {
        $msg = 'Checked in.'
        if (-not $s.ok) { $msg = "Couldn't reach Vitals: $($s.error)" }
        $tray.ShowBalloonTip(3000, 'Vitals', $msg, [Windows.Forms.ToolTipIcon]::Info)
        $script:Asked = $null
    }
    $script:Last = [double]$s.time
}

$checkIn.add_Click({
    try {
        New-Item -ItemType File -Force -Path (Join-Path $Wake "$([guid]::NewGuid()).req") | Out-Null
        $script:Asked = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $tray.ShowBalloonTip(2000, 'Vitals', 'Checking in...', [Windows.Forms.ToolTipIcon]::None)
    } catch {
        $tray.ShowBalloonTip(4000, 'Vitals', "Couldn't ask the agent: $_", [Windows.Forms.ToolTipIcon]::Warning)
    }
})
$openPage = {
    $s = Read-Status
    if ($s -and $s.server) { Start-Process $s.server }
}
$open.add_Click($openPage)
$tray.add_DoubleClick($openPage)
$hide.add_Click({
    try { Set-Content -Path $HiddenFile -Value (Get-SessionMark) } catch { }
    $tray.Visible = $false
    [Windows.Forms.Application]::Exit()
})

$timer = New-Object Windows.Forms.Timer
$timer.Interval = 3000
$timer.add_Tick({ try { Update-View } catch { Write-Log "update failed: $_" } })
$timer.Start()
Update-View
Write-Log 'started'
try {
    [Windows.Forms.Application]::Run()
} catch {
    Write-Log "stopped: $_"
} finally {
    $tray.Dispose()
    $mutex.ReleaseMutex()
}
