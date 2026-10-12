<#
.SYNOPSIS
  Service-level end-to-end test (PLAN 8.1 "Service" and "Failsafe" rows).
  Must run as Administrator on a disposable machine or VM: it installs ab-win,
  changes DNS, kills the service and uninstalls it. GitHub's windows-latest
  runners qualify.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tests\service-e2e.ps1 -Exe .\bin\ab-win.exe
#>
param([Parameter(Mandatory)] [string]$Exe)

$ErrorActionPreference = 'Stop'
$Exe = (Resolve-Path $Exe).Path
$failures = 0
function Check($name, [scriptblock]$cond) {
    $ok = $false
    try { $ok = [bool](& $cond) } catch { $ok = $false }
    if ($ok) { Write-Host "PASS  $name" -ForegroundColor Green }
    else { Write-Host "FAIL  $name" -ForegroundColor Red; $script:failures++ }
}
function WaitFor([scriptblock]$cond, $seconds = 30) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        try { if (& $cond) { return $true } } catch {}
        Start-Sleep -Milliseconds 500
    }
    return $false
}
function Resolve-A($name) {
    Clear-DnsClientCache
    (Resolve-DnsName -Name $name -Type A -DnsOnly -ErrorAction Stop | Where-Object { $_.Type -eq 'A' } | Select-Object -First 1).IPAddress
}
function DnsSnapshot {
    Get-DnsClientServerAddress | Sort-Object InterfaceIndex, AddressFamily |
        ForEach-Object { "$($_.InterfaceIndex)/$($_.AddressFamily)=$($_.ServerAddresses -join ',')" }
}

$before = DnsSnapshot
Write-Host "DNS before:`n$($before -join "`n")"

# --- install ---------------------------------------------------------------
& $Exe install --quiet
Check 'install exits 0' { $LASTEXITCODE -eq 0 }
Check 'service running' { (Get-Service ab-win).Status -eq 'Running' }
Check 'service start type automatic' { (Get-Service ab-win).StartType -eq 'Automatic' }
Check 'watchdog task exists' { schtasks /Query /TN 'ab-win watchdog' | Out-Null; $LASTEXITCODE -eq 0 }
Check 'tray Run key set' { (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run').'ab-win' -like '*tray*' }
Check 'uninstall entry present' { Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ab-win' }
Check 'state.json saved' { Test-Path "$env:ProgramData\ab-win\state.json" }
Check 'Windows resolves test domain through ab-win' { WaitFor { (Resolve-A 'blocked.ab-win.test') -eq '0.0.0.0' } 20 }
Check 'ad domain blocked system-wide' { (Resolve-A 'doubleclick.net') -eq '0.0.0.0' }
Check 'normal domain resolves' { (Resolve-A 'example.com') -ne '0.0.0.0' }

$installed = 'C:\Program Files\ab-win\ab-win.exe'
& $installed status | Out-Host
Check 'status exits 0' { $LASTEXITCODE -eq 0 }

# --- pause / resume -------------------------------------------------------------
& $installed pause 1m | Out-Host
Check 'paused: ad domain resolves' { WaitFor { (Resolve-A 'doubleclick.net') -ne '0.0.0.0' } 10 }
& $installed resume | Out-Host
Check 'resumed: ad domain blocked' { WaitFor { (Resolve-A 'doubleclick.net') -eq '0.0.0.0' } 10 }

# --- allow -----------------------------------------------------------------------
& $installed allow doubleclick.net | Out-Host
Check 'allowed domain resolves' { WaitFor { (Resolve-A 'doubleclick.net') -ne '0.0.0.0' } 10 }
& $installed unallow doubleclick.net | Out-Host

# --- crash recovery (service recovery actions) ------------------------------------
$pid1 = (Get-CimInstance Win32_Service -Filter "Name='ab-win'").ProcessId
Stop-Process -Id $pid1 -Force
Check 'service restarts after crash' { WaitFor { $p = (Get-CimInstance Win32_Service -Filter "Name='ab-win'"); $p.State -eq 'Running' -and $p.ProcessId -ne $pid1 } 30 }
Check 'blocking works after restart' { WaitFor { (Resolve-A 'doubleclick.net') -eq '0.0.0.0' } 20 }

# --- watchdog failsafe: service disabled and killed --------------------------------
Set-Service ab-win -StartupType Disabled
Stop-Process -Id (Get-CimInstance Win32_Service -Filter "Name='ab-win'").ProcessId -Force
Start-Sleep 2
& $installed watchdog
Check 'watchdog restored DNS when service is dead' { (DnsSnapshot | Out-String) -eq ($before | Out-String) }
Check 'internet works without ab-win' { (Resolve-A 'example.com') -ne $null }
Check 'failsafe note written' { Test-Path "$env:ProgramData\ab-win\failsafe.json" }
Set-Service ab-win -StartupType Automatic

# --- reinstall over existing, then uninstall --------------------------------------------
& $Exe install --quiet
Check 'reinstall exits 0' { $LASTEXITCODE -eq 0 }
& $installed uninstall
Check 'uninstall exits 0' { $LASTEXITCODE -eq 0 }
Start-Sleep 4
Check 'service removed' { -not (Get-Service ab-win -ErrorAction SilentlyContinue) }
Check 'watchdog task removed' { schtasks /Query /TN 'ab-win watchdog' 2>$null | Out-Null; $LASTEXITCODE -ne 0 }
Check 'Run key removed' { -not (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run').'ab-win' }
Check 'uninstall entry removed' { -not (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ab-win') }
Check 'DNS restored exactly' { (DnsSnapshot | Out-String) -eq ($before | Out-String) }
Check 'data folder removed' { -not (Test-Path "$env:ProgramData\ab-win") }
Check 'program folder removed' { WaitFor { -not (Test-Path 'C:\Program Files\ab-win') } 10 }

if ($failures -gt 0) {
    Write-Host "DNS after:`n$((DnsSnapshot) -join "`n")"
    Write-Host "$failures check(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host 'All service checks passed' -ForegroundColor Green
