<#
.SYNOPSIS
  Last-resort fix if the internet stopped working because of ab-win.

.DESCRIPTION
  Puts every network adapter's DNS back the way it was before ab-win, using
  C:\ProgramData\ab-win\state.json when it exists. Adapters still pointing at
  127.0.0.1 with no saved settings go back to automatic (DHCP) DNS, which is
  right for almost every home PC. It also stops the ab-win service so it
  doesn't take DNS over again; reinstall with `ab-win install` afterwards.

  How to run: right-click this file > "Run with PowerShell". It asks for
  administrator approval.
#>
param([switch]$KeepService)

$ErrorActionPreference = 'Continue'

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    if ($KeepService) { $argList += '-KeepService' }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
    exit
}

if (-not $KeepService) {
    $svc = Get-Service -Name 'ab-win' -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Host 'Stopping the ab-win service...'
        Set-Service -Name 'ab-win' -StartupType Disabled -ErrorAction SilentlyContinue
        Stop-Service -Name 'ab-win' -Force -ErrorAction SilentlyContinue
    }
}

$statePath = Join-Path $env:ProgramData 'ab-win\state.json'
$restored = @{}
if (Test-Path $statePath) {
    $state = Get-Content $statePath -Raw | ConvertFrom-Json
    foreach ($p in $state.adapters.PSObject.Properties) {
        $guid = $p.Name
        $orig = $p.Value
        $ad = Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceGuid -eq $guid }
        if (-not $ad) { continue }
        $v4 = @($orig.v4 -split '[ ,;]+' | Where-Object { $_ })
        $v6 = @($orig.v6 -split '[ ,;]+' | Where-Object { $_ })
        if ($v4.Count -eq 0 -and $v6.Count -eq 0) {
            Set-DnsClientServerAddress -InterfaceIndex $ad.ifIndex -ResetServerAddresses
            Write-Host "$($ad.Name): DNS set back to automatic (DHCP)"
        } else {
            Set-DnsClientServerAddress -InterfaceIndex $ad.ifIndex -ServerAddresses ($v4 + $v6)
            Write-Host "$($ad.Name): DNS set back to $($v4 + $v6 -join ', ')"
        }
        $restored[$ad.ifIndex] = $true
    }
    Remove-Item $statePath -ErrorAction SilentlyContinue
}

foreach ($cfg in Get-DnsClientServerAddress) {
    if ($restored[$cfg.InterfaceIndex]) { continue }
    $loop = $cfg.ServerAddresses | Where-Object { $_ -eq '127.0.0.1' -or $_ -eq '::1' }
    if ($loop) {
        Set-DnsClientServerAddress -InterfaceIndex $cfg.InterfaceIndex -ResetServerAddresses
        Write-Host "$($cfg.InterfaceAlias): DNS set back to automatic (DHCP)"
        $restored[$cfg.InterfaceIndex] = $true
    }
}

Clear-DnsClientCache
if ($restored.Count -eq 0) {
    Write-Host 'No adapter was pointing at ab-win; nothing to change.'
} else {
    Write-Host 'Done. The internet should work again.'
}
if (-not $KeepService) {
    Write-Host 'The ab-win service is stopped and disabled. Run "ab-win install" to turn protection back on, or "ab-win uninstall" to remove it.'
}
Read-Host 'Press Enter to close'
