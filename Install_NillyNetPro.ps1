# ============================================================================
# NillyNet Pro — Universal Windows 10/11 Installer (Zero Admin · Portable)
# created by Nilly graphics (Nillygraphics · Sotiris Christos) — https://nillygraphics.com/
# ============================================================================
param([switch]$Silent)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$exePath = Join-Path $root 'NillyNetPro.exe'
$icoPath = Join-Path $root 'NillyNetPro.ico'
$srcPath = Join-Path $root 'desktop\NillyNetPro.cs'

Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue

$needBuild = (-not (Test-Path $exePath)) -or ((Test-Path $srcPath) -and ((Get-Item $srcPath).LastWriteTimeUtc -gt (Get-Item $exePath).LastWriteTimeUtc))
if ($needBuild) {
    $fxDir = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319'
    if (-not (Test-Path "$fxDir\csc.exe")) { $fxDir = 'C:\Windows\Microsoft.NET\Framework\v4.0.30319' }
    $csc = Join-Path $fxDir 'csc.exe'
    if (-not (Test-Path $csc)) { throw 'Δεν βρέθηκε ο .NET Framework 4.x C# compiler (csc.exe).' }
    $cscArgs = @(
        '/nologo', '/target:winexe', '/optimize+', '/utf8output', '/platform:anycpu', "/out:$exePath",
        '/r:System.dll', '/r:System.Core.dll', '/r:System.Drawing.dll', '/r:System.Windows.Forms.dll'
    )
    if (Test-Path $icoPath) { $cscArgs += "/win32icon:$icoPath" }
    $cscArgs += $srcPath
    & $csc @cscArgs
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $exePath)) { throw "Αποτυχία μεταγλώττισης NillyNetPro.exe (exit $LASTEXITCODE)" }
    Write-Host ("  OK -> NillyNetPro.exe " + [math]::Round((Get-Item $exePath).Length / 1KB, 1) + " KB") -ForegroundColor Green
}

$appKey = 'HKCU:\Software\Classes\Applications\NillyNetPro.exe'
New-Item -Path "$appKey\DefaultIcon" -Force | Out-Null
New-Item -Path "$appKey\shell\open\command" -Force | Out-Null
Set-ItemProperty -Path $appKey -Name 'FriendlyAppName' -Value 'NillyNet Pro'
Set-ItemProperty -Path "$appKey\DefaultIcon" -Name '(Default)' -Value "$exePath,0"
Set-ItemProperty -Path "$appKey\shell\open\command" -Name '(Default)' -Value "`"$exePath`""

$wsh = New-Object -ComObject WScript.Shell
$desktopDir = [Environment]::GetFolderPath('Desktop')
$startMenuDir = Join-Path ([Environment]::GetFolderPath('Programs')) 'Nilly graphics'
New-Item -ItemType Directory -Force -Path $startMenuDir | Out-Null
foreach ($lnkPath in @((Join-Path $desktopDir 'NillyNet Pro.lnk'), (Join-Path $startMenuDir 'NillyNet Pro.lnk'))) {
    $sc = $wsh.CreateShortcut($lnkPath)
    $sc.TargetPath = $exePath; $sc.WorkingDirectory = $root
    $sc.Description = 'NillyNet Pro — Ultra-Light Network Monitor, Wi-Fi Passwords & DNS Tools | Nilly graphics'
    $sc.IconLocation = "$exePath,0"; $sc.Save()
}
if (-not $Silent) { Start-Process -FilePath $exePath }
