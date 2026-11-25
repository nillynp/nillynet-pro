# NillyNet Pro — Clean Uninstaller (Zero Admin · HKCU only)
param([switch]$Silent)
$ErrorActionPreference = 'SilentlyContinue'
Get-Process NillyNetPro -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
if (Test-Path 'HKCU:\Software\Classes\Applications\NillyNetPro.exe') { Remove-Item 'HKCU:\Software\Classes\Applications\NillyNetPro.exe' -Recurse -Force }
Remove-Item (Join-Path ([Environment]::GetFolderPath('Desktop')) 'NillyNet Pro.lnk') -Force
Remove-Item (Join-Path ([Environment]::GetFolderPath('Programs')) 'Nilly graphics\NillyNet Pro.lnk') -Force
if (-not $Silent) { Write-Host '  Το NillyNet Pro απεγκαταστάθηκε καθαρά.' -ForegroundColor Green }
