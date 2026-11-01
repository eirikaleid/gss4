<#
.SYNOPSIS
  GSS4 Universal Offset Pipeline PowerShell Wrapper
.EXAMPLE
  .\run.ps1                                   # Varsayilan profile (royale) ile calistirir
  .\run.ps1 -Profile royale -Apply            # Calistirir ve src/core/offsets.h dosyasina uygular
  .\run.ps1 -Profile template_generic -Apk C:\path\game.apk
  .\run.ps1 -Stage 6                          # Yalnizca 6. asamayi (parse) calistirir
#>
param(
    [string]$Profile = "royale",
    [string]$Package = "",
    [string]$Device = "127.0.0.1:7555",
    [string]$Arch = "arm64-v8a",
    [string[]]$Apk = @(),
    [int]$Stage = 0,
    [int]$FromStage = 1,
    [string]$OutHeader = "",
    [string]$Src = "",
    [string]$Known = "",
    [switch]$Apply
)

$PSScriptRoot_Safe = Split-Path -Parent $MyInvocation.MyCommand.Path
$Python = "python"
if (-not (Get-Command $Python -ErrorAction SilentlyContinue)) {
    Write-Host "[FAIL] Python bulunamadi! Lutfen Python'u PATH'e ekleyin." -ForegroundColor Red
    exit 1
}

$PyArgs = @((Join-Path $PSScriptRoot_Safe "run_pipeline.py"), "--profile", $Profile)

if ($Package)   { $PyArgs += @("--package", $Package) }
if ($Device)    { $PyArgs += @("--device", $Device) }
if ($Arch)      { $PyArgs += @("--arch", $Arch) }
if ($Apk)       { $PyArgs += @("--apk") + $Apk }
if ($Stage -gt 0) { $PyArgs += @("--stage", $Stage) }
elseif ($FromStage -gt 1) { $PyArgs += @("--from-stage", $FromStage) }
if ($OutHeader) { $PyArgs += @("--out-header", $OutHeader) }
if ($Src)       { $PyArgs += @("--src", $Src) }
if ($Known)     { $PyArgs += @("--known", $Known) }
if ($Apply)     { $PyArgs += @("--apply") }

& $Python @PyArgs
exit $LASTEXITCODE
