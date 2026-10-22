# Regenerates GFX1_v6.ps1 through GFX16_v6.ps1 from template/GFX_Setup.ps1.
# You do not need this to update GitHub. The 16 scripts are already built.
# Run it only after you edit template/GFX_Setup.ps1.
# Run from this folder:
#   powershell -ExecutionPolicy Bypass -File .\Build-GFXScripts.ps1

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$templatePath = Join-Path $root "template\GFX_Setup.ps1"
if (!(Test-Path $templatePath)) {
    throw "Missing template: $templatePath"
}

$template = [System.IO.File]::ReadAllText($templatePath)
if ($template -notmatch '__MACHINE_NAME__') {
    throw "template/GFX_Setup.ps1 is missing the __MACHINE_NAME__ token."
}

$utf8 = New-Object System.Text.UTF8Encoding $false
foreach ($n in 1..16) {
    $machine = "gfx$n"
    $script = $template.Replace("__MACHINE_NAME__", $machine)
    if ($script.Contains("__MACHINE_NAME__")) {
        throw "Token still present after building $machine"
    }
    $script = $script -replace "`r`n", "`n" -replace "`n", "`r`n"
    $outPath = Join-Path $root ("GFX{0}_v6.ps1" -f $n)
    [System.IO.File]::WriteAllText($outPath, $script, $utf8)
    Write-Host "Wrote $outPath"
}

Write-Host "Regenerated GFX1_v6.ps1 through GFX16_v6.ps1."
