# v25 - Zero-Touch Deployment for Unsigned VSTO
# Run as Administrator

# --- 1. CONFIGURATION ---
$OSCTargetIP    = "192.168.8.142"
$RemotePort     = 9000
$LocalPort      = 8000
$oscDir         = "C:\OSCPoint"
$vstoName       = "OSCPoint add-in.vsto"
$TempDir        = "C:\GFX_Temp_Setup"

# Corrected Download Links (Removed the trailing '1's)
$Link_OSCPoint      = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/oscpoint-2.2.0.0.zip"
$Link_InputDirector = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/InputDirector.v2.3.build173.Domain.Setup.exe1"
$Link_TallyViewer   = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/TallyViewer.ex1e"
$Link_Agent         = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/agent.exe1"

Write-Host "--- Starting OSCPoint Deployment v25 ---" -ForegroundColor Cyan

# --- 2. PREPARATION ---
Get-Process "powerpnt" -ErrorAction SilentlyContinue | Stop-Process -Force
if (Test-Path $TempDir) { Remove-Item $TempDir -Recurse -Force }
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

function Download-File {
    param ($Url, $FileName)
    $Dest = Join-Path $TempDir $FileName
    try {
        Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing -ErrorAction Stop
        if (Test-Path $Dest) { return $Dest }
    } catch { 
        Write-Warning "Failed to download $FileName from $Url"
        return $null 
    }
}

# --- 3. DOWNLOAD & EXTRACT ---
$oscZip      = Download-File $Link_OSCPoint "OSCPoint.zip"
$idInstaller = Download-File $Link_InputDirector "IDSetup.exe"
$tallyExe    = Download-File $Link_TallyViewer "TallyViewer.exe"
$agentExe    = Download-File $Link_Agent "agent.exe"

if ($oscZip) {
    if (Test-Path $oscDir) { Remove-Item $oscDir -Recurse -Force }
    New-Item -ItemType Directory -Path $oscDir -Force | Out-Null
    Expand-Archive -Path $oscZip -DestinationPath $oscDir -Force
    Get-ChildItem -Path $oscDir -Recurse | Unblock-File
    
    $vstoFile = Get-ChildItem -Path $oscDir -Filter "$vstoName" -Recurse | Select-Object -First 1
    if ($vstoFile) {
        $vstoPath = $vstoFile.FullName

        # --- 4. THE "UNSIGNED" SECURITY BYPASS ---
        # Since the VSTO is unsigned, we must tell the .NET Trust Manager 
        # that local/intranet installs are allowed without a signature prompt.
        Write-Host "[Security] Applying Trust Manager Bypass for unsigned code..." -ForegroundColor Gray
        $trustManagerPath = "HKLM:\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel"
        if (!(Test-Path $trustManagerPath)) { New-Item -Path $trustManagerPath -Force | Out-Null }
        Set-ItemProperty $trustManagerPath -Name "MyComputer" -Value "Enabled"
        Set-ItemProperty $trustManagerPath -Name "LocalIntranet" -Value "Enabled"

        # --- 5. OFFICE RESILIENCY & TRUSTED LOCATIONS ---
        foreach ($ver in @("14.0", "15.0", "16.0")) {
            $basePath = "HKCU:\Software\Microsoft\Office\$ver\PowerPoint"
            # Clear disabled items
            $resilPath = "$basePath\Resiliency"
            if (Test-Path $resilPath) { 
                Remove-Item "$resilPath\DisabledItems" -Recurse -ErrorAction SilentlyContinue
                Remove-Item "$resilPath\CrashingAddins" -Recurse -ErrorAction SilentlyContinue
            }
            # Add directory to Trusted Locations
            $trustPath = "$basePath\Security\Trusted Locations\OSCPoint"
            if (!(Test-Path $trustPath)) { New-Item $trustPath -Force | Out-Null }
            Set-ItemProperty $trustPath -Name "Path" -Value $oscDir
            Set-ItemProperty $trustPath -Name "AllowSubfolders" -Value 1 -Type DWord
        }

        # --- 6. REGISTRATION (|vstolocal is key here) ---
        $regPaths = @(
            "HKCU:\Software\Microsoft\Office\PowerPoint\Addins\OSCPoint",
            "HKLM:\SOFTWARE\Microsoft\Office\PowerPoint\Addins\OSCPoint",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\PowerPoint\Addins\OSCPoint"
        )
        foreach ($rp in $regPaths) {
            if (!(Test-Path $rp)) { New-Item $rp -Force -ErrorAction SilentlyContinue | Out-Null }
            if (Test-Path $rp) {
                Set-ItemProperty $rp -Name "Manifest" -Value "$vstoPath|vstolocal"
                Set-ItemProperty $rp -Name "LoadBehavior" -Value 3 -Type DWord
                Set-ItemProperty $rp -Name "FriendlyName" -Value "OSCPoint Add-in"
            }
        }

        # --- 7. APP CONFIGURATION ---
        $oscConfig = "HKCU:\Software\Zinc Event Production Ltd\OSCPoint"
        if (!(Test-Path $oscConfig)) { New-Item $oscConfig -Force | Out-Null }
        Set-ItemProperty $oscConfig -Name "RemoteHost" -Value $OSCTargetIP
        Set-ItemProperty $oscConfig -Name "RemotePort" -Value $RemotePort
        Set-ItemProperty $oscConfig -Name "LocalPort" -Value $LocalPort
        Set-ItemProperty $oscConfig -Name "FeedbackEnabled" -Value "True"
    }
}

# --- 8. FIREWALL & SUPPORT APPS ---
Write-Host "[Firewall] Configuring ports..." -ForegroundColor Gray
Remove-NetFirewallRule -DisplayName "OSCPoint Inbound" -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "OSCPoint Inbound" -Direction Inbound -Action Allow -Protocol UDP -LocalPort $LocalPort | Out-Null

if ($agentExe) {
    $dest = "$([System.Environment]::GetFolderPath('CommonStartup'))\agent.exe"
    Copy-Item $agentExe $dest -Force
    Unblock-File $dest
}
if ($tallyExe) {
    Copy-Item $tallyExe "$env:USERPROFILE\Desktop\TallyViewer.exe" -Force
}
if ($idInstaller) {
    Write-Host "[Install] Running InputDirector Setup..." -ForegroundColor Gray
    Start-Process $idInstaller -ArgumentList "/S" -Wait
}

# --- 9. CLEANUP ---
Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "----------------------------------------------" -ForegroundColor Cyan
Write-Host "DEPLOYMENT SUCCESSFUL" -ForegroundColor Green
Write-Host "Unsigned Trust Bypass Applied." -ForegroundColor Green
Write-Host "----------------------------------------------" -ForegroundColor Cyan
