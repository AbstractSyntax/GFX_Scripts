# v26 - Force-Loading Unsigned VSTO
# Run as Administrator

# --- 1. CONFIGURATION ---
$OSCTargetIP    = "192.168.8.142"
$RemotePort     = 9000
$LocalPort      = 8000
$oscDir         = "C:\OSCPoint"
$vstoName       = "OSCPoint add-in.vsto"
$TempDir        = "C:\GFX_Temp_Setup"

$Link_OSCPoint      = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/oscpoint-2.2.0.0.zip"
$Link_InputDirector = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/InputDirector.v2.3.build173.Domain.Setup.ex1e"
$Link_TallyViewer   = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/TallyViewer.ex1e"
$Link_Agent         = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/agent.exe1"

Write-Host "--- Starting OSCPoint Deployment v26 ---" -ForegroundColor Cyan

# --- 2. VSTO RUNTIME CHECK ---
$vstoInstalled = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\VSTO\Runtime\Wf\4.0 -ErrorAction SilentlyContinue
if (!$vstoInstalled) {
    Write-Warning "VSTO Runtime not detected. Attempting to download and install..."
    $vstoUrl = "https://download.microsoft.com/download/1/D/0/1D061D41-51A2-4ADF-A386-327D0BA50640/vstor_redist.exe"
    Invoke-WebRequest $vstoUrl -OutFile "$TempDir\vstor_redist.exe"
    Start-Process "$TempDir\vstor_redist.exe" -ArgumentList "/q /norestart" -Wait
}

# --- 3. PREPARATION ---
Get-Process "powerpnt" -ErrorAction SilentlyContinue | Stop-Process -Force
if (Test-Path $oscDir) { Remove-Item $oscDir -Recurse -Force }
New-Item -ItemType Directory -Path $oscDir -Force | Out-Null

# --- 4. DOWNLOAD & EXTRACT ---
Invoke-WebRequest -Uri $Link_OSCPoint -OutFile "$TempDir\OSCPoint.zip" -UseBasicParsing
Expand-Archive -Path "$TempDir\OSCPoint.zip" -DestinationPath $oscDir -Force
Get-ChildItem -Path $oscDir -Recurse | Unblock-File

$vstoFile = Get-ChildItem -Path $oscDir -Filter "$vstoName" -Recurse | Select-Object -First 1
if ($vstoFile) {
    $vstoPath = $vstoFile.FullName
    Write-Host "Registering: $vstoPath" -ForegroundColor Gray

    # --- 5. THE "SILENT ERROR" KILLER ---
    # This forces PowerPoint to show you an error popup if the add-in fails to load
    [Environment]::SetEnvironmentVariable("VSTO_SUPPRESSDISPLAYALERTS", "0", "Machine")
    [Environment]::SetEnvironmentVariable("VSTO_LOGALERTS", "1", "Machine")

    # --- 6. TRUST MANAGER BYPASS (For Unsigned) ---
    $trustPaths = @(
        "HKLM:\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel",
        "HKLM:\SOFTWARE\WOW6432Node\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel"
    )
    foreach ($tp in $trustPaths) {
        if (!(Test-Path $tp)) { New-Item -Path $tp -Force | Out-Null }
        Set-ItemProperty $tp -Name "MyComputer" -Value "Enabled"
        Set-ItemProperty $tp -Name "LocalIntranet" -Value "Enabled"
        Set-ItemProperty $tp -Name "Internet" -Value "Enabled"
        Set-ItemProperty $tp -Name "TrustedSites" -Value "Enabled"
    }

    # --- 7. OFFICE RESILIENCY CLEANUP ---
    foreach ($ver in @("14.0", "15.0", "16.0")) {
        $regBase = "HKCU:\Software\Microsoft\Office\$ver\PowerPoint"
        # Force Reset of disabled list
        Remove-Item "$regBase\Resiliency\DisabledItems" -Recurse -ErrorAction SilentlyContinue
        Remove-Item "$regBase\Resiliency\CrashingAddins" -Recurse -ErrorAction SilentlyContinue
        
        # Add Trusted Location
        $trustPath = "$regBase\Security\Trusted Locations\OSCPoint"
        if (!(Test-Path $trustPath)) { New-Item $trustPath -Force | Out-Null }
        Set-ItemProperty $trustPath -Name "Path" -Value $oscDir
        Set-ItemProperty $trustPath -Name "AllowSubfolders" -Value 1 -Type DWord
    }

    # --- 8. MANIFEST REGISTRATION ---
    # Register in both HKCU and HKLM to ensure visibility
    $regPaths = @(
        "HKCU:\Software\Microsoft\Office\PowerPoint\Addins\OSCPoint",
        "HKLM:\SOFTWARE\Microsoft\Office\PowerPoint\Addins\OSCPoint",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\PowerPoint\Addins\OSCPoint"
    )
    foreach ($rp in $regPaths) {
        if (!(Test-Path $rp)) { New-Item $rp -Force | Out-Null }
        Set-ItemProperty $rp -Name "Manifest" -Value "$vstoPath|vstolocal"
        Set-ItemProperty $rp -Name "LoadBehavior" -Value 3 -Type DWord
        Set-ItemProperty $rp -Name "FriendlyName" -Value "OSCPoint"
    }

    # --- 9. OSC APP CONFIG ---
    $oscConfig = "HKCU:\Software\Zinc Event Production Ltd\OSCPoint"
    if (!(Test-Path $oscConfig)) { New-Item $oscConfig -Force | Out-Null }
    Set-ItemProperty $oscConfig -Name "RemoteHost" -Value $OSCTargetIP
    Set-ItemProperty $oscConfig -Name "RemotePort" -Value $RemotePort
    Set-ItemProperty $oscConfig -Name "LocalPort" -Value $LocalPort
    Set-ItemProperty $oscConfig -Name "FeedbackEnabled" -Value "True"
}

# --- 10. FIREWALL & SUPPORT APPS ---
Remove-NetFirewallRule -DisplayName "OSCPoint Inbound" -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "OSCPoint Inbound" -Direction Inbound -Action Allow -Protocol UDP -LocalPort $LocalPort | Out-Null

# Quick Download/Install for Support Apps
Download-File $Link_Agent "agent.exe"
Download-File $Link_TallyViewer "TallyViewer.exe"
Download-File $Link_InputDirector "IDSetup.exe"

Write-Host "--- DEPLOYMENT COMPLETE ---" -ForegroundColor Green
Write-Host "Please open PowerPoint. If it fails, a popup should now appear explaining why." -ForegroundColor Yellow
