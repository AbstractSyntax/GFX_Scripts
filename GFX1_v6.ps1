# v27 - OSCPoint Deployment with Fixed VSTO Runtime Installer
# Run as Administrator

# --- 1. CONFIGURATION ---
$OSCTargetIP    = "192.168.8.142"
$RemotePort     = 9000
$LocalPort      = 8000
$oscDir         = "C:\OSCPoint"
$vstoName       = "OSCPoint add-in.vsto"
$TempDir        = "C:\GFX_Temp_Setup"

# Core Links
$Link_OSCPoint      = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/oscpoint-2.2.0.0.zip"
$Link_VSTO_Runtime  = "https://aka.ms/vstort40vix64" # Official Microsoft Redirector for VSTO Runtime

Write-Host "--- Starting OSCPoint Deployment v27 ---" -ForegroundColor Cyan

# --- 2. PREPARATION ---
if (!(Test-Path $TempDir)) { New-Item $TempDir -ItemType Directory -Force | Out-Null }
Get-Process "powerpnt" -ErrorAction SilentlyContinue | Stop-Process -Force

# --- 3. VSTO RUNTIME INSTALLER (Critical Fix) ---
# Check if VSTO is actually installed in the Registry
$vstoCheck = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\VSTO\Runtime\Wf\4.0" -ErrorAction SilentlyContinue
if (!$vstoCheck) {
    Write-Host "[Required] VSTO Runtime not found. Downloading..." -ForegroundColor Yellow
    $vstoExe = Join-Path $TempDir "vstor_redist.exe"
    try {
        Invoke-WebRequest -Uri $Link_VSTO_Runtime -OutFile $vstoExe -UseBasicParsing
        Write-Host "[Required] Installing VSTO Runtime (Silent)..." -ForegroundColor Yellow
        Start-Process $vstoExe -ArgumentList "/q /norestart" -Wait
        Write-Host "VSTO Runtime installed successfully." -ForegroundColor Green
    } catch {
        Write-Error "Could not download VSTO Runtime. The add-in will NOT load without it."
        exit
    }
}

# --- 4. DOWNLOAD & EXTRACT ADD-IN ---
Write-Host "[Task] Downloading OSCPoint..." -ForegroundColor Gray
if (Test-Path $oscDir) { Remove-Item $oscDir -Recurse -Force }
New-Item -ItemType Directory -Path $oscDir -Force | Out-Null

$zipPath = Join-Path $TempDir "OSCPoint.zip"
Invoke-WebRequest -Uri $Link_OSCPoint -OutFile $zipPath -UseBasicParsing
Expand-Archive -Path $zipPath -DestinationPath $oscDir -Force
Get-ChildItem -Path $oscDir -Recurse | Unblock-File

$vstoFile = Get-ChildItem -Path $oscDir -Filter "$vstoName" -Recurse | Select-Object -First 1
if ($vstoFile) {
    $vstoPath = $vstoFile.FullName
    Write-Host "Found VSTO at: $vstoPath" -ForegroundColor Gray

    # --- 5. THE SECURITY BYPASS (Unsigned Code) ---
    # Force .NET to allow unsigned VSTO files from the local computer
    $trustPaths = @(
        "HKLM:\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel",
        "HKLM:\SOFTWARE\WOW6432Node\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel"
    )
    foreach ($tp in $trustPaths) {
        if (!(Test-Path $tp)) { New-Item -Path $tp -Force | Out-Null }
        Set-ItemProperty $tp -Name "MyComputer" -Value "Enabled"
        Set-ItemProperty $tp -Name "LocalIntranet" -Value "Enabled"
    }

    # --- 6. OFFICE RESILIENCY & TRUSTED LOCATIONS ---
    foreach ($ver in @("14.0", "15.0", "16.0")) {
        $regBase = "HKCU:\Software\Microsoft\Office\$ver\PowerPoint"
        # Reset Blacklists
        Remove-Item "$regBase\Resiliency\DisabledItems" -Recurse -ErrorAction SilentlyContinue
        Remove-Item "$regBase\Resiliency\CrashingAddins" -Recurse -ErrorAction SilentlyContinue
        # Set Trusted Location
        $trustPath = "$regBase\Security\Trusted Locations\OSCPoint"
        if (!(Test-Path $trustPath)) { New-Item $trustPath -Force | Out-Null }
        Set-ItemProperty $trustPath -Name "Path" -Value $oscDir
        Set-ItemProperty $trustPath -Name "AllowSubfolders" -Value 1 -Type DWord
    }

    # --- 7. REGISTRATION ---
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

    # --- 8. OSC CONFIGURATION ---
    $oscConfig = "HKCU:\Software\Zinc Event Production Ltd\OSCPoint"
    if (!(Test-Path $oscConfig)) { New-Item $oscConfig -Force | Out-Null }
    Set-ItemProperty $oscConfig -Name "RemoteHost" -Value $OSCTargetIP
    Set-ItemProperty $oscConfig -Name "RemotePort" -Value $RemotePort
    Set-ItemProperty $oscConfig -Name "LocalPort" -Value $LocalPort
    Set-ItemProperty $oscConfig -Name "FeedbackEnabled" -Value "True"
}

# --- 9. FIREWALL ---
Remove-NetFirewallRule -DisplayName "OSCPoint Inbound" -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "OSCPoint Inbound" -Direction Inbound -Action Allow -Protocol UDP -LocalPort $LocalPort | Out-Null

# --- 10. CLEANUP ---
Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "----------------------------------------------" -ForegroundColor Cyan
Write-Host "DEPLOYMENT COMPLETE" -ForegroundColor Green
Write-Host "If the plugin still doesn't appear, please RESTART your PC." -ForegroundColor Yellow
Write-Host "----------------------------------------------" -ForegroundColor Cyan
