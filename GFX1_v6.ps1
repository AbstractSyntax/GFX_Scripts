# v6 - GFX Cloud Setup (The "Complete" Merger)
# Integrates: oscpoint complete unattended install, plus firewall rules
# Run as Administrator

# --- CONFIGURATION START ---
$RepoRawUrl = "https://raw.githubusercontent.com/AbstractSyntax/GFX_Scripts/main"

# Download Links
$Link_InputDirector = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/InputDirector.v2.3.build173.Domain.Setup.exe1"
$Link_TallyViewer   = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/TallyViewer.ex1e"
$Link_Agent         = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/agent.e1xe"
$Link_OSCPoint      = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/oscpoint-2.2.0.0.zip"

$OSCTargetIP = "192.168.8.142"
$LocalPort   = 8000
$RemotePort  = 9000
# --- CONFIGURATION END ---

$TempDir = "$env:TEMP\GFXSetup"
if (Test-Path $TempDir) { Remove-Item -Path $TempDir -Recurse -Force }
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

Write-Host "--- Starting GFX Cloud Setup v6 test ---" -ForegroundColor Cyan

# --- HELPER FUNCTIONS ---
function Download-File {
    param ($Url, $FileName)
    $Dest = "$TempDir\$FileName"
    try {
        Write-Host "Downloading $FileName..." -ForegroundColor Gray
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing
    } catch { 
        Write-Warning "Failed to download $FileName"
        return $null 
    }
    return $Dest
}

# --- DOWNLOAD PHASE ---
$inputDirectorInstaller = Download-File $Link_InputDirector "InputDirectorSetup.exe"
$tallyViewerExe         = Download-File $Link_TallyViewer   "TallyViewer.exe"
$agentExe               = Download-File $Link_Agent         "agent.exe"
$oscZip                 = Download-File $Link_OSCPoint      "OSCPoint.zip"
$inputDirectorConfig    = Download-File "$RepoRawUrl/InputDirectorConfig.xml" "InputDirectorConfig.xml"

# --- SYSTEM CONFIGURATION (Restored from v6) ---
Write-Host "Configuring System Services & Registry..." -ForegroundColor Gray

# 1. Services
$Services = @("LanmanServer", "fdPHost")
foreach ($Svc in $Services) {
    Set-Service -Name $Svc -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name $Svc -ErrorAction SilentlyContinue
}

# 2. Hostname
if ((Get-ComputerInfo).WindowsProductName -notlike "*GFX1*") { 
    Write-Host "Renaming Computer to GFX1..." -ForegroundColor Yellow
    Rename-Computer -NewName "GFX1" -Force -ErrorAction SilentlyContinue 
}

# 3. NTLM & SMB (Critical Legacy Support from v6)
Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "LMCompatibilityLevel" -Value 1 -ErrorAction SilentlyContinue

# 4. Insecure Guest Auth (Policies AND Services)
$regPathPol = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"
$regPathSvc = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
if (!(Test-Path $regPathPol)) { New-Item -Path $regPathPol -Force | Out-Null }
Set-ItemProperty -Path $regPathPol -Name "AllowInsecureGuestAuth" -Value 1 -Type DWord
if (!(Test-Path $regPathSvc)) { New-Item -Path $regPathSvc -Force | Out-Null }
Set-ItemProperty -Path $regPathSvc -Name "AllowInsecureGuestAuth" -Value 1 -Type DWord

# 5. Refresh Network Stack
cmd /c "sc stop lanmanworkstation > nul 2>&1"
cmd /c "sc start lanmanworkstation > nul 2>&1"

# 6. Windows UI Tweaks (From v6)
Write-Host "Applying Windows UI Fixes..." -ForegroundColor Gray
# Taskbar Left Align (Win 11)
$explorerAdvPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
if (Test-Path $explorerAdvPath) { Set-ItemProperty -Path $explorerAdvPath -Name "TaskbarAl" -Value 0 -Type DWord }
# Restore Classic Context Menu (Win 11)
$clsidPath = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
if (!(Test-Path $clsidPath)) { New-Item -Path $clsidPath -Force | Out-Null }
Set-Item -Path $clsidPath -Value ""
# DPI Scaling
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "LogPixels" -Value 96

# 7. Firewall & Sharing (From v6)
Write-Host "Configuring Sharing & Firewall..." -ForegroundColor Gray
Set-NetFirewallRule -DisplayGroup "Network Discovery" -Enabled True -ErrorAction SilentlyContinue
Set-NetFirewallRule -DisplayGroup "File and Printer Sharing" -Enabled True -ErrorAction SilentlyContinue

$sharedFolderPath = "$env:USERPROFILE\Desktop\GFX1"
if (!(Test-Path $sharedFolderPath)) { New-Item -ItemType Directory -Path $sharedFolderPath -Force | Out-Null }
if (!(Get-SmbShare -Name "GFX1" -ErrorAction SilentlyContinue)) { 
    New-SmbShare -Name "GFX1" -Path $sharedFolderPath -FullAccess "Everyone" -ErrorAction SilentlyContinue 
}

# --- OSCPOINT INSTALLATION (The "Timed Executioner") ---
if ($oscZip -and (Test-Path $oscZip)) {
    Write-Host "--- Starting OSCPoint Deployment ---" -ForegroundColor Cyan
    
    $oscDir = "C:\OSCPoint"
    $vstoPath = "C:\OSCPoint\OSCPoint.vsto"

    # Clean & Extract
    Get-Process "powerpnt", "VSTOInstaller" -ErrorAction SilentlyContinue | Stop-Process -Force
    if (Test-Path $oscDir) { Remove-Item $oscDir -Recurse -Force }
    New-Item -ItemType Directory -Path $oscDir -Force | Out-Null
    Expand-Archive -Path $oscZip -DestinationPath $oscDir -Force
    Get-ChildItem -Path $oscDir -Recurse | Unblock-File

    # Firewall Bypass (PowerPoint Binary)
    Write-Host "[1/5] Setting Firewall Rules for PowerPoint..." -ForegroundColor Gray
    $ppPath = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\powerpnt.exe" -ErrorAction SilentlyContinue)."(Default)"
    if ($ppPath) {
        Remove-NetFirewallRule -DisplayName "OSCPoint Bypass" -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName "OSCPoint Bypass" -Direction Inbound -Program $ppPath -Action Allow -Protocol UDP -LocalPort $LocalPort -Profile Any -ErrorAction SilentlyContinue | Out-Null
    }

    # Trust Certificate
    Write-Host "[2/5] Trusting OctoCue Certificate..." -ForegroundColor Gray
    $setupPath = Join-Path $oscDir "setup.exe"
    if (Test-Path $setupPath) {
        $cert = (Get-AuthenticodeSignature $setupPath).SignerCertificate
        if ($cert) {
            foreach ($s in @("Root", "TrustedPublisher")) {
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($s, "LocalMachine")
                $store.Open("ReadWrite"); $store.Add($cert); $store.Close()
            }
        }
    }

    # Ghost Watcher (Auto-Clicker)
    Write-Host "[3/5] Launching Ghost Installer Watcher..." -ForegroundColor Yellow
    $GhostScript = {
        Add-Type -AssemblyName System.Windows.Forms
        $title = "Microsoft Office Customization Installer"
        
        Add-Type @"
          using System;
          using System.Runtime.InteropServices;
          public class User32 {
            [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
            [DllImport("user32.dll")] public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
          }
"@
        $start = Get-Date
        while (((Get-Date) - $start).TotalSeconds -lt 15) {
            $hwnd = [User32]::FindWindow($null, $title)
            if ($hwnd -ne [IntPtr]::Zero) {
                [User32]::SetForegroundWindow($hwnd)
                Start-Sleep -Milliseconds 500
                [System.Windows.Forms.SendKeys]::SendWait("%i") # Alt+I
                return
            }
            Start-Sleep -Seconds 1
        }
    }
    Start-Process powershell -ArgumentList "-NoProfile -WindowStyle Hidden -Command $GhostScript"

    # Trigger Installer & Executioner
    Write-Host "[4/5] Triggering Installer (Auto-kill in 15s)..." -ForegroundColor Gray
    $vstoInstallerPath = "C:\Program Files\Common Files\microsoft shared\VSTO\10.0\VSTOInstaller.exe"
    if (!(Test-Path $vstoInstallerPath)) { $vstoInstallerPath = "C:\Program Files (x86)\Common Files\microsoft shared\VSTO\10.0\VSTOInstaller.exe" }
    
    if (Test-Path $vstoInstallerPath) {
        Start-Process $vstoInstallerPath -ArgumentList "/i ""$vstoPath""" -PassThru | Out-Null
        Start-Sleep -Seconds 15
        Get-Process "VSTOInstaller" -ErrorAction SilentlyContinue | Stop-Process -Force
    }

    # OSC Config
    Write-Host "[5/5] Configuring Registry..." -ForegroundColor Gray
    $oscConfig = "HKCU:\Software\Zinc Event Production Ltd\OSCPoint"
    if (!(Test-Path $oscConfig)) { New-Item -Path $oscConfig -Force | Out-Null }
    Set-ItemProperty -Path $oscConfig -Name "RemoteHost" -Value $OSCTargetIP
    Set-ItemProperty -Path $oscConfig -Name "RemotePort" -Value $RemotePort
    Set-ItemProperty -Path $oscConfig -Name "LocalPort" -Value $LocalPort
    Set-ItemProperty -Path $oscConfig -Name "FeedbackEnabled" -Value "True"

    Write-Host "OSCPoint Deployment Complete." -ForegroundColor Green
}

# --- OTHER APPS ---

if ($inputDirectorInstaller -and (Test-Path $inputDirectorInstaller)) {
    Write-Host "Installing Input Director..." -ForegroundColor Yellow
    Start-Process -FilePath $inputDirectorInstaller -ArgumentList "/S" -Wait
    
    # Smarter Path Detection (From v6)
    $idCmdPath = if ([Environment]::Is64BitOperatingSystem) { "C:\Program Files\Input Director\IDCmd.exe" } else { "C:\Program Files (x86)\Input Director\IDCmd.exe" }
    
    if (Test-Path $idCmdPath -and $inputDirectorConfig -and (Test-Path $inputDirectorConfig)) {
        Start-Process -FilePath $idCmdPath -ArgumentList "-importconfig:`"$inputDirectorConfig`"" -Wait
        Write-Host "Input Director Config Imported." -ForegroundColor Green
    }
}

if ($agentExe -and (Test-Path $agentExe)) {
    $agentDest = "$([System.Environment]::GetFolderPath('CommonStartup'))\agent.exe"
    Copy-Item -Path $agentExe -Destination $agentDest -Force -ErrorAction SilentlyContinue
    Unblock-File -Path $agentDest -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName "GFX Agent" -Direction Inbound -Program $agentDest -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
}

if ($tallyViewerExe -and (Test-Path $tallyViewerExe)) {
    Copy-Item -Path $tallyViewerExe -Destination "$env:USERPROFILE\Desktop\TallyViewer.exe" -Force
}

# --- CLEANUP & EXIT ---
Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "---------------------------------------------------" -ForegroundColor Cyan
Write-Host "Setup Finished. Restarting in 5 Seconds..." -ForegroundColor Green
Write-Host "---------------------------------------------------" -ForegroundColor Cyan

Start-Sleep -Seconds 5
Restart-Computer -Force
