# v6 - GFX Cloud Setup
# Run as Administrator

# --- CONFIGURATION START ---
$RepoRawUrl = "https://raw.githubusercontent.com/AbstractSyntax/GFX_Scripts/main"

# Download Links
$Link_InputDirector = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/InputDirector.v2.3.build173.Domain.Setup.exe"
$Link_TallyViewer   = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/TallyViewer.exe"
$Link_Agent         = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/agent.exe"
$Link_OSCPoint      = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/oscpoint-2.2.0.0.zip"
$Link_VSTO_Runtime  = "https://go.microsoft.com/fwlink/?LinkId=158918" 

# OSCPoint Settings
$OSCTargetIP = "192.168.8.142"
$RemotePort  = 35550
$LocalPort   = 35551
# --- CONFIGURATION END ---

$TempDir = "$env:TEMP\GFXSetup"
if (Test-Path $TempDir) { Remove-Item -Path $TempDir -Recurse -Force }
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

Write-Host "--- Starting GFX Cloud Setup v6 ---" -ForegroundColor Cyan

# --- HELPER: ROBUST DOWNLOAD ---
function Download-File {
    param ($Url, $FileName)
    $Dest = "$TempDir\$FileName"
    try {
        Write-Host "Downloading $FileName..." -ForegroundColor Gray
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        # UserAgent prevents GitHub 403 errors
        Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing -UserAgent "Mozilla/5.0" -ErrorAction Stop
        return $Dest
    } catch { 
        Write-Warning "Failed to download $FileName. Check URL or Internet."
        return $null 
    }
}

# --- STEP 1: DOWNLOAD EVERYTHING ---
$inputDirectorInstaller = Download-File $Link_InputDirector "InputDirectorSetup.exe"
$tallyViewerExe         = Download-File $Link_TallyViewer   "TallyViewer.exe"
$agentExe               = Download-File $Link_Agent         "agent.exe"
$oscZip                 = Download-File $Link_OSCPoint      "OSCPoint.zip"
# Restore the XML Config Download
$inputDirectorConfig    = Download-File "$RepoRawUrl/InputDirectorConfig.xml" "InputDirectorConfig.xml"

# --- STEP 2: SYSTEM TWEAKS ---
Write-Host "Configuring System Services & Registry..." -ForegroundColor Gray

# Services
$Services = @("LanmanServer", "fdPHost")
foreach ($Svc in $Services) {
    Set-Service -Name $Svc -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name $Svc -ErrorAction SilentlyContinue
}

# Hostname
if ((Get-ComputerInfo).WindowsProductName -notlike "*GFX3*") { 
    Write-Host "Renaming Computer to GFX3..." -ForegroundColor Yellow
    Rename-Computer -NewName "GFX3" -Force -ErrorAction SilentlyContinue 
}

# SMB & Legacy Auth
Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "LMCompatibilityLevel" -Value 1 -ErrorAction SilentlyContinue
$regPathPol = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"
if (!(Test-Path $regPathPol)) { New-Item -Path $regPathPol -Force | Out-Null }
Set-ItemProperty -Path $regPathPol -Name "AllowInsecureGuestAuth" -Value 1 -Type DWord

# Windows UI Tweaks
$explorerAdvPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
if (Test-Path $explorerAdvPath) { Set-ItemProperty -Path $explorerAdvPath -Name "TaskbarAl" -Value 0 -Type DWord }
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "LogPixels" -Value 96

# Firewall & Sharing
Set-NetFirewallRule -DisplayGroup "Network Discovery" -Enabled True -ErrorAction SilentlyContinue
Set-NetFirewallRule -DisplayGroup "File and Printer Sharing" -Enabled True -ErrorAction SilentlyContinue
$sharedFolderPath = "$env:USERPROFILE\Desktop\GFX3"
if (!(Test-Path $sharedFolderPath)) { New-Item -ItemType Directory -Path $sharedFolderPath -Force | Out-Null }
if (!(Get-SmbShare -Name "GFX3" -ErrorAction SilentlyContinue)) { 
    New-SmbShare -Name "GFX3" -Path $sharedFolderPath -FullAccess "Everyone" -ErrorAction SilentlyContinue 
}

# --- STEP 3: INSTALL EASY APPS ---

# Input Director + Config Import
if ($inputDirectorInstaller -and (Test-Path $inputDirectorInstaller)) {
    Write-Host "Installing Input Director..." -ForegroundColor Yellow
    Start-Process -FilePath $inputDirectorInstaller -ArgumentList "/S" -Wait
    
    # Restore the Config Import Logic
    $idCmdPath = if ([Environment]::Is64BitOperatingSystem) { "C:\Program Files (x86)\Input Director\IDCmd.exe" } else { "C:\Program Files\Input Director\IDCmd.exe" }
    # Fallback check
    if (!(Test-Path $idCmdPath)) { $idCmdPath = "C:\Program Files\Input Director\IDCmd.exe" }

    if (Test-Path $idCmdPath) {
        if ($inputDirectorConfig -and (Test-Path $inputDirectorConfig)) {
            Write-Host "Importing Input Director Config..." -ForegroundColor Gray
            Start-Process -FilePath $idCmdPath -ArgumentList "-importconfig:`"$inputDirectorConfig`"" -Wait
            Write-Host "Input Director configured." -ForegroundColor Green
        } else {
            Write-Warning "Input Director Config XML not found. Skipping import."
        }
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

# --- STEP 4: OSCPOINT INSTALLATION ---
if ($oscZip -and (Test-Path $oscZip)) {
    Write-Host "--- Starting OSCPoint Deployment ---" -ForegroundColor Cyan
    
    $oscDir = "C:\OSCPoint"
    $vstoPath = "C:\OSCPoint\OSCPoint.vsto"

    # A. Pre-Requisite Check: VSTO Runtime
    $vstoCheck = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\VSTO\Runtime\Wf\4.0" -ErrorAction SilentlyContinue
    if (!$vstoCheck) {
        Write-Host "[Required] VSTO Runtime Engine missing. Downloading..." -ForegroundColor Yellow
        $vstoExe = Download-File $Link_VSTO_Runtime "vstor_redist.exe"
        if ($vstoExe) {
            Write-Host "Installing VSTO Runtime..." -ForegroundColor Gray
            Start-Process $vstoExe -ArgumentList "/q /norestart" -Wait
        }
    }

    # B. Clean & Extract
    Get-Process "powerpnt", "VSTOInstaller" -ErrorAction SilentlyContinue | Stop-Process -Force
    if (Test-Path $oscDir) { Remove-Item $oscDir -Recurse -Force }
    New-Item -ItemType Directory -Path $oscDir -Force | Out-Null
    Expand-Archive -Path $oscZip -DestinationPath $oscDir -Force
    
    # C. Flatten & Rename (Critical Fix from v50)
    $foundVsto = Get-ChildItem -Path $oscDir -Filter "*.vsto" -Recurse | Select-Object -First 1
    if ($foundVsto) {
        if ($foundVsto.Directory.FullName -ne $oscDir) {
            Get-ChildItem -Path $foundVsto.Directory.FullName | Move-Item -Destination $oscDir -Force
        }
        $currentPath = Join-Path $oscDir $foundVsto.Name
        if ($foundVsto.Name -ne "OSCPoint.vsto") {
            Rename-Item -Path $currentPath -NewName "OSCPoint.vsto" -Force
        }
    }
    
    Get-ChildItem -Path $oscDir -Recurse | Unblock-File

    # D. Firewall Bypass (PowerPoint - Updated Port)
    $ppPath = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\powerpnt.exe" -ErrorAction SilentlyContinue)."(Default)"
    if ($ppPath) {
        Remove-NetFirewallRule -DisplayName "OSCPoint Bypass" -ErrorAction SilentlyContinue
        # Using $LocalPort (35551)
        New-NetFirewallRule -DisplayName "OSCPoint Bypass" -Direction Inbound -Program $ppPath -Action Allow -Protocol UDP -LocalPort $LocalPort -Profile Any -ErrorAction SilentlyContinue | Out-Null
    }

    # E. Trust Certificate
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

    # F. Ghost Watcher (Auto-Clicker)
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
        while (((Get-Date) - $start).TotalSeconds -lt 20) {
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

    # G. Trigger Installer
    $vstoInstallerPath = "C:\Program Files\Common Files\microsoft shared\VSTO\10.0\VSTOInstaller.exe"
    if (!(Test-Path $vstoInstallerPath)) { $vstoInstallerPath = "C:\Program Files (x86)\Common Files\microsoft shared\VSTO\10.0\VSTOInstaller.exe" }
    
    if (Test-Path $vstoInstallerPath) {
        Start-Process $vstoInstallerPath -ArgumentList "/i ""$vstoPath""" -PassThru | Out-Null
        Start-Sleep -Seconds 15
        Get-Process "VSTOInstaller" -ErrorAction SilentlyContinue | Stop-Process -Force
    }

    # H. OSC Config (Updated Ports)
    Write-Host "Configuring OSCPoint Registry..." -ForegroundColor Gray
    $oscConfig = "HKCU:\Software\Zinc Event Production Ltd\OSCPoint"
    if (!(Test-Path $oscConfig)) { New-Item -Path $oscConfig -Force | Out-Null }
    Set-ItemProperty -Path $oscConfig -Name "RemoteHost" -Value $OSCTargetIP
    Set-ItemProperty -Path $oscConfig -Name "RemotePort" -Value $RemotePort # 35550
    Set-ItemProperty -Path $oscConfig -Name "LocalPort" -Value $LocalPort   # 35551
    Set-ItemProperty -Path $oscConfig -Name "FeedbackEnabled" -Value "True"
}

# --- CLEANUP & EXIT ---
Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "---------------------------------------------------" -ForegroundColor Cyan
Write-Host "Setup Finished. Restarting in 5 Seconds..." -ForegroundColor Green
Write-Host "---------------------------------------------------" -ForegroundColor Cyan

Start-Sleep -Seconds 5
Restart-Computer -Force
