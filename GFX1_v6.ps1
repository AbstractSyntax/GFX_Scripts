# v50 - GFX Cloud Setup (Filename Fix & Folder Flattening)
# Run as Administrator

# --- CONFIGURATION START ---
$RepoRawUrl = "https://raw.githubusercontent.com/AbstractSyntax/GFX_Scripts/main"

# Download Links
$Link_InputDirector = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/rele1ase/InputDirector.v2.3.build173.Domain.Setup.exe"
$Link_TallyViewer   = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/rele1ase/TallyViewer.exe"
$Link_Agent         = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/relea1se/agent.exe"
$Link_OSCPoint      = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/oscpoint-2.2.0.0.zip"
$Link_VSTO_Runtime  = "https://go.microsoft.com/fwlink/?LinkId=158918" 

$OSCTargetIP = "192.168.8.142"
$LocalPort   = 8000
$RemotePort  = 9000
# --- CONFIGURATION END ---

$TempDir = "$env:TEMP\GFXSetup"
if (Test-Path $TempDir) { Remove-Item -Path $TempDir -Recurse -Force }
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

Write-Host "--- Starting GFX Cloud Setup v50 ---" -ForegroundColor Cyan

# --- HELPER: ROBUST DOWNLOAD ---
function Download-File {
    param ($Url, $FileName)
    $Dest = "$TempDir\$FileName"
    try {
        Write-Host "Downloading $FileName..." -ForegroundColor Gray
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing -ErrorAction Stop
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
if ((Get-ComputerInfo).WindowsProductName -notlike "*GFX1*") { 
    Write-Host "Renaming Computer to GFX1..." -ForegroundColor Yellow
    Rename-Computer -NewName "GFX1" -Force -ErrorAction SilentlyContinue 
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
$sharedFolderPath = "$env:USERPROFILE\Desktop\GFX1"
if (!(Test-Path $sharedFolderPath)) { New-Item -ItemType Directory -Path $sharedFolderPath -Force | Out-Null }
if (!(Get-SmbShare -Name "GFX1" -ErrorAction SilentlyContinue)) { 
    New-SmbShare -Name "GFX1" -Path $sharedFolderPath -FullAccess "Everyone" -ErrorAction SilentlyContinue 
}

# --- STEP 3: INSTALL EASY APPS ---
if ($inputDirectorInstaller -and (Test-Path $inputDirectorInstaller)) {
    Write-Host "Installing Input Director..." -ForegroundColor Yellow
    Start-Process -FilePath $inputDirectorInstaller -ArgumentList "/S" -Wait
    $idCmdPath = if ([Environment]::Is64BitOperatingSystem) { "C:\Program Files\Input Director\IDCmd.exe" } else { "C:\Program Files (x86)\Input Director\IDCmd.exe" }
    if (Test-Path $idCmdPath -and $inputDirectorConfig -and (Test-Path $inputDirectorConfig)) {
        Start-Process -FilePath $idCmdPath -ArgumentList "-importconfig:`"$inputDirectorConfig`"" -Wait
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

# --- STEP 4: OSCPOINT INSTALLATION (Fixed) ---
if ($oscZip -and (Test-Path $oscZip)) {
    Write-Host "--- Starting OSCPoint Deployment ---" -ForegroundColor Cyan
    
    $oscDir = "C:\OSCPoint"
    # Note: We will force the file to this name in the steps below
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
    
    # --- CRITICAL FIX: FLATTEN FOLDER & RENAME ---
    # Find the .vsto file wherever it is (subfolder or root)
    $foundVsto = Get-ChildItem -Path $oscDir -Filter "*.vsto" -Recurse | Select-Object -First 1
    
    if ($foundVsto) {
        Write-Host "Found VSTO at: $($foundVsto.FullName)" -ForegroundColor Gray
        
        # If it's in a subfolder, move everything up to Root C:\OSCPoint
        if ($foundVsto.Directory.FullName -ne $oscDir) {
            Write-Host "Flattening directory structure..." -ForegroundColor Gray
            Get-ChildItem -Path $foundVsto.Directory.FullName | Move-Item -Destination $oscDir -Force
        }

        # Rename the file to remove spaces (Matches $vstoPath)
        $currentPath = Join-Path $oscDir $foundVsto.Name
        if ($foundVsto.Name -ne "OSCPoint.vsto") {
            Write-Host "Renaming to OSCPoint.vsto..." -ForegroundColor Gray
            Rename-Item -Path $currentPath -NewName "OSCPoint.vsto" -Force
        }
    } else {
        Write-Error "ERROR: No .vsto file found in the zip archive!"
        # Exit this block to prevent errors downstream
        continue 
    }
    
    # Unblock everything now that it's in place
    Get-ChildItem -Path $oscDir -Recurse | Unblock-File

    # C. Firewall Bypass (PowerPoint)
    $ppPath = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\powerpnt.exe" -ErrorAction SilentlyContinue)."(Default)"
    if ($ppPath) {
        Remove-NetFirewallRule -DisplayName "OSCPoint Bypass" -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName "OSCPoint Bypass" -Direction Inbound -Program $ppPath -Action Allow -Protocol UDP -LocalPort $LocalPort -Profile Any -ErrorAction SilentlyContinue | Out-Null
    }

    # D. Trust Certificate
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

    # E. Ghost Watcher (Auto-Clicker)
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

    # F. Trigger Installer
    $vstoInstallerPath = "C:\Program Files\Common Files\microsoft shared\VSTO\10.0\VSTOInstaller.exe"
    if (!(Test-Path $vstoInstallerPath)) { $vstoInstallerPath = "C:\Program Files (x86)\Common Files\microsoft shared\VSTO\10.0\VSTOInstaller.exe" }
    
    if (Test-Path $vstoInstallerPath) {
        # Using the now guaranteed path: C:\OSCPoint\OSCPoint.vsto
        Start-Process $vstoInstallerPath -ArgumentList "/i ""$vstoPath""" -PassThru | Out-Null
        Start-Sleep -Seconds 15
        Get-Process "VSTOInstaller" -ErrorAction SilentlyContinue | Stop-Process -Force
    }

    # G. Config
    $oscConfig = "HKCU:\Software\Zinc Event Production Ltd\OSCPoint"
    if (!(Test-Path $oscConfig)) { New-Item -Path $oscConfig -Force | Out-Null }
    Set-ItemProperty -Path $oscConfig -Name "RemoteHost" -Value $OSCTargetIP
    Set-ItemProperty -Path $oscConfig -Name "RemotePort" -Value $RemotePort
    Set-ItemProperty -Path $oscConfig -Name "LocalPort" -Value $LocalPort
    Set-ItemProperty -Path $oscConfig -Name "FeedbackEnabled" -Value "True"
}

# --- CLEANUP & EXIT ---
Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "---------------------------------------------------" -ForegroundColor Cyan
Write-Host "Setup Finished. Restarting in 5 Seconds..." -ForegroundColor Green
Write-Host "---------------------------------------------------" -ForegroundColor Cyan

Start-Sleep -Seconds 5
#Restart-Computer -Force
