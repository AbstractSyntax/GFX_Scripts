# v10 Final Hybrid Version (Machine-Wide OSCPoint & GFX Setup)
# Run as Administrator

# --- CONFIGURATION START ---

# 1. GITHUB REPO RAW URL (For the XML config file)
$RepoRawUrl = "https://raw.githubusercontent.com/AbstractSyntax/GFX_Scripts/main"

# 2. GITHUB RELEASE LINKS
$Link_InputDirector = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/InputDirector.v2.3.build173.Domain.Setup.exe"
$Link_TallyViewer   = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/TallyViewer.exe"
$Link_Agent         = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/agent.exe"
$Link_OSCPoint      = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/OSCPoint.zip"

# 3. SETTINGS
$OSCTargetIP = "192.168.8.142"

# --- CONFIGURATION END ---

$TempDir = "$env:TEMP\GFXSetup"
if (Test-Path $TempDir) { Remove-Item -Path $TempDir -Recurse -Force }
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

Write-Host "--- Starting GFX Cloud Setup ---" -ForegroundColor Cyan

function Download-File {
    param ($Url, $FileName)
    $Dest = "$TempDir\$FileName"
    try {
        Write-Host "Downloading $FileName..." -ForegroundColor Gray
        Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing
    } catch {
        Write-Host "Error downloading $FileName. Check URL." -ForegroundColor Red
        return $null
    }
    return $Dest
}

# --- Download Phase ---
$inputDirectorInstaller = Download-File $Link_InputDirector "InputDirectorSetup.exe"
$tallyViewerExe         = Download-File $Link_TallyViewer   "TallyViewer.exe"
$agentExe               = Download-File $Link_Agent         "agent.exe"
$oscZip                 = Download-File $Link_OSCPoint      "OSCPoint.zip"
$inputDirectorConfig    = Download-File "$RepoRawUrl/InputDirectorConfig.xml" "InputDirectorConfig.xml"

# --- SYSTEM CONFIGURATION ---

# 1. Computer Name
if ((Get-ComputerInfo).WindowsProductName -notlike "*GFX1*") {
    Rename-Computer -NewName "GFX1" -Force
    Write-Host "Renaming Computer to GFX1..." -ForegroundColor Yellow
}

# 2. SMB & Network Services
Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
Set-Service -Name "LanmanServer" -StartupType Automatic; Start-Service "LanmanServer"
Set-Service -Name "fdPHost" -StartupType Automatic; Start-Service "fdPHost"

# 3. Registry Security
$regPathPol = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"
$regPathSvc = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
if (!(Test-Path $regPathPol)) { New-Item -Path $regPathPol -Force | Out-Null }
Set-ItemProperty -Path $regPathPol -Name "AllowInsecureGuestAuth" -Value 1 -Type DWord
Set-ItemProperty -Path $regPathSvc -Name "AllowInsecureGuestAuth" -Value 1 -Type DWord
cmd /c "sc stop lanmanworkstation > nul 2>&1"; cmd /c "sc start lanmanworkstation > nul 2>&1"

# 4. Create Desktop Share
$sharedFolderPath = "$env:USERPROFILE\Desktop\GFX1"
if (!(Test-Path $sharedFolderPath)) { New-Item -ItemType Directory -Path $sharedFolderPath -Force | Out-Null }
Set-NetFirewallRule -DisplayGroup "Network Discovery" -Enabled True
Set-NetFirewallRule -DisplayGroup "File and Printer Sharing" -Enabled True
if (!(Get-SmbShare -Name "GFX1" -ErrorAction SilentlyContinue)) {
    New-SmbShare -Name "GFX1" -Path $sharedFolderPath -FullAccess "Everyone"
}

# 5. UI Fixes & Display
$explorerAdvPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
if (Test-Path $explorerAdvPath) { Set-ItemProperty -Path $explorerAdvPath -Name "TaskbarAl" -Value 0 -Type DWord }
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "LogPixels" -Value 96

# --- INSTALLATION ---

# 1. OSCPoint Machine-Wide Installation
if ($oscZip -and (Test-Path $oscZip)) {
    Write-Host "Installing OSCPoint for All Users..." -ForegroundColor Yellow
    $oscPermanentDir = "C:\ProgramData\OSCPoint"
    if (Test-Path $oscPermanentDir) { Remove-Item $oscPermanentDir -Recurse -Force }
    New-Item -ItemType Directory -Path $oscPermanentDir -Force | Out-Null
    
    Expand-Archive -Path $oscZip -DestinationPath $oscPermanentDir -Force
    $vstoFile = Get-ChildItem -Path $oscPermanentDir -Filter "OSCPoint.vsto" -Recurse | Select-Object -First 1

    if ($vstoFile) {
        # Trust Certificate
        $cert = (Get-AuthenticodeSignature $vstoFile.FullName).SignerCertificate
        if ($cert) {
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("TrustedPublisher", "LocalMachine")
            $store.Open("ReadWrite"); $store.Add($cert); $store.Close()
        }

        # Register in HKLM so it survives for every user profile
        $regPath = "HKLM:\SOFTWARE\Microsoft\Office\PowerPoint\Addins\OSCPoint"
        if (!(Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
        Set-ItemProperty -Path $regPath -Name "Description" -Value "OSCPoint"
        Set-ItemProperty -Path $regPath -Name "FriendlyName" -Value "OSCPoint"
        Set-ItemProperty -Path $regPath -Name "Manifest" -Value "$($vstoFile.FullName)|vstolocal"
        Set-ItemProperty -Path $regPath -Name "LoadBehavior" -Value 3 -Type DWord

        # Configure OSC Settings (Target IP and Feedback)
        $oscConfigPath = "HKCU:\Software\Zinc Event Production Ltd\OSCPoint"
        if (!(Test-Path $oscConfigPath)) { New-Item -Path $oscConfigPath -Force | Out-Null }
        Set-ItemProperty -Path $oscConfigPath -Name "RemoteHost" -Value $OSCTargetIP
        Set-ItemProperty -Path $oscConfigPath -Name "FeedbackEnabled" -Value "True"
        Set-ItemProperty -Path $oscConfigPath -Name "RemotePort" -Value 9000
        Set-ItemProperty -Path $oscConfigPath -Name "LocalPort" -Value 8000
        
        # PowerPoint Firewall Rule (UDP 8000)
        $ppPath = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\powerpnt.exe")."(default)"
        if ($ppPath) {
            New-NetFirewallRule -DisplayName "OSCPoint (PowerPoint)" -Direction Inbound -Program $ppPath -Action Allow -Protocol UDP -LocalPort 8000 -Profile Any -ErrorAction SilentlyContinue
        }
        Write-Host "OSCPoint installed and configured." -ForegroundColor Green
    }
}

# 2. Input Director
if ($inputDirectorInstaller -and (Test-Path $inputDirectorInstaller)) {
    Write-Host "Installing Input Director..." -ForegroundColor Yellow
    Start-Process -FilePath $inputDirectorInstaller -ArgumentList "/S" -Wait
    if ($inputDirectorConfig -and (Test-Path $inputDirectorConfig)) {
        $idCmdPath = if ([Environment]::Is64BitOperatingSystem) { "C:\Program Files\Input Director\IDCmd.exe" } else { "C:\Program Files (x86)\Input Director\IDCmd.exe" }
        if (Test-Path $idCmdPath) { Start-Process -FilePath $idCmdPath -ArgumentList "-importconfig:`"$inputDirectorConfig`"" -Wait }
    }
}

# 3. Agent.exe Setup
if ($agentExe -and (Test-Path $agentExe)) {
    $agentDestination = "$([System.Environment]::GetFolderPath('CommonStartup'))\agent.exe"
    # Copy file (Will silently skip if file is locked/running)
    Copy-Item -Path $agentExe -Destination $agentDestination -Force -ErrorAction SilentlyContinue
    Unblock-File -Path $agentDestination -ErrorAction SilentlyContinue
    # Firewall Rule
    New-NetFirewallRule -DisplayName "GFX Agent" -Direction Inbound -Program $agentDestination -Action Allow -Profile Any -ErrorAction SilentlyContinue
    Write-Host "Agent.exe set to autostart." -ForegroundColor Green
}

# 4. TallyViewer
if ($tallyViewerExe -and (Test-Path $tallyViewerExe)) {
    Copy-Item -Path $tallyViewerExe -Destination "$env:USERPROFILE\Desktop\TallyViewer.exe" -Force
    Write-Host "TallyViewer copied to Desktop." -ForegroundColor Green
}

# Cleanup
Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Setup Complete. Restarting..." -ForegroundColor Yellow
Restart-Computer -Force
