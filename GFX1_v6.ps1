#v6 Hybrid Version (Added OSCPoint Auto-Install & Config)

# --- CONFIGURATION START ---

$RepoRawUrl = "https://raw.githubusercontent.com/AbstractSyntax/GFX_Scripts/main"

# GitHub Release Links
$Link_InputDirector = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/InputDirector.v2.3.build173.Domain.Setup.exe"
$Link_TallyViewer   = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/TallyViewer.exe"
$Link_Agent         = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/agent.exe"
$Link_OSCPoint      = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/oscpoint-2.2.0.0.zip"

# --- CONFIGURATION END ---

$TempDir = "$env:TEMP\GFXSetup"
if (Test-Path $TempDir) { Remove-Item -Path $TempDir -Recurse -Force }
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
Write-Host "--- Starting Cloud Setup ---" -ForegroundColor Cyan

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
$oscZip                 = Download-File $Link_OSCPoint      "OSCPoint.zip" # Download Zip

# Download XML Config from the Raw Code Repo
$inputDirectorConfig = Download-File "$RepoRawUrl/InputDirectorConfig.xml" "InputDirectorConfig.xml"

# --- SYSTEM CONFIGURATION ---

# 1. Computer Name
if ((Get-ComputerInfo).WindowsProductName -notlike "*GFX1*") {
    Rename-Computer -NewName "GFX1" -Force
    Write-Host "Renaming Computer to GFX1..." -ForegroundColor Yellow
}

# [ ... Sections 2 through 5 remain the same as your original script ... ]
Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
Set-Service -Name "LanmanServer" -StartupType Automatic; Start-Service "LanmanServer"
Set-Service -Name "fdPHost" -StartupType Automatic; Start-Service "fdPHost"
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "LMCompatibilityLevel" -Value 1
$regPathPol = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"
$regPathSvc = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
if (!(Test-Path $regPathPol)) { New-Item -Path $regPathPol -Force | Out-Null }
Set-ItemProperty -Path $regPathPol -Name "AllowInsecureGuestAuth" -Value 1 -Type DWord
Set-ItemProperty -Path $regPathSvc -Name "AllowInsecureGuestAuth" -Value 1 -Type DWord
cmd /c "sc stop lanmanworkstation > nul 2>&1"; cmd /c "sc start lanmanworkstation > nul 2>&1"
$sharedFolderPath = "$env:USERPROFILE\Desktop\GFX1"
if (!(Test-Path $sharedFolderPath)) { New-Item -ItemType Directory -Path $sharedFolderPath -Force | Out-Null }
Set-NetFirewallRule -DisplayGroup "Network Discovery" -Enabled True
Set-NetFirewallRule -DisplayGroup "File and Printer Sharing" -Enabled True
if (!(Get-SmbShare -Name "GFX1" -ErrorAction SilentlyContinue)) { New-SmbShare -Name "GFX1" -Path $sharedFolderPath -FullAccess "Everyone" }

# 6. Windows 11 UI Fixes
$explorerAdvPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
if (Test-Path $explorerAdvPath) { Set-ItemProperty -Path $explorerAdvPath -Name "TaskbarAl" -Value 0 -Type DWord }
$clsidPath = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
if (!(Test-Path $clsidPath)) { New-Item -Path $clsidPath -Force | Out-Null }
Set-Item -Path $clsidPath -Value ""

# 7. Display Settings
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "LogPixels" -Value 96
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "Win8DpiScaling" -Value 1

# --- INSTALLATION ---

# Install Input Director
if ($inputDirectorInstaller -and (Test-Path $inputDirectorInstaller)) {
    Write-Host "Installing Input Director..." -ForegroundColor Yellow
    Start-Process -FilePath $inputDirectorInstaller -ArgumentList "/S" -Wait
    if ($inputDirectorConfig -and (Test-Path $inputDirectorConfig)) {
        $idCmdPath = if ([Environment]::Is64BitOperatingSystem) { "C:\Program Files\Input Director\IDCmd.exe" } else { "C:\Program Files (x86)\Input Director\IDCmd.exe" }
        if (Test-Path $idCmdPath) { Start-Process -FilePath $idCmdPath -ArgumentList "-importconfig:`"$inputDirectorConfig`"" -Wait }
    }
}

# ADDED: OSCPoint Installation
if ($oscZip -and (Test-Path $oscZip)) {
    Unblock-File -Path $oscZip
    Write-Host "Installing OSCPoint..." -ForegroundColor Yellow
    $oscExtracted = "$TempDir\OSCPoint"
    Expand-Archive -Path $oscZip -DestinationPath $oscExtracted -Force
    
    # Locate the .vsto file inside the extracted zip
    $vstoFile = Get-ChildItem -Path $oscExtracted -Filter "*.vsto" -Recurse | Select-Object -First 1
    
    if ($vstoFile) {
        # Trust the certificate so it installs without a prompt
        $cert = (Get-AuthenticodeSignature $vstoFile.FullName).SignerCertificate
        if ($cert) {
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("TrustedPublisher", "LocalMachine")
            $store.Open("ReadWrite")
            $store.Add($cert)
            $store.Close()
        }

        # Run the VSTO Silent Installer
        $vstoInstaller = "$env:CommonProgramFiles\microsoft shared\VSTO\10.0\VSTOInstaller.exe"
        if (Test-Path $vstoInstaller) {
            Start-Process $vstoInstaller -ArgumentList "/i `"$($vstoFile.FullName)`" /s" -Wait
            Write-Host "OSCPoint Installed Successfully." -ForegroundColor Green
        }
    }
}

# ADDED: OSCPoint Registry Configuration
Write-Host "Configuring OSCPoint Settings..." -ForegroundColor Gray
$oscRegPath = "HKCU:\Software\Zinc Event Production Ltd\OSCPoint"
if (!(Test-Path $oscRegPath)) { New-Item -Path $oscRegPath -Force | Out-Null }
Set-ItemProperty -Path $oscRegPath -Name "RemoteHost" -Value "192.168.8.142"
Set-ItemProperty -Path $oscRegPath -Name "FeedbackEnabled" -Value "True"
Set-ItemProperty -Path $oscRegPath -Name "RemotePort" -Value 9000
Set-ItemProperty -Path $oscRegPath -Name "LocalPort" -Value 8000

# --- Firewall Rule for OSCPoint (PowerPoint) ---
Write-Host "Creating Firewall Rule for PowerPoint/OSCPoint..." -ForegroundColor Gray

# 1. Find the PowerPoint executable path dynamically
$ppPath = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\powerpnt.exe")."(default)"

if ($ppPath -and (Test-Path $ppPath)) {
    $ruleName = "Allow_OSCPoint_PowerPoint"
    
    # Check if rule exists; if not, create it
    if (!(Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue)) {
        # We allow PowerPoint to communicate on all profiles to ensure OSC works on show networks
        New-NetFirewallRule -Name $ruleName `
                            -DisplayName "OSCPoint (PowerPoint)" `
                            -Description "Allows OSCPoint add-in to receive OSC messages inside PowerPoint." `
                            -Direction Inbound `
                            -Program $ppPath `
                            -Action Allow `
                            -Protocol UDP `
                            -LocalPort 8000 `
                            -Profile Any
        Write-Host "Firewall rule created for PowerPoint on UDP Port 8000." -ForegroundColor Green
    }
} else {
    Write-Warning "Could not locate powerpnt.exe. Firewall rule not created."
}

# Copy TallyViewer
if ($tallyViewerExe -and (Test-Path $tallyViewerExe)) {
    Copy-Item -Path $tallyViewerExe -Destination "$env:USERPROFILE\Desktop\TallyViewer.exe" -Force
}

# Autostart Agent + Trust & Firewall Rule
if ($agentExe -and (Test-Path $agentExe)) {
    $agentDestination = "$([System.Environment]::GetFolderPath('CommonStartup'))\agent.exe"
    
    # 1. Copy to startup
    Copy-Item -Path $agentExe -Destination $agentDestination -Force
    
    # 2. Unblock the file (removes the "this file came from another computer" security flag)
    Unblock-File -Path $agentDestination
    
    # 3. Create Firewall Rule (Prevents the "Allow this app on your network" popup)
    Write-Host "Creating Firewall Rule for Agent.exe..." -ForegroundColor Gray
    $ruleName = "Allow_GFX_Agent"
    
    # Check if rule exists; if not, create it
    if (!(Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -Name $ruleName `
                            -DisplayName "GFX Agent (Auto-Allowed)" `
                            -Description "Allows Agent.exe to communicate on the network without prompts." `
                            -Direction Inbound `
                            -Program $agentDestination `
                            -Action Allow `
                            -Protocol Any `
                            -Profile Any
        Write-Host "Firewall rule created for Agent." -ForegroundColor Green
    }
    
    Write-Host "Agent.exe set to autostart and trusted." -ForegroundColor Green
}

# Cleanup
Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Setup Complete. Restarting..." -ForegroundColor Yellow
#Restart-Computer -Force
