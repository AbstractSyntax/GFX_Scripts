#v6 Final Hybrid Version (Repo for Code, Releases for Big Files)

# --- CONFIGURATION START ---

# 1. GITHUB REPO RAW URL (For the XML config file)
#    (Example: https://raw.githubusercontent.com/User/Repo/main)
$RepoRawUrl = "https://raw.githubusercontent.com/AbstractSyntax/GFX_Scripts/main"

# 2. GITHUB RELEASE LINKS (For the Big EXE files)
#    Paste the links you copied from the "Releases" page here:
$Link_InputDirector = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/InputDirector.v2.3.build173.Domain.Setup.exe"
$Link_TallyViewer   = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/TallyViewer.exe"
$Link_Agent         = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/agent.exe"

# --- CONFIGURATION END ---

$TempDir = "$env:TEMP\GFXSetup"
if (Test-Path $TempDir) { Remove-Item -Path $TempDir -Recurse -Force }
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
Write-Host "--- Starting Cloud Setup ---" -ForegroundColor Cyan

# Function to download
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

# Download XML Config from the Raw Code Repo
$inputDirectorConfig = Download-File "$RepoRawUrl/InputDirectorConfig.xml" "InputDirectorConfig.xml"

# --- SYSTEM CONFIGURATION ---

# 1. Computer Name
if ((Get-ComputerInfo).WindowsProductName -notlike "*GFX1*") {
    Rename-Computer -NewName "GFX1" -Force
    Write-Host "Renaming Computer to GFX1..." -ForegroundColor Yellow
}

# 2. SMB & Services
Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
Set-Service -Name "LanmanServer" -StartupType Automatic; Start-Service "LanmanServer"
Set-Service -Name "fdPHost" -StartupType Automatic; Start-Service "fdPHost"

# 3. Registry: NTLM & Guest Access
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "LMCompatibilityLevel" -Value 1
$regPathPol = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"
$regPathSvc = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
if (!(Test-Path $regPathPol)) { New-Item -Path $regPathPol -Force | Out-Null }
Set-ItemProperty -Path $regPathPol -Name "AllowInsecureGuestAuth" -Value 1 -Type DWord
Set-ItemProperty -Path $regPathSvc -Name "AllowInsecureGuestAuth" -Value 1 -Type DWord

# 4. Refresh Network
cmd /c "sc stop lanmanworkstation > nul 2>&1"
cmd /c "sc start lanmanworkstation > nul 2>&1"

# 5. Create Desktop Share
$sharedFolderPath = "$env:USERPROFILE\Desktop\GFX1"
New-Item -ItemType Directory -Path $sharedFolderPath -Force | Out-Null
Set-NetFirewallRule -DisplayGroup "Network Discovery" -Enabled True
Set-NetFirewallRule -DisplayGroup "File and Printer Sharing" -Enabled True

if (!(Get-SmbShare -Name "GFX1" -ErrorAction SilentlyContinue)) {
    New-SmbShare -Name "GFX1" -Path $sharedFolderPath -FullAccess "Everyone"
    Write-Host "Share GFX1 Created." -ForegroundColor Green
}

# 6. Windows 11 UI Fixes
$explorerAdvPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
if (Test-Path $explorerAdvPath) { Set-ItemProperty -Path $explorerAdvPath -Name "TaskbarAl" -Value 0 -Type DWord }
$clsidPath = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
if (!(Test-Path $clsidPath)) { New-Item -Path $clsidPath -Force | Out-Null }
Set-Item -Path $clsidPath -Value ""

# 7. Display Settings
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "LogPixels" -Value 96

# --- INSTALLATION ---

# Install Input Director
if ($inputDirectorInstaller -and (Test-Path $inputDirectorInstaller)) {
    Write-Host "Installing Input Director..." -ForegroundColor Yellow
    Start-Process -FilePath $inputDirectorInstaller -ArgumentList "/S" -Wait
    
    # Import Config
    if ($inputDirectorConfig -and (Test-Path $inputDirectorConfig)) {
        $idCmdPath = if ([Environment]::Is64BitOperatingSystem) { "C:\Program Files\Input Director\IDCmd.exe" } else { "C:\Program Files (x86)\Input Director\IDCmd.exe" }
        if (Test-Path $idCmdPath) {
            Start-Process -FilePath $idCmdPath -ArgumentList "-importconfig:`"$inputDirectorConfig`"" -Wait
            Write-Host "Input Director Config Imported." -ForegroundColor Green
        }
    }
}

# Copy TallyViewer
if ($tallyViewerExe -and (Test-Path $tallyViewerExe)) {
    Copy-Item -Path $tallyViewerExe -Destination "$env:USERPROFILE\Desktop\TallyViewer.exe" -Force
    Write-Host "TallyViewer copied to Desktop." -ForegroundColor Green
}

# Autostart Agent
if ($agentExe -and (Test-Path $agentExe)) {
    Copy-Item -Path $agentExe -Destination "$([System.Environment]::GetFolderPath('CommonStartup'))\agent.exe" -Force
    Write-Host "Agent.exe set to autostart." -ForegroundColor Green
}

# Cleanup
Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Setup Complete. Restarting..." -ForegroundColor Yellow
Restart-Computer -Force