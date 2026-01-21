# v14 Final Hybrid - Syntax & Install Fix
# Run as Administrator

# --- CONFIGURATION START ---
$RepoRawUrl = "https://raw.githubusercontent.com/AbstractSyntax/GFX_Scripts/main"
$Link_OSCPoint      = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/oscpoint-2.2.0.0.zip"
$Link_InputDirector = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/InputDirector.v2.3.build173.Domain.Setup.exe1"
$Link_TallyViewer   = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/TallyViewer.exe1"
$Link_Agent         = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/agent.exe1"

$OSCTargetIP = "192.168.8.142"
# --- CONFIGURATION END ---

$TempDir = "$env:TEMP\GFXSetup"
if (Test-Path $TempDir) { Remove-Item -Path $TempDir -Recurse -Force }
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

Write-Host "--- Starting GFX Cloud Setup v14 ---" -ForegroundColor Cyan

# FIXED: Removed -f shorthand to prevent the color binding error
function Download-File {
    param ($Url, $FileName)
    $Dest = "$TempDir\$FileName"
    try {
        Write-Host "DEBUG: Downloading $FileName..." -ForegroundColor Gray
        Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing
        
        if (Test-Path $Dest) {
            $fSize = (Get-Item $Dest).Length / 1KB
            # We use a separate variable for the string to avoid the -f / -ForegroundColor conflict
            $StatusMessage = "DEBUG: $FileName downloaded. Size: {0:N2} KB" -f $fSize
            Write-Host $StatusMessage -ForegroundColor Green
            return $Dest
        } else {
            Write-Host "DEBUG: $FileName download failed!" -ForegroundColor Red
            return $null
        }
    } catch {
        Write-Host "DEBUG: Error downloading $FileName : $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# --- Download Phase ---
$oscZip                 = Download-File $Link_OSCPoint      "OSCPoint.zip"
$inputDirectorInstaller = Download-File $Link_InputDirector "InputDirectorSetup.exe"
$tallyViewerExe         = Download-File $Link_TallyViewer   "TallyViewer.exe"
$agentExe               = Download-File $Link_Agent         "agent.exe"
$inputDirectorConfig    = Download-File "$RepoRawUrl/InputDirectorConfig.xml" "InputDirectorConfig.xml"

# --- SYSTEM PREP ---
Write-Host "Ensuring PowerPoint is closed for installation..." -ForegroundColor Gray
Get-Process "powerpnt" -ErrorAction SilentlyContinue | Stop-Process -Force

Write-Host "Configuring System Services..." -ForegroundColor Gray
foreach ($Svc in @("LanmanServer", "fdPHost")) {
    Set-Service -Name $Svc -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name $Svc -ErrorAction SilentlyContinue
}

if ((Get-ComputerInfo).WindowsProductName -notlike "*GFX1*") { Rename-Computer -NewName "GFX1" -Force }

# --- OSCPOINT INSTALLATION ---
if ($oscZip -and (Test-Path $oscZip)) {
    Write-Host "--- OSCPoint Deployment ---" -ForegroundColor Cyan
    $oscDir = "C:\OSCPoint"
    if (Test-Path $oscDir) { Remove-Item $oscDir -Recurse -Force }
    New-Item -ItemType Directory -Path $oscDir -Force | Out-Null
    
    Expand-Archive -Path $oscZip -DestinationPath $oscDir -Force
    Get-ChildItem -Path $oscDir -Recurse | Unblock-File
    
    $vstoFile = Get-ChildItem -Path $oscDir -Filter "OSCPoint.vsto" -Recurse | Select-Object -First 1

    if ($vstoFile) {
        Write-Host "Trusting Certificate..." -ForegroundColor Gray
        $cert = (Get-AuthenticodeSignature $vstoFile.FullName).SignerCertificate
        if ($cert) {
            foreach ($storeName in @("Root", "TrustedPublisher")) {
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, "LocalMachine")
                $store.Open("ReadWrite"); $store.Add($cert); $store.Close()
            }
        }

        Write-Host "Running VSTO Installer..." -ForegroundColor Gray
        $vstoInstaller = "$env:CommonProgramFiles\microsoft shared\VSTO\10.0\VSTOInstaller.exe"
        if (Test-Path $vstoInstaller) {
            # Start and WAIT for completion
            $proc = Start-Process $vstoInstaller -ArgumentList "/i `"$($vstoFile.FullName)`" /s" -Wait -PassThru
            Write-Host "Installer finished with code: $($proc.ExitCode)" -ForegroundColor Gray
        }

        # REGISTRY OVERRIDE
        $regPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Office\PowerPoint\Addins\OSCPoint",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\PowerPoint\Addins\OSCPoint",
            "HKCU:\Software\Microsoft\Office\PowerPoint\Addins\OSCPoint"
        )
        foreach ($path in $regPaths) {
            if (!(Test-Path $path)) { New-Item -Path $path -Force -ErrorAction SilentlyContinue | Out-Null }
            if (Test-Path $path) {
                Set-ItemProperty -Path $path -Name "Description" -Value "OSCPoint"
                Set-ItemProperty -Path $path -Name "FriendlyName" -Value "OSCPoint"
                Set-ItemProperty -Path $path -Name "Manifest" -Value "$($vstoFile.FullName)|vstolocal"
                Set-ItemProperty -Path $path -Name "LoadBehavior" -Value 3 -Type DWord
            }
        }

        # CONFIGURE OSCPOINT SETTINGS
        $oscConfig = "HKCU:\Software\Zinc Event Production Ltd\OSCPoint"
        if (!(Test-Path $oscConfig)) { New-Item -Path $oscConfig -Force | Out-Null }
        Set-ItemProperty -Path $oscConfig -Name "RemoteHost" -Value $OSCTargetIP
        Set-ItemProperty -Path $oscConfig -Name "FeedbackEnabled" -Value "True"
        Set-ItemProperty -Path $oscConfig -Name "RemotePort" -Value 9000
        Set-ItemProperty -Path $oscConfig -Name "LocalPort" -Value 8000
        
        # FIREWALL
        $ppPath = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\powerpnt.exe" -ErrorAction SilentlyContinue)."(default)"
        if ($ppPath) {
            New-NetFirewallRule -DisplayName "OSCPoint (PowerPoint)" -Direction Inbound -Program $ppPath -Action Allow -Protocol UDP -LocalPort 8000 -Profile Any -ErrorAction SilentlyContinue
        }
        Write-Host "OSCPoint Setup Finished." -ForegroundColor Green
    }
}

# --- OTHER APPS ---
if ($inputDirectorInstaller -and (Test-Path $inputDirectorInstaller)) {
    Write-Host "Installing Input Director..." -ForegroundColor Yellow
    Start-Process -FilePath $inputDirectorInstaller -ArgumentList "/S" -Wait
    $idCmdPath = "C:\Program Files\Input Director\IDCmd.exe"
    if (Test-Path $idCmdPath -and (Test-Path $inputDirectorConfig)) {
        Start-Process -FilePath $idCmdPath -ArgumentList "-importconfig:`"$inputDirectorConfig`"" -Wait
    }
}

if ($agentExe -and (Test-Path $agentExe)) {
    $agentDest = "$([System.Environment]::GetFolderPath('CommonStartup'))\agent.exe"
    Copy-Item -Path $agentExe -Destination $agentDest -Force -ErrorAction SilentlyContinue
    Unblock-File -Path $agentDest -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName "GFX Agent" -Direction Inbound -Program $agentDest -Action Allow -Profile Any -ErrorAction SilentlyContinue
}

if ($tallyViewerExe -and (Test-Path $tallyViewerExe)) {
    Copy-Item -Path $tallyViewerExe -Destination "$env:USERPROFILE\Desktop\TallyViewer.exe" -Force
}

Read-Host -Prompt "Press Enter to continue"

# Cleanup and Restart
Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "Setup Finished. Restarting..." -ForegroundColor Yellow
#Restart-Computer -Force
