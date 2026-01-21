# v12 Final Hybrid - Fixed Services & Registry
# Run as Administrator

# --- CONFIGURATION START ---
$RepoRawUrl = "https://raw.githubusercontent.com/AbstractSyntax/GFX_Scripts/main"
$Link_InputDirector = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/InputDirector.v2.3.build173.Domain.Setup.exe1"
$Link_TallyViewer   = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/TallyViewer.exe1"
$Link_Agent         = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/agent.exe1"
$Link_OSCPoint      = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/oscpoint-2.2.0.0.zip"

$OSCTargetIP = "192.168.8.142"
# --- CONFIGURATION END ---

$TempDir = "$env:TEMP\GFXSetup"
if (Test-Path $TempDir) { Remove-Item -Path $TempDir -Recurse -Force }
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

Write-Host "--- Starting GFX Cloud Setup v12 ---" -ForegroundColor Cyan

function Download-File {
    param ($Url, $FileName)
    $Dest = "$TempDir\$FileName"
    try {
        Write-Host "DEBUG: Attempting to download $FileName from $Url" -ForegroundColor Gray
        # Using -MaximumRedirection to ensure we follow GitHub's download paths
        Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing -MaximumRedirection 5
        
        if (Test-Path $Dest) {
            $fSize = (Get-Item $Dest).Length / 1KB
            Write-Host "DEBUG: $FileName downloaded. Size: {0:N2} KB" -f $fSize -ForegroundColor Green
            return $Dest
        } else {
            Write-Host "DEBUG: $FileName download failed - File not found on disk." -ForegroundColor Red
            return $null
        }
    } catch {
        Write-Host "DEBUG: Exception downloading $FileName : $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# --- Download Phase ---
$inputDirectorInstaller = Download-File $Link_InputDirector "InputDirectorSetup.exe"
$tallyViewerExe         = Download-File $Link_TallyViewer   "TallyViewer.exe"
$agentExe               = Download-File $Link_Agent         "agent.exe"
$oscZip                 = Download-File $Link_OSCPoint      "OSCPoint.zip"
$inputDirectorConfig    = Download-File "$RepoRawUrl/InputDirectorConfig.xml" "InputDirectorConfig.xml"

# --- SYSTEM CONFIGURATION ---

# Fix for the Set-Service error: Processing names one by one
Write-Host "Configuring System Services..." -ForegroundColor Gray
$Services = @("LanmanServer", "fdPHost")
foreach ($Svc in $Services) {
    Set-Service -Name $Svc -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name $Svc -ErrorAction SilentlyContinue
}

if ((Get-ComputerInfo).WindowsProductName -notlike "*GFX1*") { Rename-Computer -NewName "GFX1" -Force }

Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
$regPathPol = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"
if (!(Test-Path $regPathPol)) { New-Item -Path $regPathPol -Force | Out-Null }
Set-ItemProperty -Path $regPathPol -Name "AllowInsecureGuestAuth" -Value 1 -Type DWord

$sharedFolderPath = "$env:USERPROFILE\Desktop\GFX1"
if (!(Test-Path $sharedFolderPath)) { New-Item -ItemType Directory -Path $sharedFolderPath -Force | Out-Null }
if (!(Get-SmbShare -Name "GFX1" -ErrorAction SilentlyContinue)) { New-SmbShare -Name "GFX1" -Path $sharedFolderPath -FullAccess "Everyone" }

# --- OSCPOINT INSTALLATION ---
if ($oscZip -and (Test-Path $oscZip)) {
    Write-Host "Installing OSCPoint..." -ForegroundColor Yellow
    
    $oscDir = "C:\OSCPoint"
    if (Test-Path $oscDir) { Remove-Item $oscDir -Recurse -Force }
    New-Item -ItemType Directory -Path $oscDir -Force | Out-Null
    
    Expand-Archive -Path $oscZip -DestinationPath $oscDir -Force
    Get-ChildItem -Path $oscDir -Recurse | Unblock-File
    
    $vstoFile = Get-ChildItem -Path $oscDir -Filter "OSCPoint.vsto" -Recurse | Select-Object -First 1

    if ($vstoFile) {
        # Trust Certificate (Root and TrustedPublisher)
        $cert = (Get-AuthenticodeSignature $vstoFile.FullName).SignerCertificate
        if ($cert) {
            foreach ($storeName in @("Root", "TrustedPublisher")) {
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, "LocalMachine")
                $store.Open("ReadWrite")
                $store.Add($cert)
                $store.Close()
            }
        }

        # Run Silent Installer
        $vstoInstaller = "$env:CommonProgramFiles\microsoft shared\VSTO\10.0\VSTOInstaller.exe"
        if (Test-Path $vstoInstaller) {
            Start-Process $vstoInstaller -ArgumentList "/i `"$($vstoFile.FullName)`" /s" -Wait
        }

        # MACHINE-WIDE REGISTRATION
        # We register in 3 places to ensure 32-bit and 64-bit Office both see it
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

        # OSC FEEDBACK CONFIGURATION
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
        Write-Host "OSCPoint successfully deployed." -ForegroundColor Green
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
