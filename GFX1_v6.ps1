# v18 Final Hybrid - Fixed Filename with Spaces
# Run as Administrator

# --- CONFIGURATION ---
$RepoRawUrl = "https://raw.githubusercontent.com/AbstractSyntax/GFX_Scripts/main"
$Link_OSCPoint      = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/oscpoint-2.2.0.0.zip"
$Link_InputDirector = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/InputDirector.v2.3.build173.Domain.Setup.exe1"
$Link_TallyViewer   = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/TallyViewer.exe1"
$Link_Agent         = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/agent.exe1"

$OSCTargetIP = "192.168.8.142"
$TempDir = "C:\GFX_Temp_Setup"
$oscDir = "C:\OSCPoint"
$vstoName = "OSCPoint add-in.vsto" # Updated filename with space

# --- PREP ---
if (Test-Path $TempDir) { Remove-Item $TempDir -Recurse -Force }
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

function Download-File {
    param ($Url, $FileName)
    $Dest = Join-Path $TempDir $FileName
    try {
        Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing -MaximumRedirection 5
        if (Test-Path $Dest) { return $Dest }
    } catch { Write-Host "Download Failed: $FileName" -ForegroundColor Red }
    return $null
}

Write-Host "--- Starting Setup v18 ---" -ForegroundColor Cyan
Get-Process "powerpnt" -ErrorAction SilentlyContinue | Stop-Process -Force

# Downloads
$oscZip = Download-File $Link_OSCPoint "OSCPoint.zip"
$idInstaller = Download-File $Link_InputDirector "IDSetup.exe"
$tallyExe = Download-File $Link_TallyViewer "TallyViewer.exe"
$agentExe = Download-File $Link_Agent "agent.exe"

# --- OSCPOINT STAGE ---
Write-Host "`n[OSCPoint Stage]" -ForegroundColor Cyan
if ($oscZip) {
    if (Test-Path $oscDir) { Remove-Item $oscDir -Recurse -Force }
    New-Item -ItemType Directory -Path $oscDir -Force | Out-Null
    
    Write-Host "Extracting to $oscDir..." -ForegroundColor Gray
    Expand-Archive -Path $oscZip -DestinationPath $oscDir -Force
    
    # Locate the VSTO file (Searching for the specific name with the space)
    $vstoFile = Get-ChildItem -Path $oscDir -Filter "$vstoName" -Recurse | Select-Object -First 1

    if ($null -eq $vstoFile) {
        Write-Host "ERROR: Could not find '$vstoName' in $oscDir" -ForegroundColor Red
        # Fallback: Look for any VSTO file if the name above is slightly different
        $vstoFile = Get-ChildItem -Path $oscDir -Filter "*.vsto" -Recurse | Select-Object -First 1
    }

    if ($vstoFile) {
        $vstoPath = $vstoFile.FullName
        Write-Host "SUCCESS: Found VSTO at $vstoPath" -ForegroundColor Green

        # 1. UNBLOCK
        Get-ChildItem -Path $oscDir -Recurse | Unblock-File

        # 2. TRUST CERTIFICATE
        $cert = (Get-AuthenticodeSignature $vstoPath).SignerCertificate
        if ($cert) {
            foreach ($s in @("Root", "TrustedPublisher")) {
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($s, "LocalMachine")
                $store.Open("ReadWrite"); $store.Add($cert); $store.Close()
            }
            Write-Host "Certificate Trusted." -ForegroundColor Gray
        }

        # 3. RUN SILENT INSTALLER
        Write-Host "Running VSTO Installer..." -ForegroundColor Gray
        $vstoInstaller = "$env:CommonProgramFiles\microsoft shared\VSTO\10.0\VSTOInstaller.exe"
        if (Test-Path $vstoInstaller) {
            Start-Process $vstoInstaller -ArgumentList "/i `"$vstoPath`" /s" -Wait
        }

        # 4. FORCE REGISTRY REGISTRATION
        # This points PowerPoint directly to the extracted file
        $manifestValue = "file:///$($vstoPath.Replace('\','/'))|vstolocal"
        $regPaths = @(
            "HKCU:\Software\Microsoft\Office\PowerPoint\Addins\OSCPoint",
            "HKLM:\SOFTWARE\Microsoft\Office\PowerPoint\Addins\OSCPoint",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\PowerPoint\Addins\OSCPoint"
        )
        foreach ($rp in $regPaths) {
            if (!(Test-Path $rp)) { New-Item $rp -Force -ErrorAction SilentlyContinue | Out-Null }
            if (Test-Path $rp) {
                Set-ItemProperty $rp -Name "Manifest" -Value $manifestValue
                Set-ItemProperty $rp -Name "LoadBehavior" -Value 3 -Type DWord
                Set-ItemProperty $rp -Name "FriendlyName" -Value "OSCPoint"
            }
        }

        # 5. OSC FEEDBACK CONFIG (Point to 192.168.8.142)
        $oscConfig = "HKCU:\Software\Zinc Event Production Ltd\OSCPoint"
        if (!(Test-Path $oscConfig)) { New-Item $oscConfig -Force | Out-Null }
        Set-ItemProperty $oscConfig -Name "RemoteHost" -Value $OSCTargetIP
        Set-ItemProperty $oscConfig -Name "FeedbackEnabled" -Value "True"
        Set-ItemProperty $oscConfig -Name "RemotePort" -Value 9000
        Set-ItemProperty $oscConfig -Name "LocalPort" -Value 8000
        
        # 6. FIREWALL
        $ppPath = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\powerpnt.exe" -ErrorAction SilentlyContinue)."(default)"
        if ($ppPath) {
            New-NetFirewallRule -DisplayName "OSCPoint (PowerPoint)" -Direction Inbound -Program $ppPath -Action Allow -Protocol UDP -LocalPort 8000 -Profile Any -ErrorAction SilentlyContinue
        }
        Write-Host "OSCPoint Deployment Finished." -ForegroundColor Green
    } else {
        Write-Host "CRITICAL ERROR: Could not find any .vsto file!" -ForegroundColor Red
    }
}

# --- OTHER APPS ---
Write-Host "`n[Other Apps Stage]" -ForegroundColor Cyan

if ($agentExe) {
    $dest = "$([System.Environment]::GetFolderPath('CommonStartup'))\agent.exe"
    Copy-Item $agentExe $dest -Force -ErrorAction SilentlyContinue
    Unblock-File $dest -ErrorAction SilentlyContinue
}

if ($tallyExe) {
    Copy-Item $tallyExe "$env:USERPROFILE\Desktop\TallyViewer.exe" -Force
}

if ($idInstaller) {
    Start-Process $idInstaller -ArgumentList "/S" -Wait
}

# Cleanup and Restart
Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "`nSetup Finished. Restarting..." -ForegroundColor Yellow
Start-Sleep -Seconds 5
#Restart-Computer -Force
