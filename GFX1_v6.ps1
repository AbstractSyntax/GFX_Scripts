# v16 Final Hybrid - Office Security Bypass Edition
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

# --- PREP ---
if (Test-Path $TempDir) { Remove-Item $TempDir -Recurse -Force }
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

function Download-File {
    param ($Url, $FileName)
    $Dest = Join-Path $TempDir $FileName
    try {
        Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing -MaximumRedirection 5
        if (Test-Path $Dest) { return $Dest }
    } catch { Write-Host "Download Error: $FileName" -ForegroundColor Red }
    return $null
}

Write-Host "--- Starting Setup v16 ---" -ForegroundColor Cyan
Get-Process "powerpnt" -ErrorAction SilentlyContinue | Stop-Process -Force

# Downloads
$oscZip = Download-File $Link_OSCPoint "OSCPoint.zip"
$idInstaller = Download-File $Link_InputDirector "IDSetup.exe"
$tallyExe = Download-File $Link_TallyViewer "TallyViewer.exe"
$agentExe = Download-File $Link_Agent "agent.exe"

# --- OSCPOINT STAGE ---
if ($oscZip) {
    Write-Host "[OSCPoint Stage] Extracting and Registering..." -ForegroundColor Yellow
    if (Test-Path $oscDir) { Remove-Item $oscDir -Recurse -Force }
    New-Item -ItemType Directory -Path $oscDir -Force | Out-Null
    Expand-Archive -Path $oscZip -DestinationPath $oscDir -Force
    Get-ChildItem -Path $oscDir -Recurse | Unblock-File

    $vstoFile = Get-ChildItem -Path $oscDir -Filter "OSCPoint.vsto" -Recurse | Select-Object -First 1

    if ($vstoFile) {
        $vstoPath = $vstoFile.FullName
        Write-Host "Found VSTO: $vstoPath" -ForegroundColor Gray

        # 1. TRUST CERTIFICATE
        $cert = (Get-AuthenticodeSignature $vstoPath).SignerCertificate
        if ($cert) {
            foreach ($s in @("Root", "TrustedPublisher")) {
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($s, "LocalMachine")
                $store.Open("ReadWrite"); $store.Add($cert); $store.Close()
            }
        }

        # 2. ADD TO POWERPOINT TRUSTED LOCATIONS (Registry)
        # We target versions 14, 15, and 16 (covers Office 2010 through 365)
        foreach ($ver in @("14.0", "15.0", "16.0")) {
            $trustPath = "HKCU:\Software\Microsoft\Office\$ver\PowerPoint\Security\Trusted Locations\OSCPoint"
            if (!(Test-Path $trustPath)) { New-Item $trustPath -Force | Out-Null }
            Set-ItemProperty $trustPath -Name "Path" -Value $oscDir
            Set-ItemProperty $trustPath -Name "AllowSubfolders" -Value 1 -Type DWord
            Set-ItemProperty $trustPath -Name "Description" -Value "OSCPoint Setup"
        }

        # 3. ADD TO CLICKONCE INCLUSION LIST (Bypasses the "Are you sure?" prompt)
        $publicKey = [System.Convert]::ToBase64String($cert.GetPublicKey())
        $inclusionPath = "HKCU:\Software\Microsoft\VSTO\Security\Inclusion\OSCPoint" # Some versions use the RSA key here, we'll use a named key
        if (!(Test-Path $inclusionPath)) { New-Item $inclusionPath -Force | Out-Null }
        Set-ItemProperty $inclusionPath -Name "Url" -Value "file:///$($vstoPath.Replace('\','/'))"
        Set-ItemProperty $inclusionPath -Name "PublicKey" -Value "<RSAKeyValue><Modulus>$publicKey</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>"

        # 4. REGISTER ADD-IN FOR POWERPOINT
        # Using the file:/// format with |vstolocal is the most stable method
        $manifestPath = "file:///$($vstoPath.Replace('\','/'))|vstolocal"
        $regPaths = @(
            "HKCU:\Software\Microsoft\Office\PowerPoint\Addins\OSCPoint",
            "HKLM:\SOFTWARE\Microsoft\Office\PowerPoint\Addins\OSCPoint",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\PowerPoint\Addins\OSCPoint"
        )
        foreach ($rp in $regPaths) {
            if (!(Test-Path $rp)) { New-Item $rp -Force -ErrorAction SilentlyContinue | Out-Null }
            if (Test-Path $rp) {
                Set-ItemProperty $rp -Name "Manifest" -Value $manifestPath
                Set-ItemProperty $rp -Name "LoadBehavior" -Value 3 -Type DWord
                Set-ItemProperty $rp -Name "FriendlyName" -Value "OSCPoint"
                Set-ItemProperty $rp -Name "Description" -Value "OSC Feedback for PowerPoint"
            }
        }

        # 5. CONFIGURATION
        $oscConfig = "HKCU:\Software\Zinc Event Production Ltd\OSCPoint"
        if (!(Test-Path $oscConfig)) { New-Item $oscConfig -Force | Out-Null }
        Set-ItemProperty $oscConfig -Name "RemoteHost" -Value $OSCTargetIP
        Set-ItemProperty $oscConfig -Name "FeedbackEnabled" -Value "True"
        Set-ItemProperty $oscConfig -Name "RemotePort" -Value 9000
        Set-ItemProperty $oscConfig -Name "LocalPort" -Value 8000
        
        Write-Host "SUCCESS: OSCPoint security bypasses applied." -ForegroundColor Green
    }
}

# --- REMAINING APPS ---
Write-Host "[Other Apps Stage]" -ForegroundColor Cyan

# Agent
if ($agentExe) {
    $dest = "$([System.Environment]::GetFolderPath('CommonStartup'))\agent.exe"
    Copy-Item $agentExe $dest -Force -ErrorAction SilentlyContinue
    Unblock-File $dest -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName "GFX Agent" -Direction Inbound -Program $dest -Action Allow -Profile Any -ErrorAction SilentlyContinue
}

# Tally
if ($tallyExe) {
    Copy-Item $tallyExe "$env:USERPROFILE\Desktop\TallyViewer.exe" -Force
}

# Input Director
if ($idInstaller) {
    Start-Process $idInstaller -ArgumentList "/S" -Wait
}

# Final Clean and Restart
Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "Setup Complete. Restarting..." -ForegroundColor Yellow
Start-Sleep -Seconds 5
#Restart-Computer -Force
