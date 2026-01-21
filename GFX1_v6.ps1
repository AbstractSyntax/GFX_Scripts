# v23 Final Hybrid - Resetting Office Resiliency & Trusted Locations
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
$vstoName = "OSCPoint add-in.vsto"

# --- PREP ---
if (Test-Path $TempDir) { Remove-Item $TempDir -Recurse -Force }
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
Get-Process "powerpnt" -ErrorAction SilentlyContinue | Stop-Process -Force

function Download-File {
    param ($Url, $FileName)
    $Dest = Join-Path $TempDir $FileName
    try {
        Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing
        if (Test-Path $Dest) { return $Dest }
    } catch { return $null }
}

Write-Host "--- Starting Setup v23 ---" -ForegroundColor Cyan

# Downloads
$oscZip = Download-File $Link_OSCPoint "OSCPoint.zip"
$idInstaller = Download-File $Link_InputDirector "IDSetup.exe"
$tallyExe = Download-File $Link_TallyViewer "TallyViewer.exe"
$agentExe = Download-File $Link_Agent "agent.exe"

# --- OSCPOINT STAGE ---
if ($oscZip) {
    Write-Host "[OSCPoint Stage] Resetting and Registering..." -ForegroundColor Cyan
    if (Test-Path $oscDir) { Remove-Item $oscDir -Recurse -Force }
    New-Item -ItemType Directory -Path $oscDir -Force | Out-Null
    Expand-Archive -Path $oscZip -DestinationPath $oscDir -Force
    Get-ChildItem -Path $oscDir -Recurse | Unblock-File
    
    $vstoFile = Get-ChildItem -Path $oscDir -Filter "$vstoName" -Recurse | Select-Object -First 1

    if ($vstoFile) {
        $vstoPath = $vstoFile.FullName
        Write-Host "Found VSTO at: $vstoPath" -ForegroundColor Gray

        # 1. TRUST CERTIFICATE
        $cert = (Get-AuthenticodeSignature $vstoPath).SignerCertificate
        if ($cert) {
            foreach ($s in @("Root", "TrustedPublisher")) {
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($s, "LocalMachine")
                $store.Open("ReadWrite"); $store.Add($cert); $store.Close()
            }
        }

        # 2. CLEAR OFFICE "DISABLED" LIST (Resiliency)
        # This prevents Office from blocking the add-in due to previous "crashes"
        foreach ($ver in @("14.0", "15.0", "16.0")) {
            $resilPath = "HKCU:\Software\Microsoft\Office\$ver\PowerPoint\Resiliency"
            if (Test-Path $resilPath) { 
                Remove-Item "$resilPath\DisabledItems" -Recurse -ErrorAction SilentlyContinue
                Remove-Item "$resilPath\CrashingAddins" -Recurse -ErrorAction SilentlyContinue
            }
            # 3. ADD TO TRUSTED LOCATIONS
            $trustPath = "HKCU:\Software\Microsoft\Office\$ver\PowerPoint\Security\Trusted Locations\OSCPoint"
            if (!(Test-Path $trustPath)) { New-Item $trustPath -Force | Out-Null }
            Set-ItemProperty $trustPath -Name "Path" -Value $oscDir
            Set-ItemProperty $trustPath -Name "AllowSubfolders" -Value 1 -Type DWord
        }

        # 4. MANUAL INCLUSION LIST (Security Whitelist)
        $pubKey = [System.Convert]::ToBase64String($cert.GetPublicKey())
        $rsaKey = "<RSAKeyValue><Modulus>$pubKey</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>"
        $incPath = "HKCU:\Software\Microsoft\VSTO\Security\Inclusion\{78145241-1245-4125-8547-124578521456}"
        if (!(Test-Path $incPath)) { New-Item $incPath -Force | Out-Null }
        Set-ItemProperty $incPath -Name "Url" -Value "file:///$($vstoPath.Replace('\','/'))"
        Set-ItemProperty $incPath -Name "PublicKey" -Value $rsaKey

        # 5. REGISTER ADD-IN MANUALLY
        $regPaths = @(
            "HKCU:\Software\Microsoft\Office\PowerPoint\Addins\OSCPoint",
            "HKLM:\SOFTWARE\Microsoft\Office\PowerPoint\Addins\OSCPoint",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\PowerPoint\Addins\OSCPoint"
        )
        foreach ($rp in $regPaths) {
            if (!(Test-Path $rp)) { New-Item $rp -Force -ErrorAction SilentlyContinue | Out-Null }
            if (Test-Path $rp) {
                Set-ItemProperty $rp -Name "Manifest" -Value "$vstoPath|vstolocal"
                Set-ItemProperty $rp -Name "LoadBehavior" -Value 3 -Type DWord
                Set-ItemProperty $rp -Name "FriendlyName" -Value "OSCPoint"
            }
        }

        # 6. CONFIGURE OSC SETTINGS
        $oscConfig = "HKCU:\Software\Zinc Event Production Ltd\OSCPoint"
        if (!(Test-Path $oscConfig)) { New-Item $oscConfig -Force | Out-Null }
        Set-ItemProperty $oscConfig -Name "RemoteHost" -Value $OSCTargetIP
        Set-ItemProperty $oscConfig -Name "FeedbackEnabled" -Value "True"
        
        Write-Host "OSCPoint Registered and Whitelisted." -ForegroundColor Green
    }
}

# --- OTHER APPS ---
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
Write-Host "Setup Complete. Restarting..." -ForegroundColor Yellow
Start-Sleep -Seconds 5
#Restart-Computer -Force
