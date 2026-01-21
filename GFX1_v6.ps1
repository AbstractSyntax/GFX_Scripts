# v20 Final Hybrid - Direct Injection (Zero Installer Prompts)
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

Write-Host "--- Starting Setup v20 ---" -ForegroundColor Cyan

# Downloads
$oscZip = Download-File $Link_OSCPoint "OSCPoint.zip"
$idInstaller = Download-File $Link_InputDirector "IDSetup.exe"
$tallyExe = Download-File $Link_TallyViewer "TallyViewer.exe"
$agentExe = Download-File $Link_Agent "agent.exe"

# --- OSCPOINT STAGE ---
if ($oscZip) {
    Write-Host "[OSCPoint Stage] Direct Injecting Add-in..." -ForegroundColor Cyan
    if (Test-Path $oscDir) { Remove-Item $oscDir -Recurse -Force }
    New-Item -ItemType Directory -Path $oscDir -Force | Out-Null
    Expand-Archive -Path $oscZip -DestinationPath $oscDir -Force
    Get-ChildItem -Path $oscDir -Recurse | Unblock-File
    
    $vstoFile = Get-ChildItem -Path $oscDir -Filter "$vstoName" -Recurse | Select-Object -First 1

    if ($vstoFile) {
        $vstoPath = $vstoFile.FullName
        # Manifest URL for Registry
        $manifestUrl = "file:///$($vstoPath.Replace('\','/'))"
        
        # 1. TRUST CERTIFICATE 
        $cert = (Get-AuthenticodeSignature $vstoPath).SignerCertificate
        if ($cert) {
            foreach ($s in @("Root", "TrustedPublisher")) {
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($s, "LocalMachine")
                $store.Open("ReadWrite"); $store.Add($cert); $store.Close()
            }

            # 2. INJECT INTO VSTO INCLUSION LIST
            # This is the "Secret Sauce" that bypasses the prompt you saw.
            Write-Host "Bypassing Security Prompts..." -ForegroundColor Gray
            $pubKey = [System.Convert]::ToBase64String($cert.GetPublicKey())
            $rsaKey = "<RSAKeyValue><Modulus>$pubKey</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>"
            $inclusionPath = "HKCU:\Software\Microsoft\VSTO\Security\Inclusion\{12457852-1452-4852-8547-124578521456}" # Constant GUID
            if (!(Test-Path $inclusionPath)) { New-Item $inclusionPath -Force | Out-Null }
            Set-ItemProperty $inclusionPath -Name "Url" -Value "$manifestUrl"
            Set-ItemProperty $inclusionPath -Name "PublicKey" -Value $rsaKey
        }

        # 3. REGISTER ADD-IN MANUALLY (Skipping setup.exe to avoid prompts)
        Write-Host "Registering Add-in for PowerPoint..." -ForegroundColor Gray
        $regPaths = @(
            "HKCU:\Software\Microsoft\Office\PowerPoint\Addins\OSCPoint",
            "HKLM:\SOFTWARE\Microsoft\Office\PowerPoint\Addins\OSCPoint"
        )
        foreach ($rp in $regPaths) {
            if (!(Test-Path $rp)) { New-Item $rp -Force | Out-Null }
            Set-ItemProperty $rp -Name "Manifest" -Value "$($manifestUrl)|vstolocal"
            Set-ItemProperty $rp -Name "LoadBehavior" -Value 3 -Type DWord
            Set-ItemProperty $rp -Name "Description" -Value "OSC Feedback for PowerPoint"
            Set-ItemProperty $rp -Name "FriendlyName" -Value "OSCPoint"
        }

        # 4. CONFIGURE OSC FEEDBACK (IP & Toggle)
        Write-Host "Configuring Feedback to 192.168.8.142..." -ForegroundColor Gray
        $oscConfig = "HKCU:\Software\Zinc Event Production Ltd\OSCPoint"
        if (!(Test-Path $oscConfig)) { New-Item $oscConfig -Force | Out-Null }
        Set-ItemProperty $oscConfig -Name "RemoteHost" -Value $OSCTargetIP
        Set-ItemProperty $oscConfig -Name "FeedbackEnabled" -Value "True"
        Set-ItemProperty $oscConfig -Name "RemotePort" -Value 9000
        Set-ItemProperty $oscConfig -Name "LocalPort" -Value 8000
        
        Write-Host "OSCPoint Successfully Injected." -ForegroundColor Green
    }
}

# --- OTHER APPS ---
if ($agentExe) {
    $dest = "$([System.Environment]::GetFolderPath('CommonStartup'))\agent.exe"
    Copy-Item $agentExe $dest -Force -ErrorAction SilentlyContinue
}

if ($tallyExe) {
    Copy-Item $tallyExe "$env:USERPROFILE\Desktop\TallyViewer.exe" -Force
}

if ($idInstaller) {
    Write-Host "Installing Input Director..." -ForegroundColor Yellow
    Start-Process $idInstaller -ArgumentList "/S" -Wait
}

# Cleanup and Restart
Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "Setup Complete. Restarting..." -ForegroundColor Yellow
Start-Sleep -Seconds 5
#Restart-Computer -Force
