# v22 Final Hybrid - Side-Loading & URI Encoding
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
$vstoName = "OSCPoint add-in.vsto" # Space is the key here

# --- PREP ---
if (Test-Path $TempDir) { Remove-Item $TempDir -Recurse -Force }
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
Get-Process "powerpnt" -ErrorAction SilentlyContinue | Stop-Process -Force

function Download-File {
    param ($Url, $FileName)
    $Dest = Join-Path $TempDir $FileName
    try {
        Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing -MaximumRedirection 5
        if (Test-Path $Dest) { return $Dest }
    } catch { return $null }
}

Write-Host "--- Starting Setup v22 ---" -ForegroundColor Cyan

# Downloads
$oscZip = Download-File $Link_OSCPoint "OSCPoint.zip"
$idInstaller = Download-File $Link_InputDirector "IDSetup.exe"
$tallyExe = Download-File $Link_TallyViewer "TallyViewer.exe"
$agentExe = Download-File $Link_Agent "agent.exe"

# --- OSCPOINT SIDE-LOADING ---
Write-Host "`n[OSCPoint Stage]" -ForegroundColor Cyan
if ($oscZip) {
    if (Test-Path $oscDir) { Remove-Item $oscDir -Recurse -Force }
    New-Item -ItemType Directory -Path $oscDir -Force | Out-Null
    
    Write-Host "Extracting to $oscDir..." -ForegroundColor Gray
    Expand-Archive -Path $oscZip -DestinationPath $oscDir -Force
    
    # Deep search for the file with the space
    $vstoFile = Get-ChildItem -Path $oscDir -Filter "$vstoName" -Recurse | Select-Object -First 1

    if ($vstoFile) {
        $vstoPath = $vstoFile.FullName
        # URI Encoding: Spaces MUST be %20 for Office to read the manifest URL correctly
        $encodedPath = "file:///$($vstoPath.Replace('\','/').Replace(' ','%20'))"
        Write-Host "Registering Manifest: $encodedPath" -ForegroundColor Gray

        # 1. UNBLOCK
        Get-ChildItem -Path $oscDir -Recurse | Unblock-File

        # 2. TRUST CERTIFICATE
        $cert = (Get-AuthenticodeSignature $vstoPath).SignerCertificate
        if ($cert) {
            foreach ($s in @("Root", "TrustedPublisher")) {
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($s, "LocalMachine")
                $store.Open("ReadWrite"); $store.Add($cert); $store.Close()
            }
            
            # 3. MANUAL INCLUSION LIST (The "Prompt Killer")
            # This bypasses the "Publisher has been verified" prompt
            $pubKey = [System.Convert]::ToBase64String($cert.GetPublicKey())
            $rsaKey = "<RSAKeyValue><Modulus>$pubKey</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>"
            $inclusionPath = "HKCU:\Software\Microsoft\VSTO\Security\Inclusion\12457852-1452-4852-8547-124578521456" 
            if (!(Test-Path $inclusionPath)) { New-Item $inclusionPath -Force | Out-Null }
            Set-ItemProperty $inclusionPath -Name "Url" -Value $encodedPath
            Set-ItemProperty $inclusionPath -Name "PublicKey" -Value $rsaKey
            Write-Host "Security Inclusion List Updated." -ForegroundColor Gray
        }

        # 4. FORCE REGISTRY REGISTRATION (Machine & User)
        $regPaths = @(
            "HKCU:\Software\Microsoft\Office\PowerPoint\Addins\OSCPoint",
            "HKLM:\SOFTWARE\Microsoft\Office\PowerPoint\Addins\OSCPoint",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\PowerPoint\Addins\OSCPoint"
        )
        foreach ($rp in $regPaths) {
            if (!(Test-Path $rp)) { New-Item $rp -Force -ErrorAction SilentlyContinue | Out-Null }
            if (Test-Path $rp) {
                # We use the encoded path with |vstolocal
                Set-ItemProperty $rp -Name "Manifest" -Value "$($encodedPath)|vstolocal"
                Set-ItemProperty $rp -Name "LoadBehavior" -Value 3 -Type DWord
                Set-ItemProperty $rp -Name "FriendlyName" -Value "OSCPoint"
                Set-ItemProperty $rp -Name "Description" -Value "OSC Feedback"
            }
        }

        # 5. CONFIGURE OSC SETTINGS (The Feedback IP)
        $oscConfig = "HKCU:\Software\Zinc Event Production Ltd\OSCPoint"
        if (!(Test-Path $oscConfig)) { New-Item $oscConfig -Force | Out-Null }
        Set-ItemProperty $oscConfig -Name "RemoteHost" -Value $OSCTargetIP
        Set-ItemProperty $oscConfig -Name "FeedbackEnabled" -Value "True"
        Set-ItemProperty $oscConfig -Name "RemotePort" -Value 9000
        Set-ItemProperty $oscConfig -Name "LocalPort" -Value 8000
        
        Write-Host "OSCPoint Successfully Side-Loaded." -ForegroundColor Green
    }
}

# --- OTHER APPS ---
Write-Host "`n[Other Apps Stage]" -ForegroundColor Cyan

if ($agentExe) {
    $dest = "$([System.Environment]::GetFolderPath('CommonStartup'))\agent.exe"
    Copy-Item $agentExe $dest -Force -ErrorAction SilentlyContinue
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
