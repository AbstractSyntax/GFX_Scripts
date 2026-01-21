<#
.SYNOPSIS
    Full Automated Deployment for OSCPoint PowerPoint VSTO Add-in.
    Version: 24.0
    Logic: Bypasses ClickOnce prompts via Certificate Injection and Manual Inclusion Whitelisting.
#>

# --- 1. CONFIGURATION ---
$OSCTargetIP    = "192.168.8.142"
$RemotePort     = 9000
$LocalPort      = 8000
$oscDir         = "C:\OSCPoint"
$vstoName       = "OSCPoint add-in.vsto"
$TempDir        = "C:\GFX_Temp_Setup"

# Download Links
$Link_OSCPoint      = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/oscpoint-2.2.0.0.zip"
$Link_InputDirector = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/InputDirector.v2.3.build173.Domain.Setup.exe1"
$Link_TallyViewer   = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/TallyViewer.exe1"
$Link_Agent         = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/agent.exe1"

Write-Host "--- Starting OSCPoint Deployment v24 ---" -ForegroundColor Cyan

# --- 2. PREPARATION ---
Write-Host "[Task] Closing PowerPoint and Cleaning Temp..." -ForegroundColor Gray
Get-Process "powerpnt" -ErrorAction SilentlyContinue | Stop-Process -Force
if (Test-Path $TempDir) { Remove-Item $TempDir -Recurse -Force }
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

function Download-File {
    param ($Url, $FileName)
    $Dest = Join-Path $TempDir $FileName
    try {
        Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing -TimeoutSec 30
        if (Test-Path $Dest) { return $Dest }
    } catch { 
        Write-Warning "Failed to download $FileName"
        return $null 
    }
}

# --- 3. DOWNLOAD ASSETS ---
$oscZip      = Download-File $Link_OSCPoint "OSCPoint.zip"
$idInstaller = Download-File $Link_InputDirector "IDSetup.exe"
$tallyExe    = Download-File $Link_TallyViewer "TallyViewer.exe"
$agentExe    = Download-File $Link_Agent "agent.exe"

# --- 4. OSCPOINT VSTO STAGE ---
if ($oscZip) {
    Write-Host "[Task] Extracting and Unblocking OSCPoint..." -ForegroundColor Gray
    if (Test-Path $oscDir) { Remove-Item $oscDir -Recurse -Force }
    New-Item -ItemType Directory -Path $oscDir -Force | Out-Null
    Expand-Archive -Path $oscZip -DestinationPath $oscDir -Force
    Get-ChildItem -Path $oscDir -Recurse | Unblock-File
    
    $vstoFile = Get-ChildItem -Path $oscDir -Filter "$vstoName" -Recurse | Select-Object -First 1

    if ($vstoFile) {
        $vstoPath = $vstoFile.FullName
        # URI Encode the path (replace spaces with %20 for the Inclusion List)
        $vstoUri = "file:///$($vstoPath.Replace('\','/').Replace(' ', '%20'))"

        # A. Certificate Trust Injection
        Write-Host "[Security] Injecting Certificate Trust..." -ForegroundColor Gray
        $sig = Get-AuthenticodeSignature $vstoPath
        $cert = $sig.SignerCertificate

        if ($null -ne $cert) {
            try {
                foreach ($storeName in @("Root", "TrustedPublisher")) {
                    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, "LocalMachine")
                    $store.Open("ReadWrite")
                    $store.Add($cert)
                    $store.Close()
                }
                
                # B. Manual Inclusion List (Whitelisting the RSA Key)
                $pubKey = [System.Convert]::ToBase64String($cert.GetPublicKey())
                $rsaKey = "<RSAKeyValue><Modulus>$pubKey</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>"
                
                # Generate a unique key for the inclusion list
                $incPath = "HKCU:\Software\Microsoft\VSTO\Security\Inclusion\{78145241-1245-4125-8547-124578521456}"
                if (!(Test-Path $incPath)) { New-Item $incPath -Force | Out-Null }
                Set-ItemProperty $incPath -Name "Url" -Value $vstoUri
                Set-ItemProperty $incPath -Name "PublicKey" -Value $rsaKey
                Write-Host "Security: Success - Certificate and Inclusion List Whitelisted." -ForegroundColor Green
            } catch {
                Write-Warning "Security: Certificate found but injection failed. Manual trust may be required."
            }
        } else {
            Write-Warning "Security: VSTO is not signed. Skipping Certificate/Inclusion injection."
        }

        # C. Office Resiliency & Trusted Locations
        Write-Host "[Security] Cleaning Office Blacklists & Adding Trusted Location..." -ForegroundColor Gray
        foreach ($ver in @("14.0", "15.0", "16.0")) {
            $basePath = "HKCU:\Software\Microsoft\Office\$ver\PowerPoint"
            
            # Wipe Resiliency (Forces Office to re-examine the add-in)
            $resilPath = "$basePath\Resiliency"
            if (Test-Path $resilPath) { 
                Remove-Item "$resilPath\DisabledItems" -Recurse -ErrorAction SilentlyContinue
                Remove-Item "$resilPath\CrashingAddins" -Recurse -ErrorAction SilentlyContinue
            }
            
            # Add to Trusted Locations
            $trustPath = "$basePath\Security\Trusted Locations\OSCPoint"
            if (!(Test-Path $trustPath)) { New-Item $trustPath -Force | Out-Null }
            Set-ItemProperty $trustPath -Name "Path" -Value $oscDir
            Set-ItemProperty $trustPath -Name "AllowSubfolders" -Value 1 -Type DWord
        }

        # D. Add-in Registration (|vstolocal ensures local execution)
        Write-Host "[Registry] Registering Manifest..." -ForegroundColor Gray
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
                Set-ItemProperty $rp -Name "FriendlyName" -Value "OSCPoint Add-in"
                Set-ItemProperty $rp -Name "Description" -Value "OSC Control for PowerPoint"
            }
        }

        # E. Application Configuration
        Write-Host "[Config] Injecting OSC Settings..." -ForegroundColor Gray
        $oscConfig = "HKCU:\Software\Zinc Event Production Ltd\OSCPoint"
        if (!(Test-Path $oscConfig)) { New-Item $oscConfig -Force | Out-Null }
        Set-ItemProperty $oscConfig -Name "RemoteHost" -Value $OSCTargetIP
        Set-ItemProperty $oscConfig -Name "RemotePort" -Value $RemotePort
        Set-ItemProperty $oscConfig -Name "LocalPort" -Value $LocalPort
        Set-ItemProperty $oscConfig -Name "FeedbackEnabled" -Value "True"
    }
}

# --- 5. FIREWALL RULE ---
Write-Host "[Firewall] Opening UDP Port $LocalPort for OSC traffic..." -ForegroundColor Gray
Remove-NetFirewallRule -DisplayName "OSCPoint Inbound" -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "OSCPoint Inbound" -Direction Inbound -Action Allow -Protocol UDP -LocalPort $LocalPort | Out-Null

# --- 6. ADDITIONAL APPLICATIONS ---
Write-Host "[Task] Installing Support Applications..." -ForegroundColor Gray
if ($agentExe) {
    $dest = "$([System.Environment]::GetFolderPath('CommonStartup'))\agent.exe"
    Copy-Item $agentExe $dest -Force -ErrorAction SilentlyContinue
    Unblock-File $dest -ErrorAction SilentlyContinue
}
if ($tallyExe) {
    Copy-Item $tallyExe "$env:USERPROFILE\Desktop\TallyViewer.exe" -Force
}
if ($idInstaller) {
    # Install InputDirector Silently
    Start-Process $idInstaller -ArgumentList "/S" -Wait
}

# --- 7. CLEANUP & FINALIZE ---
Write-Host "[Task] Final Cleanup..." -ForegroundColor Gray
Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "----------------------------------------------" -ForegroundColor Cyan
Write-Host "SETUP COMPLETE: OSCPoint is ready for use." -ForegroundColor Green
Write-Host "PowerPoint Registry Whitelisted." -ForegroundColor Green
Write-Host "Firewall Ports Opened." -ForegroundColor Green
Write-Host "----------------------------------------------" -ForegroundColor Cyan

Start-Sleep -Seconds 3
