# v15 Final Hybrid - Deep Debugging Edition
# Run as Administrator

# --- CONFIGURATION ---
$RepoRawUrl = "https://raw.githubusercontent.com/AbstractSyntax/GFX_Scripts/main"
$Link_OSCPoint      = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/oscpoint-2.2.0.0.zip"
$Link_InputDirector = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/InputDirector.v2.3.build173.Domain.Setup.exe1"
$Link_TallyViewer   = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/TallyViewer.exe1"
$Link_Agent         = "https://github.com/AbstractSyntax/GFX_Scripts/releases/download/release/agent.exe1"

$OSCTargetIP = "192.168.8.142"
$TempDir = "C:\GFX_Temp_Setup" # Using a hard path instead of $env:TEMP for reliability

# --- PREP ---
if (Test-Path $TempDir) { Remove-Item $TempDir -Recurse -Force }
New-Item -ItemType Directory -Path $TempDir -Force

function Download-File {
    param ($Url, $FileName)
    $Dest = Join-Path $TempDir $FileName
    Write-Host "LOG: Attempting download of $FileName..." -ForegroundColor Gray
    try {
        Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing -MaximumRedirection 5
        if (Test-Path $Dest) {
            $Size = (Get-Item $Dest).Length / 1KB
            Write-Host "SUCCESS: $FileName downloaded ($([Math]::Round($Size,2)) KB)" -ForegroundColor Green
            return $Dest
        }
    } catch {
        Write-Host "ERROR: Failed to download $FileName. $($_.Exception.Message)" -ForegroundColor Red
    }
    return $null
}

# --- EXECUTION ---
Write-Host "--- Starting Setup v15 ---" -ForegroundColor Cyan

# Ensure PowerPoint is closed
Get-Process "powerpnt" -ErrorAction SilentlyContinue | Stop-Process -Force

# Downloads
$oscZip = Download-File $Link_OSCPoint "OSCPoint.zip"
$idInstaller = Download-File $Link_InputDirector "IDSetup.exe"
$tallyExe = Download-File $Link_TallyViewer "TallyViewer.exe"
$agentExe = Download-File $Link_Agent "agent.exe"

# --- OSCPOINT BLOCK (HEAVILY DEBUGGED) ---
Write-Host "`n[OSCPoint Stage]" -ForegroundColor Cyan
if ($null -ne $oscZip) {
    $oscDir = "C:\OSCPoint"
    Write-Host "LOG: Creating directory $oscDir..." -ForegroundColor Gray
    
    # Force create directory and verify
    if (Test-Path $oscDir) { Remove-Item $oscDir -Recurse -Force -ErrorAction SilentlyContinue }
    $folderObj = New-Item -ItemType Directory -Path $oscDir -Force
    
    if (Test-Path $oscDir) {
        Write-Host "LOG: Folder $oscDir created successfully." -ForegroundColor Green
    } else {
        Write-Host "CRITICAL ERROR: Failed to create C:\OSCPoint. Script cannot continue." -ForegroundColor Red
        return
    }

    Write-Host "LOG: Extracting ZIP..." -ForegroundColor Gray
    try {
        Expand-Archive -Path $oscZip -DestinationPath $oscDir -Force
        $files = Get-ChildItem -Path $oscDir -Recurse
        Write-Host "LOG: Extracted $($files.Count) files." -ForegroundColor Green
    } catch {
        Write-Host "ERROR: Extraction failed! ZIP might be corrupt. $($_.Exception.Message)" -ForegroundColor Red
    }

    # Find VSTO
    $vstoFile = Get-ChildItem -Path $oscDir -Filter "*.vsto" -Recurse | Select-Object -First 1
    if ($null -eq $vstoFile) {
        Write-Host "ERROR: Could not find OSCPoint.vsto in $oscDir" -ForegroundColor Red
        Write-Host "Folder Contents:" -ForegroundColor Gray
        Get-ChildItem -Path $oscDir -Recurse | Select-Object FullName
    } else {
        Write-Host "SUCCESS: Found VSTO at $($vstoFile.FullName)" -ForegroundColor Green
        
        # Trust Certificate
        Write-Host "LOG: Trusting Developer Certificate..." -ForegroundColor Gray
        $cert = (Get-AuthenticodeSignature $vstoFile.FullName).SignerCertificate
        if ($cert) {
            foreach ($storeName in @("Root", "TrustedPublisher")) {
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, "LocalMachine")
                $store.Open("ReadWrite"); $store.Add($cert); $store.Close()
            }
        }

        # Install
        Write-Host "LOG: Running VSTOInstaller.exe..." -ForegroundColor Gray
        $vstoPath = "$env:CommonProgramFiles\microsoft shared\VSTO\10.0\VSTOInstaller.exe"
        $p = Start-Process $vstoPath -ArgumentList "/i `"$($vstoFile.FullName)`" /s" -Wait -PassThru
        Write-Host "LOG: Installer Exit Code: $($p.ExitCode)" -ForegroundColor Yellow

        # Registry Registration (The "Force-Load" method)
        $paths = @(
            "HKLM:\SOFTWARE\Microsoft\Office\PowerPoint\Addins\OSCPoint",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\PowerPoint\Addins\OSCPoint",
            "HKCU:\Software\Microsoft\Office\PowerPoint\Addins\OSCPoint"
        )
        foreach ($p in $paths) {
            if (!(Test-Path $p)) { New-Item $p -Force -ErrorAction SilentlyContinue }
            if (Test-Path $p) {
                Set-ItemProperty $p -Name "Manifest" -Value "$($vstoFile.FullName)|vstolocal"
                Set-ItemProperty $p -Name "LoadBehavior" -Value 3
                Set-ItemProperty $p -Name "FriendlyName" -Value "OSCPoint"
            }
        }

        # OSC Config
        $oscConfig = "HKCU:\Software\Zinc Event Production Ltd\OSCPoint"
        if (!(Test-Path $oscConfig)) { New-Item $oscConfig -Force }
        Set-ItemProperty $oscConfig -Name "RemoteHost" -Value $OSCTargetIP
        Set-ItemProperty $oscConfig -Name "FeedbackEnabled" -Value "True"
        Write-Host "SUCCESS: OSCPoint Configured to $OSCTargetIP" -ForegroundColor Green
    }
}

# --- REMAINING APPS ---
Write-Host "`n[Other Apps Stage]" -ForegroundColor Cyan

# Agent
if ($null -ne $agentExe) {
    $dest = "$([System.Environment]::GetFolderPath('CommonStartup'))\agent.exe"
    Copy-Item $agentExe $dest -Force -ErrorAction SilentlyContinue
    Unblock-File $dest -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName "GFX Agent" -Direction Inbound -Program $dest -Action Allow -Profile Any -ErrorAction SilentlyContinue
    Write-Host "Agent Set." -ForegroundColor Green
}

# Tally
if ($null -ne $tallyExe) {
    Copy-Item $tallyExe "$env:USERPROFILE\Desktop\TallyViewer.exe" -Force
    Write-Host "Tally Set." -ForegroundColor Green
}

# Input Director
if ($null -ne $idInstaller) {
    Write-Host "Installing Input Director..." -ForegroundColor Yellow
    Start-Process $idInstaller -ArgumentList "/S" -Wait
}

Read-Host -Prompt "Press Enter to continue"

Write-Host "`nSetup Complete. Restarting..." -ForegroundColor Yellow
Start-Sleep -Seconds 5
# Restart-Computer -Force # Uncomment after testing
