# Create log file
$logFile = "C:\temp\7zip_install.log"
Start-Transcript -Path $logFile -Force

try {
    # Check if C:\temp exists, if not, create it
    if (-Not (Test-Path -Path "C:\temp")) {
        New-Item -ItemType Directory -Path "C:\temp"
    }

    # Stop explorer to release 7-zip dll
    Stop-Process -Name "explorer" -Force -ErrorAction SilentlyContinue
    
    # Get existing 7-zip installation and remove it
    $existing7zip = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "7-Zip*" }
    if ($existing7zip) {
        Write-Host "Removing existing 7-Zip installation..."
        $existing7zip.Uninstall()
        Start-Sleep -Seconds 45  # Wait for uninstall to complete
    }

    $7zipUrl = "https://www.7-zip.org/a/7z2409-x64.msi"
    $installerPath = "C:\temp\7z2409-x64.msi"

    # Download with progress
    Write-Host "Downloading 7-Zip installer..."
    Invoke-WebRequest -Uri $7zipUrl -OutFile $installerPath
    
    # Verify file was downloaded
    if (Test-Path $installerPath) {
        Write-Host "Download completed. Starting installation..."
        
        # Install with proper logging and wait
        $process = Start-Process msiexec.exe -ArgumentList "/i `"$installerPath`" /quiet /qn /norestart /l*v `"C:\temp\7zip_msi.log`"" -NoNewWindow -PassThru -Wait -Verb RunAs
        
        if ($process.ExitCode -eq 0) {
            Write-Host "Installation completed successfully"
        } else {
            throw "Installation failed with exit code: $($process.ExitCode)"
        }
    } else {
        throw "Installer download failed"
    }
} catch {
    Write-Error "Error occurred: $_"
    exit 1
} finally {
    # Cleanup and restart explorer
    if (Test-Path $installerPath) {
        Remove-Item -Path $installerPath -Force
    }
    Start-Process "explorer.exe"
    Stop-Transcript
}