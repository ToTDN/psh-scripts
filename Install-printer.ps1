#.\Install-printer.ps1 -PrinterIP "192.168.1.100" -DriverPath "C:\Drivers\PrinterModel" -PrinterName "Marketing Printer"
#.\Install-printer.ps1 -PrinterIP "192.168.1.100" -PrinterName "Marketing Printer"

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PrinterIP,
    
    [Parameter(Mandatory = $false)]
    [string]$DriverPath,
    
    [Parameter(Mandatory = $false)]
    [string]$PrinterName
)

$logFile = "C:\temp\printer_install.log"
Start-Transcript -Path $logFile -Force

function Test-ValidIPAddress {
    param([string]$IP)
    $RegEx = [regex]"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    return $RegEx.Match($IP).Success
}

try {
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must be run as Administrator"
    }
    if (-not (Test-ValidIPAddress -IP $PrinterIP)) {
        throw "Invalid IP address format"
    }
    if (-not $PrinterName) {
        $PrinterName = "IP_$PrinterIP"
    }
    $existingPrinter = Get-Printer -Name $PrinterName -ErrorAction SilentlyContinue
    if ($existingPrinter) {
        Remove-Printer -Name $PrinterName
    }
    $portName = "IP_$PrinterIP"
    $existingPort = Get-PrinterPort -Name $portName -ErrorAction SilentlyContinue
    if (-not $existingPort) {
        Add-PrinterPort -Name $portName -PrinterHostAddress $PrinterIP
    }
    if ($DriverPath) {
        $infPath = Get-ChildItem -Path $DriverPath -Filter "*.inf" -Recurse | Select-Object -First 1
        if (-not $infPath) {
            throw "No .inf file found in provided driver path"
        }
        Add-PrinterDriver -Name $PrinterName -InfPath $infPath.FullName
    } else {
        Write-Host "No driver path provided. Windows Update will be used for drivers."
    }
    Add-Printer -Name $PrinterName -DriverName $PrinterName -PortName $portName
    Write-Host "Printer installation completed successfully"
} catch {
    Write-Error "Error occurred: $_"
    exit 1
} finally {
    Stop-Transcript
}