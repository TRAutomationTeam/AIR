# PowerShell script to install and configure Ollama
Write-Host "Installing Ollama (checking Windows Installer activity)..."
Get-Process -Name "msiexec" -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Host "Found MSI process: $($_.Id), Started: $($_.StartTime)"
}

# Setup logging
$logFile = "ollama_install.log"
Start-Transcript -Path $logFile -Append

$installStartTime = Get-Date
$installTimeout = 900  # 15 minutes timeout

# Enable verbose Windows Installer logging
$env:MSIEXEC_DEBUG_LEVEL = 3
Write-Host "Starting installer with $([math]::Round($installTimeout/60, 0)) minute timeout..."

# Create log file for installation
$logFile = "ollama_install_$([DateTime]::Now.ToString('yyyyMMddHHmmss')).log"

# Monitor installation progress
$monitoringScript = {
    while ($true) {
        $installLogs = Get-ChildItem -Path $env:TEMP -Filter "MSI*.LOG" -File |
            Where-Object { $_.LastWriteTime -gt $installStartTime }

        $installerProcesses = Get-Process -Name "msiexec" -ErrorAction SilentlyContinue

        Write-Host @"
Installation Status:
Active MSI Processes: $($installerProcesses.Count)
"@
        
        # Show process details
        foreach ($installerProcess in $installerProcesses) {
            Write-Host "Process: $($installerProcess.ProcessName) (PID: $($installerProcess.Id))"
        }
        
        Start-Sleep -Seconds 30  # Report progress every 30 seconds
    }
}

# Start the monitoring job
$monitorJob = Start-Job -ScriptBlock $monitoringScript

# Install Ollama
$process = Start-Process -FilePath msiexec -ArgumentList "/i", "ollama.msi", "/quiet", "/norestart", "/l*v", $logFile -Wait -PassThru

# Stop monitoring
Stop-Job -Job $monitorJob
Remove-Job -Job $monitorJob

# Verify installation result
if ($process.ExitCode -ne 0) {
    Write-Error "Ollama installation failed with exit code $($process.ExitCode)"
    exit 1
}

Write-Host "Ollama installation completed in $([math]::Round(((Get-Date) - $installStartTime).TotalSeconds, 0)) seconds"

# Start and verify Ollama service
Write-Host "Starting Ollama service..."
Start-Service -Name Ollama
$retryCount = 0
$maxRetries = 6
$serviceStarted = $false

while ($retryCount -lt $maxRetries) {
    $service = Get-Service -Name Ollama -ErrorAction SilentlyContinue
    if ($service.Status -eq 'Running') {
        $serviceStarted = $true
        break
    }
    Write-Host "Waiting for Ollama service to start... Attempt $($retryCount + 1) of $maxRetries"
    Start-Sleep -Seconds 10
    $retryCount++
}

if (-not $serviceStarted) {
    Write-Error "Failed to start Ollama service after $maxRetries attempts"
    exit 1
}

# Verify Ollama is working
Write-Host "Verifying Ollama installation..."
try {
    $testResult = ollama list
    if ($LASTEXITCODE -eq 0 -and $testResult -match "codellama") {
        Write-Host "Ollama verification successful"
    } else {
        throw "Model not found in list"
    }
} catch {
    Write-Error "Failed to verify Ollama installation: $_"
    exit 1
}
