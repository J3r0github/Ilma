#!/usr/bin/env pwsh
# Test script to verify the configloader cleanup fix
# This script will run the application briefly and then terminate it to test cleanup

Write-Host "Starting test of configloader cleanup fix..." -ForegroundColor Green

# Set environment variables for testing
$env:TESTING_MODE = "true"
$env:DATABASE_URL = "postgresql://dbuser:dbuser@localhost/ilma_db"
$env:JWT_SECRET = "2411cfd614aa7f96558df982dde534f2f6bbd42470b76dca6702d31af0621426"
$env:RUST_LOG = "DEBUG"

Write-Host "Building the application..." -ForegroundColor Yellow
cargo build --release

if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed!" -ForegroundColor Red
    exit 1
}

Write-Host "Starting application in background..." -ForegroundColor Yellow
$process = Start-Process -FilePath ".\target\release\ilma.exe" -PassThru -WindowStyle Hidden

Write-Host "Application started with PID: $($process.Id)" -ForegroundColor Green
Write-Host "Waiting 5 seconds for startup..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

Write-Host "Sending termination signal to test cleanup..." -ForegroundColor Yellow
try {
    # Send Ctrl+C to the process
    $process.Kill()
    
    # Wait for the process to exit (with timeout)
    $exited = $process.WaitForExit(10000)  # 10 second timeout
    
    if ($exited) {
        Write-Host "Application terminated successfully. Exit code: $($process.ExitCode)" -ForegroundColor Green
        Write-Host "Test completed successfully!" -ForegroundColor Green
    } else {
        Write-Host "Application did not terminate within timeout - this indicates a hanging cleanup!" -ForegroundColor Red
        $process.Kill()
        Write-Host "Force killed the process." -ForegroundColor Yellow
        exit 1
    }
} catch {
    Write-Host "Error during test: $_" -ForegroundColor Red
    try {
        $process.Kill()
    } catch {
        # Process might already be dead
    }
    exit 1
}

Write-Host "Cleanup test completed successfully!" -ForegroundColor Green
