#!/usr/bin/env powershell
# Test script to demonstrate environment-based test user creation

Write-Host "Environment-Based Test User System Test" -ForegroundColor Green
Write-Host "=======================================" -ForegroundColor Green

# Check if .env file exists
if (!(Test-Path ".env")) {
    Write-Host "Creating test .env file..." -ForegroundColor Yellow
    Copy-Item "test_env_users.env" ".env"
    Write-Host "✓ Created .env file with test user configuration" -ForegroundColor Green
} else {
    Write-Host "✓ .env file already exists" -ForegroundColor Green
}

Write-Host ""
Write-Host "Test User Configuration:" -ForegroundColor Yellow
Write-Host "- Main Test User: main.test@example.com" -ForegroundColor White
Write-Host "- Student Test User: student.test@example.com" -ForegroundColor White
Write-Host "- Teacher Test User: teacher.test@example.com" -ForegroundColor White
Write-Host "- Admin Test User: admin.test@example.com" -ForegroundColor White

Write-Host ""
Write-Host "Starting server to test user creation..." -ForegroundColor Yellow
Write-Host "Look for log messages indicating test user creation." -ForegroundColor White
Write-Host "Press Ctrl+C to stop the server and trigger cleanup." -ForegroundColor White

Write-Host ""
Write-Host "Test the API with these credentials:" -ForegroundColor Cyan
Write-Host "curl -X POST http://localhost:8000/api/auth/login -H 'Content-Type: application/json' -d '{\"email\":\"main.test@example.com\",\"password\":\"main_test_password_123\"}'" -ForegroundColor Gray

Write-Host ""
Write-Host "Press any key to start the server..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# Start the server
cargo run
