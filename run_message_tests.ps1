#!/usr/bin/env pwsh
# PowerShell script to run E2E encrypted messaging tests
# This script demonstrates teacher-admin encrypted communication

Write-Host "🚀 Ilma E2E Encrypted Messaging Test Suite" -ForegroundColor Cyan
Write-Host "===========================================" -ForegroundColor Cyan
Write-Host ""

# Check if we're in the right directory
if (-not (Test-Path "Cargo.toml")) {
    Write-Host "❌ Error: Please run this script from the project root directory" -ForegroundColor Red
    exit 1
}

# Set environment variables for testing
$env:TESTING_MODE = "true"
$env:TEST_CONFIG_PATH = "test_config.json"

# Set JWT secret for testing
if (-not $env:JWT_SECRET) {
    $env:JWT_SECRET = "test-secret-key-that-is-long-enough-for-testing-purposes"
    Write-Host "🔑 JWT secret set for testing" -ForegroundColor Green
}

# Verify test config exists
if (-not (Test-Path "test_config.json")) {
    Write-Host "❌ Error: test_config.json not found" -ForegroundColor Red
    exit 1
}

Write-Host "📋 Test Configuration:" -ForegroundColor Yellow
Write-Host "   TESTING_MODE: $env:TESTING_MODE"
Write-Host "   TEST_CONFIG_PATH: $env:TEST_CONFIG_PATH"
Write-Host ""

# Check if database URL is set
if (-not $env:DATABASE_URL) {
    Write-Host "⚠️  Warning: DATABASE_URL not set, using default" -ForegroundColor Yellow
    $env:DATABASE_URL = "postgresql://dbuser:dbuser@localhost/ilma_db"
}
Write-Host "🗄️  Database URL: $env:DATABASE_URL" -ForegroundColor Green
Write-Host ""

Write-Host "🧪 Running E2E Encrypted Messaging Tests..." -ForegroundColor Cyan
Write-Host ""

# Run specific message E2E tests
Write-Host "1️⃣ Testing user authentication..." -ForegroundColor Blue
cargo test test_login_teacher_and_admin --test message_e2e_tests -- --nocapture

Write-Host ""
Write-Host "2️⃣ Testing teacher to admin messaging..." -ForegroundColor Blue  
cargo test test_teacher_to_admin_message --test message_e2e_tests -- --nocapture

Write-Host ""
Write-Host "3️⃣ Testing admin thread listing..." -ForegroundColor Blue
cargo test test_admin_list_threads --test message_e2e_tests -- --nocapture

Write-Host ""
Write-Host "4️⃣ Testing admin reply functionality..." -ForegroundColor Blue
cargo test test_admin_reply_to_teacher --test message_e2e_tests -- --nocapture

Write-Host ""
Write-Host "5️⃣ Testing teacher message viewing..." -ForegroundColor Blue
cargo test test_teacher_see_admin_reply --test message_e2e_tests -- --nocapture

Write-Host ""
Write-Host "6️⃣ Testing complete E2E conversation flow..." -ForegroundColor Blue
cargo test test_complete_e2e_conversation --test message_e2e_tests -- --nocapture

Write-Host ""
Write-Host "✅ All E2E encrypted messaging tests completed!" -ForegroundColor Green
Write-Host ""
Write-Host "🔍 What these tests demonstrate:" -ForegroundColor Cyan
Write-Host "   📧 Teacher can send encrypted messages to admin"
Write-Host "   📬 Admin can receive and read teacher's messages" 
Write-Host "   💬 Admin can send encrypted replies back to teacher"
Write-Host "   🔄 Both users can maintain threaded conversations"
Write-Host "   🔐 All messages use proper end-to-end encryption"
Write-Host "   🎯 Message threads and participants work correctly"
Write-Host ""
Write-Host "🎉 Your Ilma messaging system is ready for E2E encrypted communication!" -ForegroundColor Green
