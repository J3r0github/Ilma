#!/usr/bin/env pwsh
# PowerShell script to validate the E2E messaging test configuration

Write-Host "🔍 Validating E2E Messaging Test Configuration" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# Check if we're in the right directory
if (-not (Test-Path "test_config.json")) {
    Write-Host "❌ Error: test_config.json not found in current directory" -ForegroundColor Red
    exit 1
}

try {
    # Load and parse the JSON configuration
    $config = Get-Content "test_config.json" | ConvertFrom-Json
    Write-Host "✅ JSON syntax is valid" -ForegroundColor Green

    # Validate basic structure
    $requiredFields = @("version", "users", "classes", "grades", "attendance", "schedule_events", "messages", "threads", "permissions")
    foreach ($field in $requiredFields) {
        if (-not $config.$field) {
            Write-Host "❌ Error: Missing required field '$field'" -ForegroundColor Red
            exit 1
        }
    }
    Write-Host "✅ All required fields present" -ForegroundColor Green

    # Validate users
    $users = $config.users
    Write-Host "👥 Users configured: $($users.Count)" -ForegroundColor Yellow

    $adminUser = $users | Where-Object { $_.role -eq "principal" }
    $teacherUser = $users | Where-Object { $_.role -eq "teacher" }
    $studentUsers = $users | Where-Object { $_.role -eq "student" }

    if (-not $adminUser) {
        Write-Host "❌ Error: No admin/principal user found" -ForegroundColor Red
        exit 1
    }
    Write-Host "✅ Admin user found: $($adminUser.email)" -ForegroundColor Green

    if (-not $teacherUser) {
        Write-Host "❌ Error: No teacher user found" -ForegroundColor Red
        exit 1
    }
    Write-Host "✅ Teacher user found: $($teacherUser.email)" -ForegroundColor Green

    if ($studentUsers.Count -eq 0) {
        Write-Host "⚠️  Warning: No student users found" -ForegroundColor Yellow
    } else {
        Write-Host "✅ Student users found: $($studentUsers.Count)" -ForegroundColor Green
    }

    # Validate message threads
    $threads = $config.threads
    $messages = $config.messages
    Write-Host "💬 Message threads configured: $($threads.Count)" -ForegroundColor Yellow
    Write-Host "📨 Messages configured: $($messages.Count)" -ForegroundColor Yellow

    # Check for teacher-admin communication
    $teacherAdminThread = $threads | Where-Object { 
        $_.participants -contains $adminUser.id -and $_.participants -contains $teacherUser.id 
    }

    if (-not $teacherAdminThread) {
        Write-Host "❌ Error: No teacher-admin communication thread found" -ForegroundColor Red
        exit 1
    }
    Write-Host "✅ Teacher-Admin thread found: $($teacherAdminThread.Count) thread(s)" -ForegroundColor Green

    # Check for messages between teacher and admin
    $teacherToAdminMessages = $messages | Where-Object { 
        $_.sender_id -eq $teacherUser.id -and 
        ($_.encrypted_keys | Where-Object { $_.recipient_id -eq $adminUser.id })
    }

    $adminToTeacherMessages = $messages | Where-Object { 
        $_.sender_id -eq $adminUser.id -and 
        ($_.encrypted_keys | Where-Object { $_.recipient_id -eq $teacherUser.id })
    }

    Write-Host "📤 Teacher to Admin messages: $($teacherToAdminMessages.Count)" -ForegroundColor Yellow
    Write-Host "📥 Admin to Teacher messages: $($adminToTeacherMessages.Count)" -ForegroundColor Yellow

    if ($teacherToAdminMessages.Count -eq 0 -and $adminToTeacherMessages.Count -eq 0) {
        Write-Host "⚠️  Warning: No messages between teacher and admin found" -ForegroundColor Yellow
    } else {
        Write-Host "✅ Teacher-Admin messaging configured" -ForegroundColor Green
    }

    # Validate encrypted keys
    $messagesMissingKeys = $messages | Where-Object { 
        -not $_.encrypted_keys -or $_.encrypted_keys.Count -eq 0 
    }

    if ($messagesMissingKeys.Count -gt 0) {
        Write-Host "❌ Error: $($messagesMissingKeys.Count) message(s) missing encrypted keys" -ForegroundColor Red
        exit 1
    }
    Write-Host "✅ All messages have encrypted keys" -ForegroundColor Green

    # Summary
    Write-Host ""
    Write-Host "📊 Configuration Summary:" -ForegroundColor Cyan
    Write-Host "   Users: $($users.Count) (Admin: 1, Teacher: 1, Students: $($studentUsers.Count))"
    Write-Host "   Threads: $($threads.Count)"
    Write-Host "   Messages: $($messages.Count)"
    Write-Host "   Teacher-Admin Communication: Configured ✅"

    Write-Host ""
    Write-Host "🎉 E2E Messaging configuration is valid and ready for testing!" -ForegroundColor Green
    Write-Host ""
    Write-Host "🚀 Next steps:" -ForegroundColor Cyan
    Write-Host "   1. Run: .\run_message_tests.ps1"
    Write-Host "   2. Or manually test with: cargo test --test message_e2e_tests"
    Write-Host "   3. Start server with: cargo run"
    Write-Host ""

} catch {
    Write-Host "❌ Error validating configuration: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
