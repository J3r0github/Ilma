# Test Credentials System

## Overview

The testing credentials system has been completely re-implemented to use actual database users instead of bypassing authentication.

## Changes Made

### 1. Authentication Changes

- **Removed** the `verify_testing_credentials` function that allowed bypassing JWT validation
- **Updated** the JWT middleware to only use standard JWT validation
- **Removed** the special testing credential bypass logic

### 2. Test User Creation

- **Added** `create_test_users` function that creates real users in the database at startup
- **Test users created:**
  - `test_admin` (test_admin@example.com) - Password: `admin123` - Role: Principal, Superuser
  - `test_teacher` (test_teacher@example.com) - Password: `teacher123` - Role: Teacher
  - `test_student` (test_student@example.com) - Password: `student123` - Role: Student

### 3. Cleanup System

- **Added** `cleanup_test_users` function that removes all test users and their data
- **Tracks** test user IDs using a static HashSet for proper cleanup
- **Cascading cleanup** removes all associated data:
  - Messages and encrypted keys
  - Thread participations
  - Attendance records
  - Grades
  - Class enrollments
  - Permission assignments
  - Password reset tokens

### 4. Server Lifecycle Integration

- **Startup:** Test users are created automatically when `TESTING_MODE=true`
- **Shutdown:** Test users and all their data are cleaned up on server shutdown (Ctrl+C)

## Usage

### 1. Enable Testing Mode

Set the environment variable:

```bash
TESTING_MODE=true
```

### 2. Start the Server

```bash
cargo run
```

### 3. Test Authentication

You can now authenticate using the test users with regular JWT tokens:

```bash
# Login as test admin
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "test_admin@example.com", "password": "admin123"}'

# Login as test teacher
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "test_teacher@example.com", "password": "teacher123"}'

# Login as test student
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "test_student@example.com", "password": "student123"}'
```

### 4. Use the JWT Token

The login response will contain a JWT token that you can use for authenticated requests:

```bash
# Example authenticated request
curl -X GET http://localhost:8000/api/me \
  -H "Authorization: Bearer YOUR_JWT_TOKEN_HERE"
```

## Security Improvements

1. **No More Authentication Bypass:** Test users must authenticate normally through the standard JWT system
2. **Proper User Management:** Test users are real database entities with proper roles and permissions
3. **Clean Shutdown:** All test data is automatically cleaned up when the server shuts down
4. **Environment-Based:** Only works when `TESTING_MODE=true` is explicitly set

## Benefits

- **More Realistic Testing:** Tests use the same authentication flow as production
- **Better Security:** No special bypass logic that could be accidentally enabled in production
- **Proper Cleanup:** No test data left behind after testing sessions
- **Role-Based Testing:** Different test users with different permission levels for comprehensive testing
