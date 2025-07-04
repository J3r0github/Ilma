# Environment-Based Test User System

## Overview

The Ilma API now supports dynamic test user creation based on environment variables, replacing the previous hardcoded test users. This provides greater flexibility for testing different user roles and scenarios.

## Configuration

### Environment Variables

The system reads test user configuration from the following environment variables:

#### Main Test User

- `TEST_USERNAME`: Username for the main test user
- `TEST_EMAIL`: Email address for the main test user
- `TEST_PASSWORD`: Password for the main test user
- Role: Automatically assigned as Principal with superuser privileges

#### Additional Test Users (1-5)

For each additional test user (numbered 1-5), configure:

- `TEST_USER_N_USERNAME`: Username for test user N
- `TEST_USER_N_EMAIL`: Email address for test user N
- `TEST_USER_N_PASSWORD`: Password for test user N
- `TEST_USER_N_ROLE`: Role for test user N (optional, defaults to "student")

Supported roles:

- `student`: Regular student user
- `teacher`: Teacher user
- `admin` or `principal`: Administrator user with superuser privileges

### Rate Limiting Bypass

Test users can bypass rate limiting when configured:

- `TEST_SKIP_RATE_LIMITS=true`: Enables rate limiting bypass for test users
- The system identifies test users by their JWT claims (email matching configured test emails)
- Local IP addresses (127.0.0.1, ::1, localhost) also bypass rate limits in testing mode

## Example Configuration

```env
# Enable testing mode
TESTING_MODE=true

# Main test user (automatically Principal with superuser)
TEST_USERNAME=main_admin
TEST_EMAIL=admin@test.edu
TEST_PASSWORD=admin_secure_password

# Student test user
TEST_USER_1_USERNAME=test_student
TEST_USER_1_EMAIL=student@test.edu
TEST_USER_1_PASSWORD=student_password
TEST_USER_1_ROLE=student

# Teacher test user
TEST_USER_2_USERNAME=test_teacher
TEST_USER_2_EMAIL=teacher@test.edu
TEST_USER_2_PASSWORD=teacher_password
TEST_USER_2_ROLE=teacher

# Additional admin user
TEST_USER_3_USERNAME=test_admin
TEST_USER_3_EMAIL=admin2@test.edu
TEST_USER_3_PASSWORD=admin_password
TEST_USER_3_ROLE=admin

# Enable rate limiting bypass
TEST_SKIP_RATE_LIMITS=true
```

## Behavior

### Test User Creation

- Test users are created automatically when the server starts (only in testing mode)
- Users are created with proper password hashing
- Each user gets a unique UUID and generated public key
- Duplicate emails are handled with ON CONFLICT DO UPDATE

### Test User Cleanup

- All test users and their associated data are automatically cleaned up on server shutdown
- Cleanup includes: messages, threads, attendance records, grades, class enrollments, permissions, and password reset tokens
- This ensures no test data persists between test sessions

### Rate Limiting

- Test users identified by email in JWT claims bypass rate limiting
- Local development IP addresses also bypass rate limits in testing mode
- Rate limiting bypass only works when both `TESTING_MODE=true` and `TEST_SKIP_RATE_LIMITS=true`

## Security Considerations

⚠️ **IMPORTANT SECURITY WARNINGS:**

1. **Never enable testing mode in production environments**
2. **Use strong, unique passwords even for test users**
3. **Regularly rotate test user credentials**
4. **Ensure test database is separate from production**
5. **Test users bypass security controls - only use in isolated environments**

## Migration from Hardcoded Users

The previous hardcoded test users have been replaced with this environment-based system. Update your testing scripts to use the new configurable test user credentials instead of the old hardcoded ones:

### Old Hardcoded Users (Removed)

- `test_admin@example.com` / `admin123`
- `test_teacher@example.com` / `teacher123`
- `test_student@example.com` / `student123`

### New Environment-Based Users

Configure as needed using the environment variables described above.

## Benefits

1. **Flexibility**: Configure any number of test users with different roles
2. **Security**: No hardcoded credentials in source code
3. **Isolation**: Test users are completely cleaned up after each session
4. **Scalability**: Easy to add more test scenarios without code changes
5. **Rate Limiting**: Intelligent bypass for test users during development

## Testing

To test the new system:

1. Copy the example environment file: `cp test_env_users.env .env`
2. Start the server: `cargo run`
3. Verify test users are created in the logs
4. Test authentication with configured credentials
5. Verify rate limiting bypass (if enabled)
6. Stop the server and verify cleanup in logs
