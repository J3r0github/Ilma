# Simple Test Runner for Ilma Authentication Tests

## Prerequisites

Before running the tests, make sure you have:

1. A PostgreSQL database running (optional - tests will skip if no connection)
2. The correct environment variables set

## Setting up Environment Variables

### Windows (PowerShell)

```powershell
$env:DATABASE_URL = "postgresql://username:password@localhost/ilma_test"
$env:JWT_SECRET = "test-secret-key-that-is-long-enough-for-testing-purposes"
```

### Linux/Mac (Bash)

```bash
export DATABASE_URL="postgresql://username:password@localhost/ilma_test"
export JWT_SECRET="test-secret-key-that-is-long-enough-for-testing-purposes"
```

## Running the Tests

### Run All Tests

```bash
cargo test
```

### Run Only Authentication Tests

```bash
cargo test auth_tests
```

### Run a Specific Test

```bash
cargo test test_login_with_credentials
```

### Run Tests with Output

```bash
cargo test -- --nocapture
```

## Test Database Setup

You'll need a test database. Create one with:

```sql
CREATE DATABASE ilma_test;
```

Then run your migrations:

```bash
sqlx migrate run --database-url "postgresql://username:password@localhost/ilma_test"
```

## Understanding the Tests

### What Each Test Does:

1. **test_successful_login**:

   - Sends a POST request to `/auth/login` with valid credentials
   - Expects either 200 OK (if user exists) or 401 Unauthorized (if user doesn't exist)

2. **test_login_wrong_password**:

   - Sends login request with wrong password
   - Should always return 401 Unauthorized

3. **test_login_nonexistent_email**:

   - Sends login request with non-existent email
   - Should return 401 Unauthorized

4. **test_password_reset_request**:

   - Sends password reset request
   - Should always return 200 OK (to prevent email enumeration)

5. **test_password_reset_invalid_token**:

   - Tries to reset password with invalid token
   - Should return 400 Bad Request

6. **test_login_malformed_json**:

   - Sends malformed JSON to login endpoint
   - Should return 400 Bad Request

### What Each Test Does:

1. **test_login_with_credentials**:

   - Sends a POST request to `/auth/login` with valid credentials
   - Expects either 200 OK (if user exists) or 401 Unauthorized (if user doesn't exist)

2. **test_login_invalid_email**:

   - Sends login request with invalid email format
   - Should return 401 Unauthorized

3. **test_password_reset_request**:

   - Sends password reset request
   - Should always return 200 OK (to prevent email enumeration)

4. **test_reset_password_invalid_token**:

   - Tries to reset password with invalid token
   - Should return 400 Bad Request

5. **test_login_malformed_json**:

   - Sends malformed JSON to login endpoint
   - Should return 400 Bad Request

6. **test_login_missing_fields**:

   - Sends login request missing required fields
   - Should return 400 Bad Request

7. **test_login_empty_credentials**:
   - Sends login request with empty email and password
   - Should return 401 Unauthorized

## Expected Test Results

When you run the tests, you should see output like:

```
running 7 tests
test auth_tests::test_login_empty_credentials ... ok
test auth_tests::test_login_invalid_email ... ok
test auth_tests::test_login_malformed_json ... ok
test auth_tests::test_login_missing_fields ... ok
test auth_tests::test_login_with_credentials ... ok
test auth_tests::test_password_reset_request ... ok
test auth_tests::test_reset_password_invalid_token ... ok

test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

## Troubleshooting

### Common Issues:

1. **Database Connection Error**: Tests will automatically skip if database connection fails
2. **JWT Secret Error**: Make sure JWT_SECRET is set and is long enough (at least 32 characters)
3. **Migration Issues**: Run `sqlx migrate run` to make sure your database schema is up to date

### Debug Mode:

Add this to see more detailed output:

```bash
RUST_LOG=debug cargo test -- --nocapture
```

## Test Coverage

These tests cover:

- ✅ Login endpoint (`/api/auth/login`)
- ✅ Password reset request (`/api/auth/request-password-reset`)
- ✅ Password reset (`/api/auth/reset-password`)
- ✅ Error handling for malformed requests
- ✅ Authentication failure cases
- ✅ JSON validation

This covers all the authentication endpoints documented in your Swagger UI!
