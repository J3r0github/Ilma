# Testing Mode Documentation

## Overview

The Ilma API includes a testing mode feature that allows bypassing authentication for development and testing purposes. This feature is designed to simplify API testing and development workflows.

## ⚠️ Security Warning

**TESTING MODE MUST NEVER BE ENABLED IN PRODUCTION ENVIRONMENTS**

- Testing mode completely bypasses authentication
- Test credentials have full superuser privileges
- This feature is only for development and testing purposes
- Always ensure `TESTING_MODE=false` in production

## Configuration

### Environment Variables

Add these variables to your `.env` file:

```bash
# Enable testing mode (set to "true" or "1")
TESTING_MODE=false

# Test credentials
TEST_USERNAME=test_user
TEST_PASSWORD=test_pass_123
```

### Default Values

If not specified in the environment, the following defaults are used:

- `TEST_USERNAME`: "test_user"
- `TEST_PASSWORD`: "test_pass"

## Usage

### 1. Enable Testing Mode

Set the environment variable:

```bash
TESTING_MODE=true
```

### 2. Use Test Credentials

Instead of a JWT token, use the test credentials in the format:

```
Authorization: Bearer test_user:test_pass_123
```

### 3. API Access

When testing mode is enabled and valid test credentials are provided:

- The user gets full superuser privileges
- All API endpoints become accessible
- No database user lookup is required
- Rate limiting still applies

## Example Usage

### cURL Example

```bash
# With testing mode enabled
curl -X GET "http://localhost:8000/api/me" \
  -H "Authorization: Bearer test_user:test_pass_123"
```

### JavaScript Example

```javascript
const response = await fetch("http://localhost:8000/api/me", {
  headers: {
    Authorization: "Bearer test_user:test_pass_123",
  },
});
```

### Python Example

```python
import requests

headers = {
    'Authorization': 'Bearer test_user:test_pass_123'
}

response = requests.get('http://localhost:8000/api/me', headers=headers)
```

## Testing Mode User Properties

When using test credentials, the system creates a virtual user with:

- **User ID**: "test-user-id"
- **Email**: "test@example.com"
- **Role**: Principal (highest privileges)
- **Superuser**: true
- **Testing Flag**: true

## Server Logs

When testing mode is enabled, the server will log:

```
⚠️  TESTING MODE IS ENABLED - This should only be used in development!
⚠️  Testing credentials will bypass authentication!
Test credentials: test_user:test_pass_123
```

## Best Practices

1. **Development Only**: Only enable testing mode in development environments
2. **Unique Credentials**: Use unique test credentials for each project
3. **Regular Rotation**: Change test credentials regularly
4. **Environment Isolation**: Keep testing environments isolated from production
5. **Clear Documentation**: Document when and how testing mode is used in your project

## Integration with CI/CD

For automated testing, you can enable testing mode in your CI/CD pipeline:

```yaml
# Example GitHub Actions
env:
  TESTING_MODE: true
  TEST_USERNAME: ci_test_user
  TEST_PASSWORD: ci_test_pass_secure_123
```

## Troubleshooting

### Testing Mode Not Working

1. Check that `TESTING_MODE=true` is set
2. Verify the server logs show testing mode is enabled
3. Ensure the credentials format is correct: `username:password`
4. Check that the bearer token format is correct

### Authentication Still Required

1. Verify testing mode is enabled in server logs
2. Check environment variables are loaded correctly
3. Ensure the credential format matches exactly

## Security Considerations

- Never commit `.env` files with testing mode enabled
- Use different credentials for different environments
- Monitor access logs when testing mode is enabled
- Disable testing mode immediately after testing
- Consider using time-limited testing mode activation

## Limitations

- Testing mode bypasses all authentication checks
- Database user permissions are not checked
- Some user-specific operations may not work as expected
- Rate limiting is still enforced
