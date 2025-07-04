# Rate Limiting Configuration

This document explains how to configure rate limiting for the Ilma API server.

## Overview

The Ilma API server implements a flexible rate limiting system that supports both global and per-endpoint rate limiting. The rate limiting is IP-based and uses a sliding window algorithm to track request counts over time.

## Global Rate Limiting

Global rate limiting applies to all API endpoints unless overridden by endpoint-specific configurations.

### Environment Variables

- `RATE_LIMIT_REQUESTS`: Maximum number of requests per IP within the time window (default: 100)
- `RATE_LIMIT_WINDOW_SECONDS`: Time window in seconds for rate limiting (default: 60)

### Example

```bash
# Allow 50 requests per minute globally
RATE_LIMIT_REQUESTS=50
RATE_LIMIT_WINDOW_SECONDS=60
```

## Per-Endpoint Rate Limiting

You can configure specific rate limits for individual endpoints using environment variables with the following format:

```
RATE_LIMIT_<METHOD>_<PATH>_REQUESTS=<number>
RATE_LIMIT_<METHOD>_<PATH>_WINDOW=<seconds>
```

Where:

- `<METHOD>` is the HTTP method (GET, POST, PUT, DELETE, etc.)
- `<PATH>` is the API path with forward slashes replaced by underscores
- Leading underscores from paths are removed

### Supported Endpoints

The following endpoints support per-endpoint rate limiting:

#### Authentication Endpoints

- `POST /api/auth/login`
- `POST /api/auth/request-password-reset`
- `POST /api/auth/reset-password`

#### User Management

- `POST /api/users` (user creation)

#### Messaging

- `POST /api/messages/threads` (send message)
- `GET /api/messages/threads` (list threads)

#### Academic Features

- `POST /api/grades` (assign grade)
- `POST /api/attendance` (record attendance)
- `POST /api/classes` (create class)

### Configuration Examples

#### Strict Authentication Rate Limiting

```bash
# Allow only 5 login attempts per 5 minutes
RATE_LIMIT_POST_AUTH_LOGIN_REQUESTS=5
RATE_LIMIT_POST_AUTH_LOGIN_WINDOW=300

# Allow only 3 password reset requests per hour
RATE_LIMIT_POST_AUTH_REQUEST_PASSWORD_RESET_REQUESTS=3
RATE_LIMIT_POST_AUTH_REQUEST_PASSWORD_RESET_WINDOW=3600
```

#### User Creation Limits

```bash
# Allow only 2 user creations per hour
RATE_LIMIT_POST_USERS_REQUESTS=2
RATE_LIMIT_POST_USERS_WINDOW=3600
```

#### Message Rate Limiting

```bash
# Allow 20 messages per minute
RATE_LIMIT_POST_MESSAGES_THREADS_REQUESTS=20
RATE_LIMIT_POST_MESSAGES_THREADS_WINDOW=60

# Allow 100 thread list requests per minute
RATE_LIMIT_GET_MESSAGES_THREADS_REQUESTS=100
RATE_LIMIT_GET_MESSAGES_THREADS_WINDOW=60
```

#### Academic Feature Limits

```bash
# Grade assignment: 50 per minute
RATE_LIMIT_POST_GRADES_REQUESTS=50
RATE_LIMIT_POST_GRADES_WINDOW=60

# Attendance recording: 100 per minute
RATE_LIMIT_POST_ATTENDANCE_REQUESTS=100
RATE_LIMIT_POST_ATTENDANCE_WINDOW=60

# Class creation: 5 per hour
RATE_LIMIT_POST_CLASSES_REQUESTS=5
RATE_LIMIT_POST_CLASSES_WINDOW=3600
```

## Environment-Specific Configurations

### Development Environment

```bash
# More lenient limits for development
RATE_LIMIT_REQUESTS=200
RATE_LIMIT_WINDOW_SECONDS=60

# Relaxed authentication limits
RATE_LIMIT_POST_AUTH_LOGIN_REQUESTS=20
RATE_LIMIT_POST_AUTH_LOGIN_WINDOW=300
```

### Production Environment

```bash
# Stricter limits for production
RATE_LIMIT_REQUESTS=50
RATE_LIMIT_WINDOW_SECONDS=60

# Very strict authentication limits
RATE_LIMIT_POST_AUTH_LOGIN_REQUESTS=5
RATE_LIMIT_POST_AUTH_LOGIN_WINDOW=300
```

### High-Security Environment

```bash
# Very strict global limits
RATE_LIMIT_REQUESTS=30
RATE_LIMIT_WINDOW_SECONDS=60

# Extremely strict authentication
RATE_LIMIT_POST_AUTH_LOGIN_REQUESTS=3
RATE_LIMIT_POST_AUTH_LOGIN_WINDOW=600
```

## How It Works

1. **IP-Based Tracking**: Each client IP address is tracked separately
2. **Per-Endpoint Tracking**: Each endpoint can have its own rate limiting configuration
3. **Sliding Window**: The system uses a sliding window algorithm that tracks request timestamps
4. **Automatic Cleanup**: Old request records are automatically removed when they fall outside the time window
5. **Graceful Degradation**: If endpoint-specific limits aren't configured, the global limits apply

## Rate Limit Responses

When a rate limit is exceeded, the server responds with:

- HTTP Status: `429 Too Many Requests`
- Content-Type: `application/json`
- Response Body:
  ```json
  {
    "error": "Rate limit exceeded",
    "message": "Too many requests from this IP address",
    "endpoint": "POST /api/auth/login"
  }
  ```

## Monitoring

The server logs rate limiting configuration at startup. Look for log messages like:

```
INFO ilma: Configured custom rate limit for POST /api/auth/login
INFO ilma: Rate limiting: 100 requests per 60 seconds
```

## Best Practices

1. **Start Conservative**: Begin with stricter limits and relax them based on actual usage patterns
2. **Monitor Critical Endpoints**: Pay special attention to authentication and user creation endpoints
3. **Environment-Specific Configuration**: Use different limits for development, staging, and production
4. **Regular Review**: Periodically review and adjust limits based on traffic patterns and security needs
5. **Log Analysis**: Monitor rate limit violations to identify potential abuse or the need for limit adjustments

## Troubleshooting

### Common Issues

1. **Rate Limits Too Strict**: If legitimate users are being blocked, increase the request limits or extend the time window
2. **Configuration Not Applied**: Ensure environment variables are properly set and the server is restarted
3. **Endpoint Not Recognized**: Check that the endpoint path format matches the expected pattern (forward slashes replaced with underscores)

### Debugging

To debug rate limiting issues:

1. Check server logs for rate limiting configuration messages
2. Verify environment variables are set correctly
3. Test with curl or similar tools to understand the behavior
4. Monitor the `429 Too Many Requests` responses

## Security Considerations

- Rate limiting helps prevent brute force attacks on authentication endpoints
- Per-endpoint limits provide granular control over resource usage
- The sliding window algorithm provides smooth rate limiting without sudden resets
- IP-based tracking means legitimate users on the same network may be affected by malicious users

## Performance Impact

The rate limiting system is designed to be lightweight:

- Uses in-memory storage with automatic cleanup
- Minimal CPU overhead per request
- Efficient data structures for fast lookups
- Concurrent access is handled safely with thread-safe data structures
