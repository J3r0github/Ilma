# Security Setup Guide

## Critical Security Configuration

### 1. Environment Variables Setup

**IMPORTANT**: Before deploying to production, you MUST:

1. Copy `.env.example` to `.env`
2. Generate a secure JWT secret:
   ```bash
   # Generate a secure 64-character random string
   openssl rand -hex 32
   ```
3. Replace `JWT_SECRET` in `.env` with the generated value
4. Update database credentials
5. **NEVER** commit the `.env` file to version control

### 2. JWT Secret Requirements

- **Minimum 32 characters**
- **Must be cryptographically random**
- **Must not contain default/example values**
- **Should be unique per environment**

### 3. Database Security

- Use strong database passwords
- Enable SSL/TLS for database connections
- Restrict database access by IP
- Regular security updates

### 4. Production Deployment Checklist

- [ ] Secure JWT secret configured
- [ ] Database credentials secured
- [ ] HTTPS/TLS enabled
- [ ] Security headers configured (automatically applied)
- [ ] Log monitoring setup
- [ ] Backup procedures in place
- [ ] Database encrypted at rest
- [ ] Network security configured

### 5. Security Headers

The application automatically applies these security headers:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `Referrer-Policy: strict-origin-when-cross-origin`

### 6. Logging and Monitoring

- All authentication events are logged
- Failed login attempts are tracked
- Database errors are logged internally (not exposed to users)
- Use structured logging for security monitoring

### 7. Error Handling

- No sensitive information exposed in error messages
- Standardized error response format
- Internal errors logged separately from user-facing messages

## Development vs Production

### Development

- Use `.env.example` as template
- Generate development-specific secrets
- Enable debug logging if needed

### Production

- Use environment-specific configuration
- Enable only necessary logging
- Implement proper monitoring
- Regular security audits
