# Ilma - Anti-Wilma MVP API v2

A school management backend API with GDPR-compliant E2E messaging, atomic permissions, multi-recipient encrypted messages, and modular access control.

## Features

- **JWT Authentication**: Secure token-based authentication
- **Role-based Access Control**: Student, Teacher, and Principal roles
- **Permission System**: Granular permission management
- **Class Management**: Create and manage classes with student enrollment
- **Grade Assignment**: Teachers can assign grades to students
- **Attendance Tracking**: Record student attendance
- **End-to-End Encrypted Messaging**: GDPR-compliant encrypted messaging between users
- **Rate Limiting**: Configurable global and per-endpoint rate limiting
- **PostgreSQL Database**: Robust data storage with migrations
- **OpenAPI Documentation**: Automatic API documentation with Swagger UI

## Tech Stack

- **Rust** with Actix Web framework
- **PostgreSQL** database with SQLx
- **JWT** for authentication
- **Argon2** for password hashing
- **OpenAPI 3.0** for API documentation

## Quick Start

### Prerequisites

- Rust (latest stable)
- PostgreSQL
- Git

### Installation

1. Clone the repository:

```bash
git clone <repository-url>
cd Ilma
```

2. Set up environment variables:

```bash
cp .env.example .env
# Edit .env with your database credentials and JWT secret
```

3. Start PostgreSQL and create a database:

```bash
createdb ilma_db
```

4. Run the application:

```bash
cargo run
```

The server will start at `http://localhost:8000`

### API Documentation

Once the server is running, you can access:

- **Swagger UI**: http://localhost:8000/swagger-ui/
- **OpenAPI JSON**: http://localhost:8000/api-docs/openapi.json

## Configuration

### Environment Variables

The application uses the following environment variables:

- `DATABASE_URL` - PostgreSQL connection string
- `JWT_SECRET` - Secret key for JWT tokens (minimum 32 characters)
- `BIND_ADDRESS` - Server bind address (default: 127.0.0.1:8000)
- `RUST_LOG` - Logging level (default: info)

### Rate Limiting

The application supports both global and per-endpoint rate limiting:

- `RATE_LIMIT_REQUESTS` - Global request limit per IP (default: 100)
- `RATE_LIMIT_WINDOW_SECONDS` - Global time window in seconds (default: 60)

For per-endpoint configuration, see [RATE_LIMITING.md](RATE_LIMITING.md) for detailed documentation.

## API Endpoints

### Authentication

- `POST /api/auth/login` - Login and get JWT token

### Users

- `GET /api/me` - Get current user info
- `POST /api/users` - Create a user (superuser/principal only)
- `GET /api/users/{id}/public_key` - Get user's public key

### Permissions

- `GET /api/permissions` - List all permissions
- `GET /api/permissions/sets` - List permission sets
- `GET /api/users/{id}/permissions` - Get user permissions
- `POST /api/users/{id}/permissions` - Assign permissions to user

### Classes

- `GET /api/classes` - List classes user is part of
- `POST /api/classes` - Create a new class (teacher only)
- `POST /api/classes/{class_id}/students` - Add student to class

### Grades

- `POST /api/grades` - Assign grade to student (teacher only)

### Attendance

- `POST /api/attendance` - Record attendance for student

### Messages (E2E Encrypted)

- `GET /api/messages/threads` - List message threads
- `POST /api/messages/threads` - Send encrypted message
- `GET /api/messages/threads/{thread_id}` - Get messages from thread

## Database Schema

The application automatically runs migrations on startup. The schema includes:

- **users**: User accounts with roles and public keys
- **permissions**: Available permissions
- **permission_sets**: Grouped permissions
- **user_permissions**: User-permission assignments
- **classes**: Class information
- **class_students**: Student-class relationships
- **grades**: Grade assignments
- **attendance**: Attendance records
- **threads**: Message threads
- **thread_participants**: Thread participation
- **messages**: Encrypted messages
- **message_encrypted_keys**: Per-recipient encrypted keys

## User Roles

- **Student**: Can view their classes, grades, and messages
- **Teacher**: Can create classes, assign grades, record attendance, and manage their students
- **Principal**: Has access to all functionality across the school

## Security Features

- **Password Security**: Argon2 password hashing
- **JWT Authentication**: Stateless authentication with configurable expiration
- **End-to-End Encryption**: Messages are encrypted client-side with per-recipient keys
- **Role-based Access**: Endpoint-level role validation
- **Permission System**: Granular permission management

## Documentation

- [API Testing Guide](API_TESTING.md) - How to test the API endpoints
- [Rate Limiting Configuration](RATE_LIMITING.md) - Detailed rate limiting setup
- [Rate Limiting Testing](RATE_LIMITING_TEST.md) - How to test rate limiting functionality
- [Environment-Based Test Users](ENVIRONMENT_BASED_TEST_USERS.md) - Configure test users via environment variables
- [Security Audit Report](SECURITY_AUDIT_REPORT.md) - Security analysis and recommendations

## Testing

### Environment-Based Test Users

The API supports dynamic test user creation based on environment variables, replacing hardcoded test credentials. This provides greater flexibility and security for testing different user roles and scenarios.

#### Quick Setup

1. Copy the example test environment:

   ```bash
   cp test_env_users.env .env
   ```

2. Start the server:

   ```bash
   cargo run
   ```

3. Test with configured credentials:
   ```bash
   curl -X POST http://localhost:8000/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email":"main.test@example.com","password":"main_test_password_123"}'
   ```

#### Configuration

Configure test users using environment variables:

```env
# Enable testing mode
TESTING_MODE=true

# Main test user (automatically Principal with superuser)
TEST_USERNAME=main_admin
TEST_EMAIL=admin@test.edu
TEST_PASSWORD=admin_secure_password

# Additional test users (TEST_USER_1 through TEST_USER_5)
TEST_USER_1_USERNAME=test_student
TEST_USER_1_EMAIL=student@test.edu
TEST_USER_1_PASSWORD=student_password
TEST_USER_1_ROLE=student

# Enable rate limiting bypass for test users
TEST_SKIP_RATE_LIMITS=true
```

For detailed configuration and security information, see [ENVIRONMENT_BASED_TEST_USERS.md](ENVIRONMENT_BASED_TEST_USERS.md).

⚠️ **Security Warning**: Only enable testing mode in development environments. Test users bypass security controls and should never be used in production.

## Development

### Building

```bash
cargo build --release
```

### Database Migrations

Migrations run automatically on startup. The database schema is created if it doesn't exist.

### Testing Rate Limiting

See [RATE_LIMITING_TEST.md](RATE_LIMITING_TEST.md) for testing instructions.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

[Add your license here]
