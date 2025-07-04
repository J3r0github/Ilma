# Ilma API Testing

This file contains example API calls to test the Ilma school management system.

## Prerequisites

1. Set up PostgreSQL and create a database called `ilma_db`
2. Copy `.env.example` to `.env` and update the database credentials
3. Run the server: `cargo run`

The server will run on `http://localhost:8000` by default.

## API Testing Examples

### 1. Health Check

The Swagger UI will be available at: http://localhost:8000/swagger-ui/

### 2. Create a Superuser (Manual Database Insert)

Since the first user needs to be created manually, you can insert a superuser directly into the database:

```sql
INSERT INTO users (id, username, email, password_hash, role, is_superuser, public_key)
VALUES (
    gen_random_uuid(),
    'admin',
    'admin@school.com',
    '$argon2id$v=19$m=19456,t=2,p=1$...',  -- Hash for 'password123'
    'principal',
    true,
    'base64-encoded-public-key-here'
);
```

### 3. Login

```bash
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@school.com",
    "password": "password123"
  }'
```

### 4. Get Current User Info

```bash
curl -X GET http://localhost:8000/api/me \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### 5. Create a Teacher

```bash
curl -X POST http://localhost:8000/api/users \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "username": "teacher1",
    "email": "teacher@school.com",
    "password": "teacher123",
    "role": "teacher",
    "public_key": "base64-encoded-public-key"
  }'
```

### 6. Create a Student

```bash
curl -X POST http://localhost:8000/api/users \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "username": "student1",
    "email": "student@school.com",
    "password": "student123",
    "role": "student",
    "public_key": "base64-encoded-public-key"
  }'
```

### 7. Create a Class

```bash
curl -X POST http://localhost:8000/api/classes \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TEACHER_JWT_TOKEN" \
  -d '{
    "name": "Mathematics 101"
  }'
```

### 8. Add Student to Class

```bash
curl -X POST http://localhost:8000/api/classes/{class_id}/students \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TEACHER_JWT_TOKEN" \
  -d '{
    "student_id": "student-uuid-here"
  }'
```

### 9. Assign Grade

```bash
curl -X POST http://localhost:8000/api/grades \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TEACHER_JWT_TOKEN" \
  -d '{
    "student_id": "student-uuid-here",
    "class_id": "class-uuid-here",
    "grade": "A"
  }'
```

### 10. Record Attendance

```bash
curl -X POST http://localhost:8000/api/attendance \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TEACHER_JWT_TOKEN" \
  -d '{
    "student_id": "student-uuid-here",
    "class_id": "class-uuid-here",
    "status": "present"
  }'
```

### 11. Send Encrypted Message

```bash
curl -X POST http://localhost:8000/api/messages/threads \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "participant_ids": ["sender-uuid", "recipient-uuid"],
    "ciphertext": "base64-encoded-encrypted-message",
    "encrypted_keys": [
      {
        "recipient_id": "recipient-uuid",
        "encrypted_key": "base64-encoded-encrypted-symmetric-key"
      }
    ]
  }'
```

### 12. List Message Threads

```bash
curl -X GET http://localhost:8000/api/messages/threads \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### 13. Get Messages from Thread

```bash
curl -X GET http://localhost:8000/api/messages/threads/{thread_id} \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## Testing with a Test Client

You can also test the API using tools like:

- Postman
- Insomnia
- Thunder Client (VS Code extension)
- curl (as shown above)

The Swagger UI at http://localhost:8000/swagger-ui/ provides an interactive interface for testing all endpoints.

## Database Schema

The application automatically creates all necessary tables on startup. The schema includes:

- Users with roles (student, teacher, principal)
- Permission system
- Classes and student enrollment
- Grades and attendance records
- End-to-end encrypted messaging system

## Security Features

- Argon2 password hashing
- JWT authentication
- Role-based access control
- End-to-end encrypted messaging
- GDPR-compliant data handling
