# E2E Encrypted Messaging API Example

# This file demonstrates how to use the Ilma messaging API for encrypted communication

## Test Data Overview

The test configuration includes these pre-configured users for testing:

### Users:

- **Admin**: `admin@test.edu` / `admin123` (ID: `550e8400-e29b-41d4-a716-446655440000`)
- **Teacher**: `teacher@test.edu` / `teacher123` (ID: `550e8400-e29b-41d4-a716-446655440001`)
- **Student1**: `student1@example.com` / `student123` (ID: `550e8400-e29b-41d4-a716-446655440002`)
- **Student2**: `student2@test.edu` / `student123` (ID: `550e8400-e29b-41d4-a716-446655440003`)

### Pre-configured Message Threads:

1. **Teacher-Students Thread** (`bb0e8400-e29b-41d4-a716-446655440000`)

   - Participants: Teacher, Student1, Student2
   - Contains: 1 message from teacher

2. **Teacher-Admin Direct Thread** (`bb0e8400-e29b-41d4-a716-446655440001`)

   - Participants: Teacher, Admin
   - Contains: 2 messages (teacher -> admin, admin -> teacher)

3. **Admin-Staff Broadcast Thread** (`bb0e8400-e29b-41d4-a716-446655440002`)
   - Participants: Admin, Teacher
   - Contains: 1 admin broadcast message

## API Endpoints for E2E Messaging

### 1. Authentication

```bash
# Login as teacher
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "teacher@test.edu",
    "password": "teacher123"
  }'

# Login as admin
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@test.edu",
    "password": "admin123"
  }'
```

### 2. List Message Threads (for authenticated user)

```bash
# List threads for teacher
curl -X GET http://localhost:8080/api/messages/threads \
  -H "Authorization: Bearer YOUR_TEACHER_JWT_TOKEN"

# List threads for admin
curl -X GET http://localhost:8080/api/messages/threads \
  -H "Authorization: Bearer YOUR_ADMIN_JWT_TOKEN"
```

### 3. Send Encrypted Message (Teacher to Admin)

```bash
curl -X POST http://localhost:8080/api/messages/threads \
  -H "Authorization: Bearer YOUR_TEACHER_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "participant_ids": ["550e8400-e29b-41d4-a716-446655440000"],
    "ciphertext": "encrypted_message_content_here",
    "encrypted_keys": [
      {
        "recipient_id": "550e8400-e29b-41d4-a716-446655440000",
        "encrypted_key": "admin_encrypted_symmetric_key"
      },
      {
        "recipient_id": "550e8400-e29b-41d4-a716-446655440001",
        "encrypted_key": "teacher_self_encrypted_symmetric_key"
      }
    ]
  }'
```

### 4. Send Encrypted Reply (Admin to Teacher)

```bash
curl -X POST http://localhost:8080/api/messages/threads \
  -H "Authorization: Bearer YOUR_ADMIN_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "participant_ids": ["550e8400-e29b-41d4-a716-446655440001"],
    "ciphertext": "encrypted_reply_content_here",
    "encrypted_keys": [
      {
        "recipient_id": "550e8400-e29b-41d4-a716-446655440001",
        "encrypted_key": "teacher_encrypted_symmetric_key"
      },
      {
        "recipient_id": "550e8400-e29b-41d4-a716-446655440000",
        "encrypted_key": "admin_self_encrypted_symmetric_key"
      }
    ]
  }'
```

### 5. Get Messages from Specific Thread

```bash
# Get messages from teacher-admin thread
curl -X GET http://localhost:8080/api/messages/threads/bb0e8400-e29b-41d4-a716-446655440001 \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# With pagination
curl -X GET "http://localhost:8080/api/messages/threads/bb0e8400-e29b-41d4-a716-446655440001?limit=10&before=MESSAGE_ID" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## Expected API Responses

### Successful Message Send Response:

```json
{
  "message": "Message sent successfully",
  "thread_id": "550e8400-e29b-41d4-a716-446655440000",
  "message_id": "aa0e8400-e29b-41d4-a716-446655440000"
}
```

### Thread List Response:

```json
[
  {
    "thread_id": "bb0e8400-e29b-41d4-a716-446655440001",
    "last_message_preview": "encrypted_admin_reply_to_teacher",
    "last_message_at": "2025-01-15T12:30:00Z"
  }
]
```

### Thread Messages Response:

```json
[
  {
    "id": "aa0e8400-e29b-41d4-a716-446655440002",
    "thread_id": "bb0e8400-e29b-41d4-a716-446655440001",
    "sender_id": "550e8400-e29b-41d4-a716-446655440000",
    "sent_at": "2025-01-15T12:30:00Z",
    "ciphertext": "encrypted_admin_reply_to_teacher",
    "encrypted_keys": [
      {
        "recipient_id": "550e8400-e29b-41d4-a716-446655440001",
        "encrypted_key": "encrypted_key_for_teacher_from_admin"
      },
      {
        "recipient_id": "550e8400-e29b-41d4-a716-446655440000",
        "encrypted_key": "encrypted_key_for_admin_self"
      }
    ]
  },
  {
    "id": "aa0e8400-e29b-41d4-a716-446655440001",
    "thread_id": "bb0e8400-e29b-41d4-a716-446655440001",
    "sender_id": "550e8400-e29b-41d4-a716-446655440001",
    "sent_at": "2025-01-15T12:00:00Z",
    "ciphertext": "encrypted_teacher_to_admin_message_1",
    "encrypted_keys": [
      {
        "recipient_id": "550e8400-e29b-41d4-a716-446655440000",
        "encrypted_key": "encrypted_key_for_admin_from_teacher"
      },
      {
        "recipient_id": "550e8400-e29b-41d4-a716-446655440001",
        "encrypted_key": "encrypted_key_for_teacher_self"
      }
    ]
  }
]
```

## Running the Tests

### Prerequisites

The E2E tests require specific environment variables to be set:

```bash
TESTING_MODE=true
JWT_SECRET=your-secret-key-here
DATABASE_URL=postgresql://dbuser:dbuser@localhost/ilma_db  # optional
TEST_CONFIG_PATH=test_config.json  # optional
```

### Option 1: Run the automated test suite (Recommended)

```powershell
# From the project root directory (sets environment variables automatically):
.\run_message_tests.ps1
```

### Option 2: Run individual tests manually

```bash
# Set environment variables first
export TESTING_MODE=true
export JWT_SECRET=test-secret-key-that-is-long-enough-for-testing-purposes

# Test authentication
cargo test test_login_teacher_and_admin --test message_e2e_tests -- --nocapture

# Test complete E2E flow
cargo test test_complete_e2e_conversation --test message_e2e_tests -- --nocapture
```

### Option 3: Start the server and test manually

```bash
# Start the Ilma server
cargo run

# Use the curl commands above to test the API endpoints manually
```

## Key Features Demonstrated

✅ **End-to-End Encryption**: All message content is encrypted with recipient-specific keys
✅ **Multi-User Threads**: Support for group conversations with multiple participants  
✅ **Bidirectional Communication**: Both teacher and admin can send/receive messages
✅ **Thread Management**: Automatic thread creation and participant management
✅ **Pagination Support**: Cursor-based pagination for message history
✅ **Authentication**: JWT-based authentication for all endpoints
✅ **Data Validation**: Proper validation of user IDs and message format
✅ **Database Transactions**: Atomic operations for message creation

The system is now ready for testing E2E encrypted communication between teachers and administrators!
