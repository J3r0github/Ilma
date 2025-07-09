# JSON-Based Test Configuration System

## Overview

This system replaces the previous environment variable-based test configuration with a comprehensive JSON-based approach. The new system allows you to define a complete database state for testing, including users, classes, grades, attendance records, schedule events, messages, and permissions.

## Features

- **Comprehensive Test Data**: Define complete database state in a single JSON file
- **Data Validation**: Automatic validation of references between entities
- **Rollback on Shutdown**: All test data is automatically cleaned up when the server shuts down
- **Backward Compatibility**: Legacy environment variable system still works via wrapper functions
- **Relationship Management**: Automatically handles complex relationships between entities

## Configuration Files

### Test Configuration JSON (`test_config.json`)

The main configuration file that defines all test data:

```json
{
  "version": "1.0",
  "description": "Complete database state configuration for testing",
  "rollback_on_shutdown": true,
  "users": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "email": "admin.test@example.com",
      "password": "admin_test_password_123",
      "role": "principal",
      "is_superuser": true,
      "public_key": "TEST_ADMIN_PUBLIC_KEY"
    }
  ],
  "classes": [...],
  "grades": [...],
  "attendance": [...],
  "schedule_events": [...],
  "messages": [...],
  "threads": [...],
  "permissions": [...]
}
```

### Environment Configuration (`test_env_json.env`)

Environment variables for the new system:

```bash
# Enable testing mode
TESTING_MODE=true

# Path to test configuration file (optional)
TEST_CONFIG_PATH=test_config.json

# Other configuration...
```

## Usage

1. **Set up the environment**:

   ```bash
   cp test_env_json.env .env
   ```

2. **Customize test configuration**:
   Edit `test_config.json` to define your test data

3. **Start the server**:

   ```bash
   cargo run
   ```

4. **Test data lifecycle**:
   - Data is created at startup
   - Available during server operation
   - Automatically cleaned up on shutdown

## JSON Configuration Structure

### Users

```json
{
  "id": "uuid",
  "email": "string",
  "password": "plain_text_password",
  "role": "student|teacher|principal",
  "is_superuser": "boolean",
  "public_key": "string",
  "recovery_key": "optional_string",
  "encrypted_private_key_blob": "optional_string"
}
```

### Classes

```json
{
  "id": "uuid",
  "name": "string",
  "teacher_id": "uuid_reference_to_user",
  "students": ["uuid_array_of_student_ids"]
}
```

### Grades

```json
{
  "id": "uuid",
  "student_id": "uuid_reference_to_user",
  "class_id": "uuid_reference_to_class",
  "teacher_id": "uuid_reference_to_user",
  "grade": "string"
}
```

### Attendance

```json
{
  "id": "uuid",
  "student_id": "uuid_reference_to_user",
  "class_id": "uuid_reference_to_class",
  "status": "present|absent|late",
  "recorded_by": "uuid_reference_to_user"
}
```

### Schedule Events

```json
{
  "id": "uuid",
  "title": "string",
  "description": "optional_string",
  "start_time": "ISO8601_datetime",
  "end_time": "ISO8601_datetime",
  "date": "ISO8601_date",
  "class_id": "optional_uuid_reference_to_class",
  "teacher_id": "optional_uuid_reference_to_user"
}
```

### Messages and Threads

```json
{
  "threads": [
    {
      "id": "uuid",
      "participants": ["uuid_array_of_user_ids"]
    }
  ],
  "messages": [
    {
      "id": "uuid",
      "thread_id": "uuid_reference_to_thread",
      "sender_id": "uuid_reference_to_user",
      "ciphertext": "string",
      "encrypted_keys": [
        {
          "recipient_id": "uuid_reference_to_user",
          "encrypted_key": "string"
        }
      ]
    }
  ]
}
```

### Permissions

```json
{
  "user_id": "uuid_reference_to_user",
  "permission_ids": ["array_of_permission_ids"]
}
```

## Data Validation

The system automatically validates:

- **Reference Integrity**: All UUID references must point to existing entities
- **Role Consistency**: Teachers can only be assigned to classes they can teach
- **Relationship Validity**: Students can only be enrolled in existing classes
- **Permission Validity**: Only valid permission IDs can be assigned

## Error Handling

- **Configuration Errors**: Invalid JSON or missing files will prevent startup
- **Validation Errors**: Reference violations will be reported with detailed messages
- **Database Errors**: Database issues during test data creation will be logged

## Migration from Environment Variables

To migrate from the old system:

1. **Extract existing test users** from your `.env` file
2. **Convert to JSON format** using the structure above
3. **Add additional test data** as needed (classes, grades, etc.)
4. **Update environment file** to use `TEST_CONFIG_PATH`
5. **Test the configuration** by starting the server

## Benefits

- **Comprehensive Testing**: Define complete scenarios, not just users
- **Maintainability**: Single JSON file easier to manage than multiple environment variables
- **Validation**: Automatic validation prevents configuration errors
- **Flexibility**: Easy to add new test scenarios or modify existing ones
- **Documentation**: JSON structure serves as documentation of test data

## Example Test Scenarios

The provided `test_config.json` includes:

- 1 Admin user (principal)
- 1 Teacher user
- 2 Student users
- 2 Classes with student enrollments
- Grade records
- Attendance records
- Schedule events
- Message threads with encrypted messages
- Permission assignments

This creates a complete testing environment for all major system functions.
