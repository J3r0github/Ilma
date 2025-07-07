# Missing API Endpoints Documentation

This document lists API endpoints that are needed by the UI but are not present in the current OpenAPI specification (`ilma-OpenAPI.yml`).

## Schedule Endpoints

### GET /api/schedule

**Description:** Get schedule events for classes or students
**Parameters:**

- `class_id` (optional): Filter by class ID
- `student_id` (optional): Filter by student ID
- `date_from` (optional): Filter events from this date
- `date_to` (optional): Filter events to this date

**Response:**

```json
[
  {
    "id": "string",
    "title": "string",
    "description": "string",
    "start_time": "string (ISO 8601)",
    "end_time": "string (ISO 8601)",
    "date": "string (YYYY-MM-DD)",
    "class_id": "string",
    "created_at": "string (ISO 8601)"
  }
]
```

### POST /api/schedule

**Description:** Create a new schedule event
**Request Body:**

```json
{
  "title": "string",
  "description": "string (optional)",
  "start_time": "string (ISO 8601)",
  "end_time": "string (ISO 8601)",
  "date": "string (YYYY-MM-DD)",
  "class_id": "string"
}
```

- `email` (optional): Filter by email
- `role` (optional): Filter by role
- **Response**: Array of User objects
- **Usage**: Used for user search functionality in various components

## Class Management Endpoints

### GET /api/classes/{class_id}/students

- **Purpose**: Get students in a specific class
- **Method**: GET
- **Authentication**: Required (Bearer token)
- **Path Parameters**:
  - `class_id`: UUID of the class
- **Response**: Array of User objects (students)
- **Usage**: Used in classes page to display students in each class

### DELETE /api/classes/{class_id}/students/{student_id}

- **Purpose**: Remove a student from a class
- **Method**: DELETE
- **Authentication**: Required (Bearer token)
- **Path Parameters**:
  - `class_id`: UUID of the class
  - `student_id`: UUID of the student
- **Response**: 204 No Content
- **Usage**: Used in classes page to remove students from classes

## Grade Management Endpoints

### GET /api/grades

- **Purpose**: Get grades with optional filtering
- **Method**: GET
- **Authentication**: Required (Bearer token)
- **Query Parameters**:
  - `student_id` (optional): Filter by student
  - `class_id` (optional): Filter by class
- **Response**: Array of Grade objects
- **Usage**: Used to display grades in various components

## Attendance Management Endpoints

### GET /api/attendance

- **Purpose**: Get attendance records with optional filtering
- **Method**: GET
- **Authentication**: Required (Bearer token)
- **Query Parameters**:
  - `student_id` (optional): Filter by student
  - `class_id` (optional): Filter by class
  - `date` (optional): Filter by date
- **Response**: Array of Attendance objects
- **Usage**: Used to display attendance records

## Schedule Management Endpoints

### GET /api/schedule

- **Purpose**: Get schedule/calendar events
- **Method**: GET
- **Authentication**: Required (Bearer token)
- **Query Parameters**:
  - `class_id` (optional): Filter by class
  - `student_id` (optional): Filter by student
  - `date_from` (optional): Start date filter
  - `date_to` (optional): End date filter
- **Response**: Array of ScheduleEvent objects
- **Usage**: Used in schedule page to display calendar events

### POST /api/schedule

- **Purpose**: Create a new schedule event
- **Method**: POST
- **Authentication**: Required (Bearer token)
- **Request Body**: ScheduleEvent object
- **Response**: 201 Created
- **Usage**: Used to create new schedule events

## Authentication Endpoints

### POST /api/auth/request-password-reset

- **Purpose**: Request password reset
- **Method**: POST
- **Request Body**: `{ "email": "user@example.com" }`
- **Response**: 200 OK
- **Usage**: Used in password reset functionality

## Additional Type Definitions Needed

The following TypeScript interfaces should be added to `types/api.ts` to support the missing endpoints:

```typescript
export interface ScheduleEvent {
  id: string;
  title: string;
  description?: string;
  start_time: string;
  end_time: string;
  class_id?: string;
  teacher_id?: string;
  created_at: string;
  updated_at: string;
}

export interface CreateScheduleEventRequest {
  title: string;
  description?: string;
  start_time: string;
  end_time: string;
  class_id?: string;
}

export interface UserSearchParams {
  username?: string;
  email?: string;
  role?: UserRole;
}

export interface GradeSearchParams {
  student_id?: string;
  class_id?: string;
}

export interface AttendanceSearchParams {
  student_id?: string;
  class_id?: string;
  date?: string;
}

export interface ScheduleSearchParams {
  class_id?: string;
  student_id?: string;
  date_from?: string;
  date_to?: string;
}
```

## Implementation Priority

1. **High Priority**: User listing/search endpoints (needed for message composition)
2. **High Priority**: Class student management endpoints (needed for class management)
3. **Medium Priority**: Grade and attendance query endpoints (needed for reporting)
4. **Medium Priority**: Schedule management endpoints (needed for calendar functionality)
5. **Low Priority**: Password reset endpoint (nice to have)

## Security Considerations

- All endpoints should require authentication
- User listing endpoints should be restricted based on user role:
  - Students: Can only see users in their classes
  - Teachers: Can see students in their classes and other teachers
  - Principals: Can see all users
- Grade and attendance endpoints should respect privacy rules
- Schedule endpoints should follow similar access control patterns
