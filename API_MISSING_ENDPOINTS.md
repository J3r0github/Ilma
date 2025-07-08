# Missing API Endpoints

(c) 2025 Jero Lampila / (the Interactive Learning Management Appplication (ILMA / Anti-Wilma)) project
This document lists the API endpoints that are missing from the current implementation but are needed for full GUI functionality.

## Summary of Current Implementation Status

**✅ Currently Implemented:** 45+ endpoints
**❌ Missing:** 35+ endpoints for full functionality

### Key Areas Well Covered:

- **Authentication**: Login, password reset ✅
- **User Management**: Create, read, update, delete, search users ✅
- **Classes**: Full CRUD operations, student management, teacher details ✅
- **Messages**: Thread management, send/receive ✅
- **Grades**: Full CRUD operations, filtering by student/class ✅
- **Attendance**: Full CRUD operations, filtering by student/class/date ✅
- **Schedule**: Create, read, update, delete events ✅

### Major Missing Areas:

- **File Management** (completely missing)
- **Dashboard/Analytics** (completely missing)
- **Notifications** (completely missing)
- **Advanced Authentication** (2FA, session management)
- **Messaging Enhancements** (participant management, read status)

---

This document lists the API endpoints that are missing from the current implementation but are needed for full GUI functionality.

## Classes Management

### Recently Implemented Endpoints:

✅ **PUT /api/classes/{id}** - Update class information (implemented)
✅ **DELETE /api/classes/{id}** - Delete a class (implemented)
✅ **GET /api/classes/{id}/teacher** - Get teacher details for a class (implemented)

### Existing Endpoints:

✅ **GET /api/classes** - List classes (implemented)
✅ **POST /api/classes** - Create class (implemented)
✅ **POST /api/classes/{class_id}/students** - Add student to class (implemented)
✅ **GET /api/classes/{id}/students** - Get list of students in a class (implemented)
✅ **DELETE /api/classes/{id}/students/{studentId}** - Remove student from class (implemented)

### Missing Endpoints:

1. **GET /api/classes/{id}/schedule** - Get class schedule details
2. **PUT /api/classes/{id}/schedule** - Update class schedule

### Missing Fields in Class Model:

- `code` - Class code (e.g., "MAT101")
- `description` - Class description
- `credits` - Number of credits
- `room` - Classroom location
- `schedule` - Class schedule (times, days)
- `semester` - Current semester
- `student_count` - Number of enrolled students
- `teacher_name` - Teacher display name (currently only teacher_id)

## Messages System

### Missing Endpoints:

1. **GET /api/messages/threads/{threadId}/participants** - Get thread participants
2. **POST /api/messages/threads/{threadId}/participants** - Add participant to thread
3. **DELETE /api/messages/threads/{threadId}/participants/{userId}** - Remove participant from thread
4. **PUT /api/messages/threads/{threadId}/messages/{messageId}** - Mark message as read
5. **GET /api/messages/unread-count** - Get count of unread messages
6. **DELETE /api/messages/threads/{threadId}** - Delete thread
7. **GET /api/messages/search** - Search messages

### Existing Endpoints:

✅ **GET /api/messages/threads** - List message threads (implemented)
✅ **POST /api/messages/threads** - Send message (implemented)
✅ **GET /api/messages/threads/{thread_id}** - Get thread messages (implemented)

### Missing Fields:

- Messages need better structure for display (subject, formatted content)
- Thread previews need participant names (currently only IDs)
- Message read status per user
- Message priority/importance levels

## User Management

### Recently Implemented Endpoints:

✅ **GET /api/users/{id}** - Get user details (implemented)
✅ **PUT /api/users/{id}** - Update user information (implemented)
✅ **DELETE /api/users/{id}** - Delete user (implemented)
✅ **GET /api/users/search** - Search users by name/email (implemented)

### Existing Endpoints:

✅ **GET /api/me** - Get current user (implemented)
✅ **POST /api/users** - Create user (implemented)
✅ **GET /api/users** - Get list of all users (implemented)
✅ **GET /api/users/{id}/permissions** - Get user permissions (implemented)
✅ **POST /api/users/{id}/permissions** - Assign user permissions (implemented)
✅ **GET /api/users/{id}/public_key** - Get user public key (implemented)
✅ **GET /api/user/public-key/{username}** - Get user public key by username (implemented)
✅ **GET /api/user/recovery-key/{username}** - Get recovery key (implemented)
✅ **POST /api/user/set-recovery-key** - Set recovery key (implemented)

### Missing Endpoints:

1. **POST /api/users/{id}/avatar** - Upload user avatar

### Missing Fields:

**Important additions:**

For **Students**:

- `first_names` - All first names (can be multiple, e.g., "Anna Maria")
- `chosen_name` - Student's chosen/preferred name (should be shown on dashboards and in the UI)
- `last_name` - Student's last name
- `birthday` - Student's date of birth
- `ssn` - Finnish personal identity number (Henkilötunnus)
- `learner_number` - National learner number (e.g., 1.2.246.562.24.XXXXXXXXXXX)
- `person_oid` - Person OID identifier (this, too is: 1.2.246.562.24.XXXXXXXXXXX)

For **Teachers and Employees**:

- `name_short` - Customizable short name for teachers (e.g., "ESO" for Erkki Esimerkki, "MAN" for Mandy Mansikka)
  - Should be customizable by teachers
  - Length should be configurable per school

**Other missing fields:**

- `avatar_url` - Profile picture URL
- `phone` - Phone number
- `address` - User address
- `enrollment_date` - When student enrolled
- `graduation_date` - Expected graduation date

## Schedule Management

### Recently Implemented Endpoints:

✅ **PUT /api/schedule/events/{id}** - Update calendar event (implemented)
✅ **DELETE /api/schedule/events/{id}** - Delete calendar event (implemented)

### Existing Endpoints:

✅ **GET /api/schedule** - Get user's personal schedule (implemented)
✅ **POST /api/schedule** - Create calendar event (implemented)

### Missing Endpoints:

1. **GET /api/schedule/class/{classId}** - Get class schedule
2. **GET /api/schedule/conflicts** - Check for schedule conflicts

### Missing Models:

- Enhanced `Event` model with conflict detection
- `TimeSlot` model for class scheduling

## Grades & Assessment

### Recently Implemented Endpoints:

✅ **GET /api/grades/student/{studentId}** - Get all grades for a student (implemented)
✅ **GET /api/grades/class/{classId}** - Get all grades for a class (implemented)
✅ **PUT /api/grades/{id}** - Update grade (implemented)
✅ **DELETE /api/grades/{id}** - Delete grade (implemented)

### Existing Endpoints:

✅ **POST /api/grades** - Assign grade (implemented)
✅ **GET /api/grades** - Get grades with filtering (implemented)

### Missing Endpoints:

1. **GET /api/grades/statistics** - Get grade statistics
2. **POST /api/grades/bulk** - Bulk grade assignment

### Missing Fields in Grade Model:

- `assignment_name` - Name of assignment
- `assignment_type` - Type (exam, homework, quiz, etc.)
- `weight` - Grade weight for final calculation
- `comments` - Teacher comments
- `max_points` - Maximum possible points
- `points_earned` - Points earned

## Attendance System

### Recently Implemented Endpoints:

✅ **GET /api/attendance/student/{studentId}** - Get attendance for student (implemented)
✅ **GET /api/attendance/class/{classId}** - Get attendance for class (implemented)
✅ **GET /api/attendance/class/{classId}/date/{date}** - Get attendance for specific date (implemented)
✅ **PUT /api/attendance/{id}** - Update attendance record (implemented)
✅ **DELETE /api/attendance/{id}** - Delete attendance record (implemented)

### Existing Endpoints:

✅ **POST /api/attendance** - Record attendance (implemented)
✅ **GET /api/attendance** - Get attendance with filtering (implemented)

### Missing Endpoints:

1. **GET /api/attendance/statistics** - Get attendance statistics

### Missing Fields:

- `notes` - Additional notes about attendance
- `excuse` - Excuse for absence
- `parent_notified` - Whether parent was notified

## Authentication & Authorization

### Missing Endpoints:

1. **POST /api/auth/logout** - Logout user
2. **POST /api/auth/change-password** - Change password
3. **GET /api/auth/sessions** - Get active sessions
4. **DELETE /api/auth/sessions/{id}** - Revoke session
5. **POST /api/auth/2fa/enable** - Enable 2FA
6. **POST /api/auth/2fa/disable** - Disable 2FA

### Existing Endpoints:

✅ **POST /api/auth/login** - Login (implemented)
✅ **POST /api/auth/request-password-reset** - Request password reset (implemented)
✅ **POST /api/auth/reset-password** - Reset password (implemented)

### Existing Permission Endpoints:

✅ **GET /api/permissions** - List permissions (implemented)
✅ **GET /api/permissions/sets** - List permission sets (implemented)

## Notifications

### Missing Endpoints:

1. **GET /api/notifications** - Get user notifications
2. **POST /api/notifications** - Create notification
3. **PUT /api/notifications/{id}/read** - Mark notification as read
4. **DELETE /api/notifications/{id}** - Delete notification
5. **GET /api/notifications/settings** - Get notification preferences
6. **PUT /api/notifications/settings** - Update notification preferences

### Missing Models:

- `Notification` - System notifications
- `NotificationSettings` - User notification preferences

## File Management

### Missing Endpoints:

1. **POST /api/files/upload** - Upload file
2. **GET /api/files/{id}** - Download file
3. **DELETE /api/files/{id}** - Delete file
4. **GET /api/files/class/{classId}** - Get class files
5. **POST /api/files/class/{classId}** - Upload file to class

### Missing Models:

- `File` - File metadata
- `FilePermission` - File access permissions

## Dashboard & Analytics

### Missing Endpoints:

1. **GET /api/dashboard/stats** - Get dashboard statistics
2. **GET /api/dashboard/recent-activity** - Get recent activities
3. **GET /api/dashboard/announcements** - Get announcements
4. **GET /api/reports/grades** - Grade reports
5. **GET /api/reports/attendance** - Attendance reports

## Additional Findings from GUI Integration

### Schedule Management (Updated)

Based on the schedule page implementation, the following endpoints are required:

- **GET /api/schedule** - Get schedule events with date filtering
- **POST /api/schedule/events** - Create new schedule events
- **PUT /api/schedule/events/{id}** - Update existing events
- **DELETE /api/schedule/events/{id}** - Delete events

### Messages System (Updated)

The messages page needs:

- Better integration with thread-based messaging
- Support for message subjects and rich content
- Read/unread status tracking per user
- Message composition with participant selection

### GUI-Specific Requirements

#### Common Issues Found:

1. **Pagination**: Most lists need pagination support
2. **Search**: Search functionality needs backend endpoints
3. **Filtering**: Advanced filtering options need API support
4. **Sorting**: Sort options need backend implementation
5. **Real-time Updates**: WebSocket or polling for live updates

#### CSS and Styling:

- Some components use inline styles which need to be moved to CSS classes
- Accessibility improvements needed (ARIA labels, titles)
- Better responsive design support

#### Error Handling:

- Consistent error messages across all endpoints
- Loading states for all async operations
- Retry mechanisms for failed API calls

## Implementation Priority

### High Priority (Core Functionality):

1. Classes management (student lists, teacher details)
2. Messages system (thread participants, message status)
3. Schedule management (complete CRUD operations)
4. User management (search, profile updates)

### Medium Priority (Enhanced Features):

1. Grades and attendance statistics
2. File upload and management
3. Notifications system
4. Dashboard analytics

### Low Priority (Advanced Features):

1. Advanced reporting
2. Bulk operations
3. Advanced search
4. Third-party integrations

## Notes

- Many endpoints would benefit from pagination, filtering, and sorting parameters
- Error handling and validation need to be consistent across all endpoints
- API responses should include proper HTTP status codes and error messages
- Consider implementing API versioning for future compatibility
- Add rate limiting for security
- Implement proper logging and monitoring
