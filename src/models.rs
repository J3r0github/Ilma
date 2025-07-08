use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema, sqlx::Type)]
#[sqlx(type_name = "user_role", rename_all = "lowercase")]
pub enum UserRole {
    #[serde(rename = "student")]
    Student,
    #[serde(rename = "teacher")]
    Teacher,
    #[serde(rename = "principal")]
    Principal,
}

#[derive(Debug, Serialize, Deserialize, FromRow, ToSchema)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub role: UserRole,
    pub is_superuser: bool,
    pub public_key: String,
    #[serde(skip)]
    pub password_hash: String,
    #[serde(skip)]
    pub recovery_key: Option<String>,
    #[serde(skip)]
    pub encrypted_private_key_blob: Option<String>,
    
    // Name fields for students
    pub first_names: Option<String>,
    pub chosen_name: Option<String>,
    pub last_name: Option<String>,
    
    // Teacher-specific fields
    pub name_short: Option<String>,
    
    // Personal information
    pub birthday: Option<chrono::NaiveDate>,
    pub ssn: Option<String>,
    pub learner_number: Option<String>,
    pub person_oid: Option<String>,
    pub avatar_url: Option<String>,
    pub phone: Option<String>,
    pub address: Option<String>,
    pub enrollment_date: Option<chrono::NaiveDate>,
    pub graduation_date: Option<chrono::NaiveDate>,
    
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Permission {
    pub id: i32,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct PermissionSet {
    pub id: i32,
    pub name: String,
    pub permissions: Vec<Permission>,
}

#[derive(Debug, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Class {
    pub id: Uuid,
    pub name: String,
    pub teacher_id: Uuid,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Thread {
    pub id: Uuid,
    pub participants: Vec<Uuid>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, FromRow, ToSchema)]
pub struct ThreadPreview {
    pub thread_id: Uuid,
    pub last_message_preview: String,
    pub last_message_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EncryptedKey {
    pub recipient_id: Uuid,
    pub encrypted_key: String,
}

#[derive(Debug, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Message {
    pub id: Uuid,
    pub thread_id: Uuid,
    pub sender_id: Uuid,
    pub sent_at: DateTime<Utc>,
    pub ciphertext: String,
    #[sqlx(skip)]
    pub encrypted_keys: Vec<EncryptedKey>,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct MessageEncryptedKey {
    pub message_id: Uuid,
    pub recipient_id: Uuid,
    pub encrypted_key: String,
}

#[derive(Debug, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Grade {
    pub id: Uuid,
    pub student_id: Uuid,
    pub class_id: Uuid,
    pub teacher_id: Uuid,
    pub grade: String,
    pub assigned_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Attendance {
    pub id: Uuid,
    pub student_id: Uuid,
    pub class_id: Uuid,
    pub status: AttendanceStatus,
    pub recorded_at: DateTime<Utc>,
    pub recorded_by: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, sqlx::Type)]
#[sqlx(type_name = "attendance_status", rename_all = "lowercase")]
pub enum AttendanceStatus {
    #[serde(rename = "present")]
    Present,
    #[serde(rename = "absent")]
    Absent,
    #[serde(rename = "late")]
    Late,
}

#[derive(Debug, Serialize, Deserialize, FromRow, ToSchema)]
pub struct ScheduleEvent {
    pub id: Uuid,
    pub title: String,
    pub description: Option<String>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub date: chrono::NaiveDate,
    pub class_id: Option<Uuid>,
    pub teacher_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// Request DTOs
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct PasswordResetRequest {
    pub email: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ResetPasswordRequest {
    pub reset_token: String,
    pub new_password_hash: String,
    pub encrypted_private_key_blob: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct SetRecoveryKeyRequest {
    pub email: String,
    pub recovery_key: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
    pub role: UserRole,
    pub public_key: String,
    // Personal information fields
    pub first_names: Option<String>,
    pub chosen_name: Option<String>,
    pub last_name: Option<String>,
    pub name_short: Option<String>, // For teachers
    pub birthday: Option<chrono::NaiveDate>,
    pub ssn: Option<String>,
    pub learner_number: Option<String>,
    pub person_oid: Option<String>,
    pub avatar_url: Option<String>,
    pub phone: Option<String>,
    pub address: Option<String>,
    pub enrollment_date: Option<chrono::NaiveDate>, // For students only
    pub graduation_date: Option<chrono::NaiveDate>, // For students only
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateUserRequest {
    pub first_names: Option<String>,
    pub chosen_name: Option<String>,
    pub last_name: Option<String>,
    pub name_short: Option<String>,
    pub phone: Option<String>,
    pub address: Option<String>,
    pub avatar_url: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AssignPermissionsRequest {
    pub permission_ids: Vec<i32>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateClassRequest {
    pub name: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateClassRequest {
    pub name: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AddStudentRequest {
    pub student_id: Uuid,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AssignGradeRequest {
    pub student_id: Uuid,
    pub class_id: Uuid,
    pub grade: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateGradeRequest {
    pub grade: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RecordAttendanceRequest {
    pub student_id: Uuid,
    pub class_id: Uuid,
    pub status: AttendanceStatus,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateAttendanceRequest {
    pub status: AttendanceStatus,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SendMessageRequest {
    pub participant_ids: Vec<Uuid>,
    pub ciphertext: String,
    pub encrypted_keys: Vec<EncryptedKey>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateScheduleEventRequest {
    pub title: String,
    pub description: Option<String>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub date: chrono::NaiveDate,
    pub class_id: Option<Uuid>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateScheduleEventRequest {
    pub title: String,
    pub description: Option<String>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub date: chrono::NaiveDate,
}

// Response DTOs
#[derive(Debug, Serialize, ToSchema)]
pub struct RecoveryKeyResponse {
    pub recovery_key: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LoginResponse {
    pub token: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PublicKeyResponse {
    pub public_key: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorResponse {
    pub error: String,
}

// JWT Claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // User ID
    pub email: String,
    pub role: UserRole,
    pub is_superuser: bool,
    pub exp: usize,
    pub is_testing: Option<bool>, // For testing mode
}

#[derive(Debug, Serialize, Deserialize, FromRow, ToSchema)]
pub struct PasswordResetToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub used: bool,
}

// Query parameter DTOs
#[derive(Debug, Deserialize, ToSchema)]
pub struct PaginationQuery {
    pub limit: Option<i32>,
    pub offset: Option<i32>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct MessagePaginationQuery {
    pub limit: Option<i32>,
    pub before: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UserSearchParams {
    pub name: Option<String>, // Search by any name field (first_names, chosen_name, last_name, name_short)
    pub email: Option<String>,
    pub role: Option<UserRole>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct GradeSearchParams {
    pub student_id: Option<Uuid>,
    pub class_id: Option<Uuid>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AttendanceSearchParams {
    pub student_id: Option<Uuid>,
    pub class_id: Option<Uuid>,
    pub date: Option<chrono::NaiveDate>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ScheduleSearchParams {
    pub class_id: Option<Uuid>,
    pub student_id: Option<Uuid>,
    pub date_from: Option<chrono::NaiveDate>,
    pub date_to: Option<chrono::NaiveDate>,
}
