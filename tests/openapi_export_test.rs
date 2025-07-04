// This test file is used to export the OpenAPI specification for the Ilma API.
// It's not necessarily a unit test, but rather an integration test that generates the OpenAPI spec and writes it to a file.
// This is simply convienient to run as a test to ensure the OpenAPI spec is always up-to-date.
use std::fs;
use utoipa::OpenApi;

// We need to recreate the ApiDoc struct here since it's not exported from the main crate
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Ilma API",
        version = "1.0.0",
        description = "School management system API with end-to-end encryption for messaging. Currently under development.",
        contact(
            name = "API Support / Developer",
            email = "jero.lampila@gmail.com"
        )
    ),
    paths(
        ilma::auth::login,
        ilma::auth::request_password_reset,
        ilma::auth::reset_password,
        ilma::handlers::users::get_me,
        ilma::handlers::users::create_user,
        ilma::handlers::users::get_user_public_key,
        ilma::handlers::users::get_recovery_key,
        ilma::handlers::users::set_recovery_key,
        ilma::handlers::users::get_user_public_key_by_username,
        ilma::handlers::permissions::list_permissions,
        ilma::handlers::permissions::list_permission_sets,
        ilma::handlers::permissions::get_user_permissions,
        ilma::handlers::permissions::assign_user_permissions,
        ilma::handlers::classes::list_classes,
        ilma::handlers::classes::create_class,
        ilma::handlers::classes::add_student_to_class,
        ilma::handlers::grades::assign_grade,
        ilma::handlers::attendance::record_attendance,
        ilma::handlers::messages::list_threads,
        ilma::handlers::messages::send_message,
        ilma::handlers::messages::get_thread_messages,
    ),
    components(
        schemas(
            ilma::User, ilma::UserRole, ilma::Permission, ilma::PermissionSet, ilma::Class, ilma::Thread, 
            ilma::ThreadPreview, ilma::Message, ilma::EncryptedKey, ilma::Grade, ilma::Attendance, ilma::AttendanceStatus,
            ilma::LoginRequest, ilma::CreateUserRequest, ilma::PasswordResetRequest, ilma::ResetPasswordRequest, 
            ilma::SetRecoveryKeyRequest, ilma::AssignPermissionsRequest, ilma::CreateClassRequest, 
            ilma::AddStudentRequest, ilma::AssignGradeRequest, ilma::RecordAttendanceRequest, 
            ilma::SendMessageRequest, ilma::LoginResponse, ilma::RecoveryKeyResponse, ilma::PublicKeyResponse, 
            ilma::PasswordResetToken, ilma::ErrorResponse, ilma::PaginationQuery, ilma::MessagePaginationQuery
        )
    ),
    tags(
        (name = "auth", description = "Authentication and authorization endpoints"),
        (name = "users", description = "User management and profile operations"),
        (name = "permissions", description = "Permission and role management"),
        (name = "classes", description = "Class creation and student management"),
        (name = "grades", description = "Grade assignment and management"),
        (name = "attendance", description = "Attendance tracking and reporting"),
        (name = "messages", description = "End-to-end encrypted messaging system")
    ),
    servers(
        (url = "http://localhost:8000", description = "Development server"),
    )
)]
struct ApiDoc;

#[test]
fn test_export_openapi() {
    // Generate the OpenAPI specification
    let openapi = ApiDoc::openapi();

    // Serialize the OpenAPI spec to JSON
    let json = serde_json::to_string_pretty(&openapi)
        .expect("Failed to serialize OpenAPI specification");

    // Define the output file path
    let output_path = "test_output/openapi.json";

    // Attempt to write the JSON to a file
    fs::create_dir_all("test_output").expect("Failed to create test_output directory");
    fs::write(output_path, json).expect("Failed to write OpenAPI specification to file");

    // Assert that the file exists
    assert!(fs::metadata(output_path).is_ok(), "OpenAPI specification file was not created");
}
