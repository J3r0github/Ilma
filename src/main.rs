use actix_web::{middleware::Logger, web, App, HttpServer, middleware::DefaultHeaders};
use actix_web_httpauth::middleware::HttpAuthentication;
use actix_cors::Cors;
use dotenvy::dotenv;
use std::env;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;
use log::{info, error, warn};
use std::process;
use std::sync::Arc;
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use std::thread;

mod models;
mod handlers;
mod auth;
mod db;
mod middleware;
mod errors;

use models::*;

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
        auth::login,
        auth::request_password_reset,
        auth::reset_password,
        handlers::users::get_me,
        handlers::users::create_user,
        handlers::users::get_user_public_key,
        handlers::users::get_recovery_key,
        handlers::users::set_recovery_key,
        handlers::users::get_user_public_key_by_username,
        handlers::permissions::list_permissions,
        handlers::permissions::list_permission_sets,
        handlers::permissions::get_user_permissions,
        handlers::permissions::assign_user_permissions,
        handlers::classes::list_classes,
        handlers::classes::create_class,
        handlers::classes::add_student_to_class,
        handlers::grades::assign_grade,
        handlers::attendance::record_attendance,
        handlers::messages::list_threads,
        handlers::messages::send_message,
        handlers::messages::get_thread_messages,
    ),
    components(
        schemas(
            User, UserRole, Permission, PermissionSet, Class, Thread, 
            ThreadPreview, Message, EncryptedKey, Grade, Attendance, AttendanceStatus,
            LoginRequest, CreateUserRequest, PasswordResetRequest, ResetPasswordRequest, 
            SetRecoveryKeyRequest, AssignPermissionsRequest, CreateClassRequest, 
            AddStudentRequest, AssignGradeRequest, RecordAttendanceRequest, 
            SendMessageRequest, LoginResponse, RecoveryKeyResponse, PublicKeyResponse, 
            PasswordResetToken, ErrorResponse, PaginationQuery, MessagePaginationQuery
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
        (url = "http://localhost:8000", description = "Development server"),    )
)]
struct ApiDoc;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init();

    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");
    
    let pool = db::create_pool(&database_url).await
        .expect("Failed to create database pool");

    // Run migrations
    db::run_migrations(&pool).await
        .expect("Failed to run migrations");

    // Create test users if in testing mode
    if let Err(e) = auth::create_test_users(&pool).await {
        error!("Failed to create test users: {:?}", e);
        process::exit(1);
    }

    let bind_address = env::var("BIND_ADDRESS")
        .unwrap_or_else(|_| "127.0.0.1:8000".to_string());

    // Validate JWT secret on startup
    if let Ok(jwt_secret) = env::var("JWT_SECRET") {
        if jwt_secret.len() < 32 {
            error!("JWT_SECRET must be at least 32 characters long");
            process::exit(1);
        }
        if jwt_secret.contains("change-this") || jwt_secret.contains("your-super-secret") {
            error!("JWT_SECRET appears to be a default value. Please change it to a secure random string");
            process::exit(1);
        }
    } else {
        error!("JWT_SECRET environment variable must be set");
        process::exit(1);
    }

    // Check if testing mode is enabled
    let testing_mode = env::var("TESTING_MODE")
        .map(|v| v.to_lowercase() == "true" || v == "1")
        .unwrap_or(false);
    
    if testing_mode {
        warn!("TESTING MODE IS ENABLED - This should only be used in development!");
        warn!("Test users will be created at startup and cleaned up on shutdown.");
    }

    // Configure rate limiting
    let rate_limit_requests: usize = env::var("RATE_LIMIT_REQUESTS")
        .unwrap_or_else(|_| "100".to_string())
        .parse()
        .unwrap_or(100);
    
    let rate_limit_window: u64 = env::var("RATE_LIMIT_WINDOW_SECONDS")
        .unwrap_or_else(|_| "60".to_string())
        .parse()
        .unwrap_or(60);

    let mut rate_limiter = middleware::RateLimiter::new(rate_limit_requests, rate_limit_window);
    
    // Configure per-endpoint rate limiting from environment variables
    configure_endpoint_rate_limits(&mut rate_limiter);

    let rate_limiter = Arc::new(rate_limiter);

    // Configure CORS from environment variables
    let cors_origins = env::var("CORS_ALLOWED_ORIGINS")
        .unwrap_or_else(|_| "http://localhost:3000".to_string());
    
    info!("Starting server at http://{}", bind_address);
    info!("Rate limiting: {} requests per {} seconds", rate_limit_requests, rate_limit_window);
    info!("CORS allowed origins: {}", cors_origins);

    // Clone pool for cleanup before moving into server
    let pool_for_cleanup = pool.clone();
    
    // Create server with shutdown handling
    let server = HttpServer::new(move || {
        // Configure CORS middleware
        let cors = Cors::default()
            .allowed_origin(&cors_origins)
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"])
            .allowed_headers(vec![
                "Authorization",
                "Content-Type",
                "X-Requested-With",
                "Accept",
                "Origin",
            ])
            .supports_credentials()
            .max_age(3600);

        App::new()
            .app_data(web::Data::new(pool.clone()))
            .wrap(cors)
            .wrap(Logger::default())
            .wrap(middleware::RateLimitFactory::new(rate_limiter.clone()))
            .wrap(
                DefaultHeaders::new()
                    .add(("X-Content-Type-Options", "nosniff"))
                    .add(("X-Frame-Options", "DENY"))
                    .add(("X-XSS-Protection", "1; mode=block"))
                    .add(("Strict-Transport-Security", "max-age=31536000; includeSubDomains"))
                    .add(("Referrer-Policy", "strict-origin-when-cross-origin"))
            )
            .service(
                web::scope("/api")
                    .service(auth_routes())
                    .service(
                        web::scope("")
                            .wrap(HttpAuthentication::bearer(middleware::jwt_middleware))
                            .service(user_routes())
                            .service(permission_routes())
                            .service(class_routes())
                            .service(grade_routes())
                            .service(attendance_routes())
                            .service(message_routes())
                    )
            )
            .service(
                SwaggerUi::new("/swagger-ui/{_:.*}")
                    .url("/api-docs/openapi.json", ApiDoc::openapi())
            )
    })
    .bind(&bind_address)?
    .run();

    let server_handle = server.handle();

    // Signal handler in a blocking thread
    let cleanup_handle = thread::spawn(move || {
        let mut signals = Signals::new(&[SIGINT, SIGTERM]).expect("Failed to set up signals");
        // Wait for any signal
        for sig in signals.forever() {
            match sig {
                SIGINT | SIGTERM => {
                    info!("Shutdown signal ({}) received, cleaning up test users...", sig);
                    let rt = tokio::runtime::Runtime::new().unwrap();
                    rt.block_on(async {
                        if let Err(e) = auth::cleanup_test_users(&pool_for_cleanup).await {
                            error!("Error cleaning up test users: {:?}", e);
                        }
                        server_handle.stop(true).await;
                    });
                    break;
                }
                _ => (), // Ignore others
            }
        }
    });

    // Await server (actix handles its own runtime)
    let result = server.await;

    // Wait for cleanup thread to finish
    let _ = cleanup_handle.join();

    result
}

fn auth_routes() -> actix_web::Scope {
    web::scope("/auth")
        .route("/login", web::post().to(auth::login))
        .route("/request-password-reset", web::post().to(auth::request_password_reset))
        .route("/reset-password", web::post().to(auth::reset_password))
}

fn user_routes() -> actix_web::Scope {
    web::scope("")
        .route("/me", web::get().to(handlers::users::get_me))
        .route("/users", web::post().to(handlers::users::create_user))
        .route("/users/{id}/public_key", web::get().to(handlers::users::get_user_public_key))
        .route("/user/recovery-key/{username}", web::get().to(handlers::users::get_recovery_key))
        .route("/user/set-recovery-key", web::post().to(handlers::users::set_recovery_key))
        .route("/user/public-key/{username}", web::get().to(handlers::users::get_user_public_key_by_username))
}

fn permission_routes() -> actix_web::Scope {
    web::scope("/permissions")
        .route("", web::get().to(handlers::permissions::list_permissions))
        .route("/sets", web::get().to(handlers::permissions::list_permission_sets))
        .route("/users/{id}/permissions", web::get().to(handlers::permissions::get_user_permissions))
        .route("/users/{id}/permissions", web::post().to(handlers::permissions::assign_user_permissions))
}

fn class_routes() -> actix_web::Scope {
    web::scope("/classes")
        .route("", web::get().to(handlers::classes::list_classes))
        .route("", web::post().to(handlers::classes::create_class))
        .route("/{class_id}/students", web::post().to(handlers::classes::add_student_to_class))
}

fn grade_routes() -> actix_web::Scope {
    web::scope("/grades")
        .route("", web::post().to(handlers::grades::assign_grade))
}

fn attendance_routes() -> actix_web::Scope {
    web::scope("/attendance")
        .route("", web::post().to(handlers::attendance::record_attendance))
}

fn message_routes() -> actix_web::Scope {
    web::scope("/messages")
        .route("/threads", web::get().to(handlers::messages::list_threads))
        .route("/threads", web::post().to(handlers::messages::send_message))
        .route("/threads/{thread_id}", web::get().to(handlers::messages::get_thread_messages))
}

fn configure_endpoint_rate_limits(rate_limiter: &mut middleware::RateLimiter) {
    // Helper function to parse environment variables for endpoint-specific rate limiting
    let parse_endpoint_config = |method: &str, path: &str| -> Option<middleware::RateLimitConfig> {
        let endpoint_key = format!("{}_{}", method, path.replace('/', "_").trim_start_matches('_'));
        
        let requests_key = format!("RATE_LIMIT_{}_REQUESTS", endpoint_key);
        let window_key = format!("RATE_LIMIT_{}_WINDOW", endpoint_key);
        
        if let (Ok(requests_str), Ok(window_str)) = (env::var(&requests_key), env::var(&window_key)) {
            if let (Ok(requests), Ok(window)) = (requests_str.parse::<usize>(), window_str.parse::<u64>()) {
                return Some(middleware::RateLimitConfig::new(requests, window));
            }
        }
        None
    };

    // Configure authentication endpoints
    if let Some(config) = parse_endpoint_config("POST", "/api/auth/login") {
        rate_limiter.add_endpoint_config("POST_api_auth_login".to_string(), config);
    }
    if let Some(config) = parse_endpoint_config("POST", "/api/auth/request-password-reset") {
        rate_limiter.add_endpoint_config("POST_api_auth_request-password-reset".to_string(), config);
    }
    if let Some(config) = parse_endpoint_config("POST", "/api/auth/reset-password") {
        rate_limiter.add_endpoint_config("POST_api_auth_reset-password".to_string(), config);
    }

    // Configure user endpoints
    if let Some(config) = parse_endpoint_config("POST", "/api/users") {
        rate_limiter.add_endpoint_config("POST_api_users".to_string(), config);
    }

    // Configure message endpoints
    if let Some(config) = parse_endpoint_config("POST", "/api/messages/threads") {
        rate_limiter.add_endpoint_config("POST_api_messages_threads".to_string(), config);
    }
    if let Some(config) = parse_endpoint_config("GET", "/api/messages/threads") {
        rate_limiter.add_endpoint_config("GET_api_messages_threads".to_string(), config);
    }

    // Configure grade endpoints
    if let Some(config) = parse_endpoint_config("POST", "/api/grades") {
        rate_limiter.add_endpoint_config("POST_api_grades".to_string(), config);
    }

    // Configure attendance endpoints
    if let Some(config) = parse_endpoint_config("POST", "/api/attendance") {
        rate_limiter.add_endpoint_config("POST_api_attendance".to_string(), config);
    }

    // Configure class endpoints
    if let Some(config) = parse_endpoint_config("POST", "/api/classes") {
        rate_limiter.add_endpoint_config("POST_api_classes".to_string(), config);
    }

    // Log configured endpoint limits
    for (method, path) in &[
        ("POST", "/api/auth/login"),
        ("POST", "/api/auth/request-password-reset"),
        ("POST", "/api/users"),
        ("POST", "/api/messages/threads"),
        ("GET", "/api/messages/threads"),
        ("POST", "/api/grades"),
        ("POST", "/api/attendance"),
        ("POST", "/api/classes"),
    ] {
        if parse_endpoint_config(method, path).is_some() {
            info!("Configured custom rate limit for {} {}", method, path);
        }
    }
}