use std::env;
use std::sync::{Mutex, LazyLock};
use log::{error, warn, info};

use crate::db::DbPool;
use crate::errors::{ApiError, ApiResult};
use crate::test_config::{TestConfig, TestDataTracker};
use crate::utils::hash_password;

// Testing mode functions
pub fn is_testing_mode() -> bool {
    env::var("TESTING_MODE")
        .map(|v| v.to_lowercase() == "true" || v == "1")
        .unwrap_or(false)
}

// Track test data for cleanup
static TEST_DATA_TRACKER: LazyLock<Mutex<TestDataTracker>> = LazyLock::new(|| Mutex::new(TestDataTracker::new()));

pub async fn create_test_data_from_config(pool: &DbPool) -> ApiResult<()> {
    if !is_testing_mode() {
        return Ok(());
    }

    let test_config_path = env::var("TEST_CONFIG_PATH")
        .unwrap_or_else(|_| "test_config.json".to_string());

    info!("Loading test configuration from: {}", test_config_path);
    
    let config = TestConfig::load_from_file(&test_config_path)
        .map_err(|e| {
            error!("Failed to load test configuration: {:?}", e);
            ApiError::InternalServerError
        })?;

    // Validate the configuration
    config.validate().map_err(|e| {
        error!("Test configuration validation failed: {}", e);
        ApiError::InternalServerError
    })?;

    info!("Creating test data from configuration...");
    
    let mut tracker = TEST_DATA_TRACKER.lock().unwrap();
    
    // 1. Create users
    for user in &config.users {
        let password_hash = hash_password(&user.password)?;
        
        let result = sqlx::query(
            r#"
            INSERT INTO users (id, username, email, password_hash, role, is_superuser, public_key, recovery_key, encrypted_private_key_blob, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
            ON CONFLICT (id) DO UPDATE SET
                username = EXCLUDED.username,
                email = EXCLUDED.email,
                password_hash = EXCLUDED.password_hash,
                role = EXCLUDED.role,
                is_superuser = EXCLUDED.is_superuser,
                public_key = EXCLUDED.public_key,
                recovery_key = EXCLUDED.recovery_key,
                encrypted_private_key_blob = EXCLUDED.encrypted_private_key_blob,
                updated_at = NOW()
            "#
        )
        .bind(user.id)
        .bind(&user.username)
        .bind(&user.email)
        .bind(&password_hash)
        .bind(&user.role)
        .bind(user.is_superuser)
        .bind(&user.public_key)
        .bind(&user.recovery_key)
        .bind(&user.encrypted_private_key_blob)
        .execute(pool)
        .await;

        match result {
            Ok(_) => {
                tracker.add_user(user.id);
                info!("Created test user: {} ({})", user.username, user.email);
            }
            Err(e) => {
                // Try fallback without username column if it doesn't exist
                if e.to_string().contains("username") {
                    warn!("Username column not found, creating test user without username");
                    sqlx::query(
                        r#"
                        INSERT INTO users (id, email, password_hash, role, is_superuser, public_key, recovery_key, encrypted_private_key_blob, created_at, updated_at)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
                        ON CONFLICT (id) DO UPDATE SET
                            email = EXCLUDED.email,
                            password_hash = EXCLUDED.password_hash,
                            role = EXCLUDED.role,
                            is_superuser = EXCLUDED.is_superuser,
                            public_key = EXCLUDED.public_key,
                            recovery_key = EXCLUDED.recovery_key,
                            encrypted_private_key_blob = EXCLUDED.encrypted_private_key_blob,
                            updated_at = NOW()
                        "#
                    )
                    .bind(user.id)
                    .bind(&user.email)
                    .bind(&password_hash)
                    .bind(&user.role)
                    .bind(user.is_superuser)
                    .bind(&user.public_key)
                    .bind(&user.recovery_key)
                    .bind(&user.encrypted_private_key_blob)
                    .execute(pool)
                    .await
                    .map_err(|e| {
                        error!("Failed to create test user {} (fallback): {:?}", user.username, e);
                        ApiError::InternalServerError
                    })?;
                    
                    tracker.add_user(user.id);
                    info!("Created test user: {} ({})", user.username, user.email);
                } else {
                    error!("Failed to create test user {}: {:?}", user.username, e);
                    return Err(ApiError::InternalServerError);
                }
            }
        }
    }

    // 2. Create classes
    for class in &config.classes {
        sqlx::query(
            r#"
            INSERT INTO classes (id, name, teacher_id, created_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (id) DO UPDATE SET
                name = EXCLUDED.name,
                teacher_id = EXCLUDED.teacher_id
            "#
        )
        .bind(class.id)
        .bind(&class.name)
        .bind(class.teacher_id)
        .execute(pool)
        .await
        .map_err(|e| {
            error!("Failed to create test class {}: {:?}", class.name, e);
            ApiError::InternalServerError
        })?;

        tracker.add_class(class.id);
        info!("Created test class: {}", class.name);

        // Add students to class
        for student_id in &class.students {
            sqlx::query(
                r#"
                INSERT INTO class_students (class_id, student_id)
                VALUES ($1, $2)
                ON CONFLICT (class_id, student_id) DO NOTHING
                "#
            )
            .bind(class.id)
            .bind(student_id)
            .execute(pool)
            .await
            .map_err(|e| {
                error!("Failed to add student {} to class {}: {:?}", student_id, class.name, e);
                ApiError::InternalServerError
            })?;
        }
    }

    // 3. Create grades
    for grade in &config.grades {
        sqlx::query(
            r#"
            INSERT INTO grades (id, student_id, class_id, teacher_id, grade, assigned_at)
            VALUES ($1, $2, $3, $4, $5, NOW())
            ON CONFLICT (id) DO UPDATE SET
                student_id = EXCLUDED.student_id,
                class_id = EXCLUDED.class_id,
                teacher_id = EXCLUDED.teacher_id,
                grade = EXCLUDED.grade,
                assigned_at = EXCLUDED.assigned_at
            "#
        )
        .bind(grade.id)
        .bind(grade.student_id)
        .bind(grade.class_id)
        .bind(grade.teacher_id)
        .bind(&grade.grade)
        .execute(pool)
        .await
        .map_err(|e| {
            error!("Failed to create test grade: {:?}", e);
            ApiError::InternalServerError
        })?;

        tracker.add_grade(grade.id);
        info!("Created test grade: {} for student {}", grade.grade, grade.student_id);
    }

    // 4. Create attendance records
    for attendance in &config.attendance {
        sqlx::query(
            r#"
            INSERT INTO attendance (id, student_id, class_id, status, recorded_at, recorded_by)
            VALUES ($1, $2, $3, $4, NOW(), $5)
            ON CONFLICT (id) DO UPDATE SET
                student_id = EXCLUDED.student_id,
                class_id = EXCLUDED.class_id,
                status = EXCLUDED.status,
                recorded_by = EXCLUDED.recorded_by,
                recorded_at = EXCLUDED.recorded_at
            "#
        )
        .bind(attendance.id)
        .bind(attendance.student_id)
        .bind(attendance.class_id)
        .bind(&attendance.status)
        .bind(attendance.recorded_by)
        .execute(pool)
        .await
        .map_err(|e| {
            error!("Failed to create test attendance: {:?}", e);
            ApiError::InternalServerError
        })?;

        tracker.add_attendance(attendance.id);
        info!("Created test attendance: {:?} for student {}", attendance.status, attendance.student_id);
    }

    // 5. Create schedule events
    for event in &config.schedule_events {
        sqlx::query(
            r#"
            INSERT INTO schedule_events (id, title, description, start_time, end_time, date, class_id, teacher_id, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
            ON CONFLICT (id) DO UPDATE SET
                title = EXCLUDED.title,
                description = EXCLUDED.description,
                start_time = EXCLUDED.start_time,
                end_time = EXCLUDED.end_time,
                date = EXCLUDED.date,
                class_id = EXCLUDED.class_id,
                teacher_id = EXCLUDED.teacher_id,
                updated_at = NOW()
            "#
        )
        .bind(event.id)
        .bind(&event.title)
        .bind(&event.description)
        .bind(&event.start_time)
        .bind(&event.end_time)
        .bind(&event.date)
        .bind(&event.class_id)
        .bind(&event.teacher_id)
        .execute(pool)
        .await
        .map_err(|e| {
            error!("Failed to create test schedule event {}: {:?}", event.title, e);
            ApiError::InternalServerError
        })?;

        tracker.add_schedule_event(event.id);
        info!("Created test schedule event: {}", event.title);
    }

    // 6. Create threads
    for thread in &config.threads {
        sqlx::query(
            r#"
            INSERT INTO threads (id, created_at)
            VALUES ($1, NOW())
            ON CONFLICT (id) DO NOTHING
            "#
        )
        .bind(thread.id)
        .execute(pool)
        .await
        .map_err(|e| {
            error!("Failed to create test thread: {:?}", e);
            ApiError::InternalServerError
        })?;

        tracker.add_thread(thread.id);

        // Add participants to thread
        for participant_id in &thread.participants {
            sqlx::query(
                r#"
                INSERT INTO thread_participants (thread_id, user_id)
                VALUES ($1, $2)
                ON CONFLICT (thread_id, user_id) DO NOTHING
                "#
            )
            .bind(thread.id)
            .bind(participant_id)
            .execute(pool)
            .await
            .map_err(|e| {
                error!("Failed to add participant {} to thread {}: {:?}", participant_id, thread.id, e);
                ApiError::InternalServerError
            })?;
        }

        info!("Created test thread with {} participants", thread.participants.len());
    }

    // 7. Create messages
    for message in &config.messages {
        sqlx::query(
            r#"
            INSERT INTO messages (id, thread_id, sender_id, sent_at, ciphertext)
            VALUES ($1, $2, $3, NOW(), $4)
            ON CONFLICT (id) DO UPDATE SET
                thread_id = EXCLUDED.thread_id,
                sender_id = EXCLUDED.sender_id,
                ciphertext = EXCLUDED.ciphertext,
                sent_at = EXCLUDED.sent_at
            "#
        )
        .bind(message.id)
        .bind(message.thread_id)
        .bind(message.sender_id)
        .bind(&message.ciphertext)
        .execute(pool)
        .await
        .map_err(|e| {
            error!("Failed to create test message: {:?}", e);
            ApiError::InternalServerError
        })?;

        tracker.add_message(message.id);

        // Add encrypted keys for message
        for encrypted_key in &message.encrypted_keys {
            sqlx::query(
                r#"
                INSERT INTO message_encrypted_keys (message_id, recipient_id, encrypted_key)
                VALUES ($1, $2, $3)
                ON CONFLICT (message_id, recipient_id) DO UPDATE SET
                    encrypted_key = EXCLUDED.encrypted_key
                "#
            )
            .bind(message.id)
            .bind(encrypted_key.recipient_id)
            .bind(&encrypted_key.encrypted_key)
            .execute(pool)
            .await
            .map_err(|e| {
                error!("Failed to create test message encrypted key: {:?}", e);
                ApiError::InternalServerError
            })?;
        }

        info!("Created test message with {} encrypted keys", message.encrypted_keys.len());
    }

    // 8. Create user permissions
    for permission in &config.permissions {
        for permission_id in &permission.permission_ids {
            sqlx::query(
                r#"
                INSERT INTO user_permissions (user_id, permission_id)
                VALUES ($1, $2)
                ON CONFLICT (user_id, permission_id) DO NOTHING
                "#
            )
            .bind(permission.user_id)
            .bind(permission_id)
            .execute(pool)
            .await
            .map_err(|e| {
                error!("Failed to create test user permission: {:?}", e);
                ApiError::InternalServerError
            })?;
        }

        info!("Created test permissions for user {}", permission.user_id);
    }

    info!("Successfully created test data from configuration");
    Ok(())
}

pub async fn cleanup_test_data(pool: &DbPool) -> ApiResult<()> {
    if !is_testing_mode() {
        return Ok(());
    }

    info!("Cleaning up test data...");
    
    // Get tracker data and immediately drop the guard
    let tracker = {
        let tracker = TEST_DATA_TRACKER.lock().unwrap();
        
        if tracker.user_ids.is_empty() && tracker.class_ids.is_empty() &&
           tracker.grade_ids.is_empty() && tracker.attendance_ids.is_empty() &&
           tracker.schedule_event_ids.is_empty() && tracker.message_ids.is_empty() &&
           tracker.thread_ids.is_empty() {
            info!("No test data to clean up");
            return Ok(());
        }
        
        tracker.clone()
    }; // Guard is dropped here
    
    // Clean up in reverse order of foreign key dependencies
    
    // 1. Delete message encrypted keys
    if !tracker.message_ids.is_empty() {
        sqlx::query("DELETE FROM message_encrypted_keys WHERE message_id = ANY($1)")
            .bind(&tracker.message_ids)
            .execute(pool)
            .await?;
    }
    
    // 2. Delete messages
    if !tracker.message_ids.is_empty() {
        sqlx::query("DELETE FROM messages WHERE id = ANY($1)")
            .bind(&tracker.message_ids)
            .execute(pool)
            .await?;
    }
    
    // 3. Delete thread participants
    if !tracker.thread_ids.is_empty() {
        sqlx::query("DELETE FROM thread_participants WHERE thread_id = ANY($1)")
            .bind(&tracker.thread_ids)
            .execute(pool)
            .await?;
    }
    
    // 4. Delete threads
    if !tracker.thread_ids.is_empty() {
        sqlx::query("DELETE FROM threads WHERE id = ANY($1)")
            .bind(&tracker.thread_ids)
            .execute(pool)
            .await?;
    }
    
    // 5. Delete attendance records
    if !tracker.attendance_ids.is_empty() {
        sqlx::query("DELETE FROM attendance WHERE id = ANY($1)")
            .bind(&tracker.attendance_ids)
            .execute(pool)
            .await?;
    }
    
    // 6. Delete grades
    if !tracker.grade_ids.is_empty() {
        sqlx::query("DELETE FROM grades WHERE id = ANY($1)")
            .bind(&tracker.grade_ids)
            .execute(pool)
            .await?;
    }
    
    // 7. Delete schedule events
    if !tracker.schedule_event_ids.is_empty() {
        sqlx::query("DELETE FROM schedule_events WHERE id = ANY($1)")
            .bind(&tracker.schedule_event_ids)
            .execute(pool)
            .await?;
    }
    
    // 8. Delete class enrollments
    if !tracker.class_ids.is_empty() {
        sqlx::query("DELETE FROM class_students WHERE class_id = ANY($1)")
            .bind(&tracker.class_ids)
            .execute(pool)
            .await?;
    }
    
    // 9. Delete classes
    if !tracker.class_ids.is_empty() {
        sqlx::query("DELETE FROM classes WHERE id = ANY($1)")
            .bind(&tracker.class_ids)
            .execute(pool)
            .await?;
    }
    
    // 10. Delete user permission assignments
    if !tracker.user_ids.is_empty() {
        sqlx::query("DELETE FROM user_permissions WHERE user_id = ANY($1)")
            .bind(&tracker.user_ids)
            .execute(pool)
            .await?;
    }
    
    // 11. Delete password reset tokens
    if !tracker.user_ids.is_empty() {
        sqlx::query("DELETE FROM password_reset_tokens WHERE user_id = ANY($1)")
            .bind(&tracker.user_ids)
            .execute(pool)
            .await?;
    }
    
    // 12. Finally, delete the test users themselves
    if !tracker.user_ids.is_empty() {
        sqlx::query("DELETE FROM users WHERE id = ANY($1)")
            .bind(&tracker.user_ids)
            .execute(pool)
            .await?;
    }

    info!("Successfully cleaned up test data");
    Ok(())
}

// Legacy function for backward compatibility
pub async fn create_test_users(pool: &DbPool) -> ApiResult<()> {
    create_test_data_from_config(pool).await
}

// Legacy function for backward compatibility
pub async fn cleanup_test_users(pool: &DbPool) -> ApiResult<()> {
    cleanup_test_data(pool).await
}
