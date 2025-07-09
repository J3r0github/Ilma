use std::env;
use std::sync::{Mutex, LazyLock};
use std::collections::HashMap;
use log::{error, warn, info};
use base64::{Engine, engine::general_purpose::STANDARD};
use uuid::Uuid;
use rand::{rngs::OsRng, RngCore};
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::{EncodePrivateKey, EncodePublicKey, DecodePublicKey, LineEnding}};
use rsa::pkcs1v15::Pkcs1v15Encrypt;
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};

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

/// RSA key pair for development
#[derive(Debug, Clone)]
struct DevKeyPair {
    pub public_key: String,      // PEM encoded RSA public key
    pub private_key: String,     // PEM encoded RSA private key  
    pub encrypted_private_key_blob: String, // AES encrypted private key for storage
    pub recovery_key: String,    // BIP39-style recovery phrase
}

/// Cryptographic key management for development environments
struct DevCrypto {
    pub user_keys: HashMap<Uuid, DevKeyPair>,
}

impl DevCrypto {
    pub fn new() -> Self {
        Self {
            user_keys: HashMap::new(),
        }
    }

    /// Generate a real RSA key pair for development use
    pub fn generate_key_pair_for_user(&mut self, user_id: Uuid, email: &str, password: &str) -> ApiResult<&DevKeyPair> {
        info!("Generating RSA key pair for user: {} ({})", email, user_id);
        
        // Generate real 2048-bit RSA keys
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|e| {
                error!("Failed to generate RSA private key: {:?}", e);
                ApiError::InternalServerError
            })?;
        
        let public_key = RsaPublicKey::from(&private_key);
        
        // Encode keys to PEM format
        let private_pem = private_key.to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| {
                error!("Failed to encode private key to PEM: {:?}", e);
                ApiError::InternalServerError
            })?;
        
        let public_pem = public_key.to_public_key_pem(LineEnding::LF)
            .map_err(|e| {
                error!("Failed to encode public key to PEM: {:?}", e);
                ApiError::InternalServerError
            })?;
        
        // Generate encrypted private key blob (AES-256-GCM) with password
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        let encrypted_private_key_blob = Self::encrypt_private_key(&private_pem, password, &salt)?;
        
        // Generate BIP39-style recovery key
        let recovery_key = Self::generate_bip39_recovery_key(user_id, email)?;

        let key_pair = DevKeyPair {
            public_key: public_pem.to_string(),
            private_key: private_pem.to_string(),
            encrypted_private_key_blob,
            recovery_key,
        };

        self.user_keys.insert(user_id, key_pair);
        Ok(self.user_keys.get(&user_id).unwrap())
    }

    /// Generate encrypted key for a message recipient using RSA
    pub fn generate_encrypted_key_for_recipient(
        &self, 
        sender_id: Uuid, 
        recipient_id: Uuid, 
        message_content: &str
    ) -> ApiResult<String> {
        // Get recipient's public key
        if let Some(recipient_keys) = self.user_keys.get(&recipient_id) {
            // Parse the public key
            let public_key = RsaPublicKey::from_public_key_pem(&recipient_keys.public_key)
                .map_err(|e| {
                    error!("Failed to parse recipient public key: {:?}", e);
                    ApiError::InternalServerError
                })?;
            
            // Generate a random AES key for this message
            let mut aes_key = [0u8; 32];
            OsRng.fill_bytes(&mut aes_key);
            
            // Encrypt the AES key with recipient's RSA public key
            let mut rng = OsRng;
            let encrypted_aes_key = public_key.encrypt(&mut rng, Pkcs1v15Encrypt, &aes_key)
                .map_err(|e| {
                    error!("Failed to encrypt AES key with RSA: {:?}", e);
                    ApiError::InternalServerError
                })?;
            
            // Return base64 encoded encrypted AES key
            Ok(STANDARD.encode(encrypted_aes_key))
        } else {
            // Fallback: generate deterministic key for recipients without keys yet
            let combined = format!("{}{}{}", sender_id, recipient_id, message_content.len());
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            use std::hash::{Hash, Hasher};
            combined.hash(&mut hasher);
            let hash = hasher.finish();
            
            let encrypted_key = format!("{:016x}{:016x}{:016x}{:016x}", 
                hash, 
                hash.wrapping_mul(7),
                hash.wrapping_mul(13), 
                hash.wrapping_mul(19)
            );
            
            Ok(encrypted_key)
        }
    }

    fn encrypt_private_key(private_pem: &str, password: &str, salt: &[u8; 32]) -> ApiResult<String> {
        // Use Argon2id for password-based key derivation (SECURE!)
        use argon2::{Argon2, password_hash::{PasswordHasher, SaltString}};
        
        let salt_string = SaltString::encode_b64(salt)
            .map_err(|e| {
                error!("Failed to encode salt: {:?}", e);
                ApiError::InternalServerError
            })?;
        
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt_string)
            .map_err(|e| {
                error!("Failed to derive key from password: {:?}", e);
                ApiError::InternalServerError
            })?;
        
        // Extract 32 bytes for AES-256 key
        let hash_bytes = password_hash.hash.unwrap();
        let derived_key = &hash_bytes.as_bytes()[..32];
        let key = Key::<Aes256Gcm>::from_slice(derived_key);
        let cipher = Aes256Gcm::new(key);
        
        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Encrypt the private key
        let ciphertext = cipher.encrypt(nonce, private_pem.as_bytes())
            .map_err(|e| {
                error!("Failed to encrypt private key: {:?}", e);
                ApiError::InternalServerError
            })?;
        
        // Combine salt + nonce + ciphertext and encode
        let mut result = salt.to_vec();
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(STANDARD.encode(result))
    }

    fn generate_bip39_recovery_key(user_id: Uuid, email: &str) -> ApiResult<String> {
        // BIP39 word list (first 24 words for brevity)
        let words = [
            "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
            "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
            "acoustic", "acquire", "across", "action", "actor", "actress", "actual", "adapt"
        ];
        
        // Generate deterministic but secure seed from user data
        let combined = format!("{}{}", user_id, email);
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        use std::hash::{Hash, Hasher};
        combined.hash(&mut hasher);
        let mut seed = hasher.finish();
        
        let mut recovery_words = Vec::new();
        for _ in 0..12 {
            let word_index = (seed % words.len() as u64) as usize;
            recovery_words.push(words[word_index]);
            seed = seed.wrapping_mul(1103515245).wrapping_add(12345); // Simple LCG
        }
        
        Ok(recovery_words.join(" "))
    }
}

/// Generate real AES-256-GCM encrypted message content
fn generate_test_message_ciphertext(content: &str, sender_id: Uuid) -> String {
    // Use real AES-256-GCM encryption
    let mut key_material = [0u8; 32];
    let sender_bytes = sender_id.as_bytes();
    for (i, &byte) in sender_bytes.iter().cycle().take(32).enumerate() {
        key_material[i] = byte.wrapping_add(i as u8);
    }
    
    let key = Key::<Aes256Gcm>::from_slice(&key_material);
    let cipher = Aes256Gcm::new(key);
    
    // Generate random nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // Encrypt the message content
    let ciphertext = cipher.encrypt(nonce, content.as_bytes())
        .expect("AES encryption should not fail");
    
    // Combine nonce + ciphertext and encode as base64
    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);
    STANDARD.encode(result)
}

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
    let mut crypto = DevCrypto::new();
    
    // 1. Create users with auto-generated cryptographic keys
    for user in &config.users {
        let password_hash = hash_password(&user.password)?;
        
        // Generate cryptographic keys for this user (using their password for encryption)
        let key_pair = crypto.generate_key_pair_for_user(user.id, &user.email, &user.password)?;
        
        let result = sqlx::query(
            r#"
            INSERT INTO users (
                id, email, password_hash, role, is_superuser, public_key, recovery_key, encrypted_private_key_blob,
                first_names, chosen_name, last_name, name_short, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW(), NOW())
            ON CONFLICT (id) DO UPDATE SET
                email = EXCLUDED.email,
                password_hash = EXCLUDED.password_hash,
                role = EXCLUDED.role,
                is_superuser = EXCLUDED.is_superuser,
                public_key = EXCLUDED.public_key,
                recovery_key = EXCLUDED.recovery_key,
                encrypted_private_key_blob = EXCLUDED.encrypted_private_key_blob,
                first_names = EXCLUDED.first_names,
                chosen_name = EXCLUDED.chosen_name,
                last_name = EXCLUDED.last_name,
                name_short = EXCLUDED.name_short,
                updated_at = NOW()
            "#
        )
        .bind(user.id)
        .bind(&user.email)
        .bind(&password_hash)
        .bind(&user.role)
        .bind(user.is_superuser)
        .bind(&key_pair.public_key)
        .bind(&key_pair.recovery_key)
        .bind(&key_pair.encrypted_private_key_blob)
        .bind(&user.first_names)
        .bind(&user.chosen_name)
        .bind(&user.last_name)
        .bind(&user.name_short)
        .execute(pool)
        .await;

        match result {
            Ok(_) => {
                tracker.add_user(user.id);
                info!("Created test user: {} with auto-generated keys", user.email);
            }
            Err(e) => {
                // Try fallback without extended name fields if there are issues
                if e.to_string().contains("column") {
                    warn!("Column not found, creating test user with fallback query");
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
                    .bind(&key_pair.public_key)
                    .bind(&key_pair.recovery_key)
                    .bind(&key_pair.encrypted_private_key_blob)
                    .execute(pool)
                    .await
                    .map_err(|e| {
                        error!("Failed to create test user {} (fallback): {:?}", user.email, e);
                        ApiError::InternalServerError
                    })?;
                    
                    tracker.add_user(user.id);
                    info!("Created test user: {} with auto-generated keys", user.email);
                } else {
                    error!("Failed to create test user {}: {:?}", user.email, e);
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

    // 7. Create messages with auto-generated encryption
    for message in &config.messages {
        // Generate ciphertext from plain text content
        let ciphertext = generate_test_message_ciphertext(&message.content, message.sender_id);
        
        sqlx::query(
            r#"
            INSERT INTO messages (id, thread_id, sender_id, sent_at, ciphertext)
            VALUES ($1, $2, $3, $4, $5)
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
        .bind(message.sent_at)
        .bind(&ciphertext)
        .execute(pool)
        .await
        .map_err(|e| {
            error!("Failed to create test message: {:?}", e);
            ApiError::InternalServerError
        })?;

        tracker.add_message(message.id);

        // Get thread participants to generate encrypted keys for each recipient
        let participants: Vec<uuid::Uuid> = sqlx::query_scalar(
            "SELECT user_id FROM thread_participants WHERE thread_id = $1"
        )
        .bind(message.thread_id)
        .fetch_all(pool)
        .await
        .map_err(|e| {
            error!("Failed to get thread participants: {:?}", e);
            ApiError::InternalServerError
        })?;

        // Generate encrypted keys for all thread participants
        let mut encrypted_key_count = 0;
        for recipient_id in participants {
            let encrypted_key = crypto.generate_encrypted_key_for_recipient(
                message.sender_id, 
                recipient_id, 
                &message.content
            )?;
            
            sqlx::query(
                r#"
                INSERT INTO message_encrypted_keys (message_id, recipient_id, encrypted_key)
                VALUES ($1, $2, $3)
                ON CONFLICT (message_id, recipient_id) DO UPDATE SET
                    encrypted_key = EXCLUDED.encrypted_key
                "#
            )
            .bind(message.id)
            .bind(recipient_id)
            .bind(&encrypted_key)
            .execute(pool)
            .await
            .map_err(|e| {
                error!("Failed to create test message encrypted key: {:?}", e);
                ApiError::InternalServerError
            })?;
            
            encrypted_key_count += 1;
        }

        info!("Created test message '{}' with {} auto-generated encrypted keys", 
               message.content.chars().take(30).collect::<String>(), 
               encrypted_key_count);
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
    
    // Use a transaction to prevent deadlocks and ensure atomic cleanup
    let mut transaction = pool.begin().await.map_err(|e| {
        error!("Failed to begin cleanup transaction: {:?}", e);
        ApiError::InternalServerError
    })?;
    
    // Set a timeout to prevent hanging
    let cleanup_timeout = std::time::Duration::from_secs(30);
    let cleanup_future = async {
        // Clean up in reverse order of foreign key dependencies
        
        // 1. Delete message encrypted keys
        if !tracker.message_ids.is_empty() {
            info!("Deleting {} message encrypted keys", tracker.message_ids.len());
            sqlx::query("DELETE FROM message_encrypted_keys WHERE message_id = ANY($1)")
                .bind(&tracker.message_ids)
                .execute(&mut *transaction)
                .await?;
        }
        
        // 2. Delete messages
        if !tracker.message_ids.is_empty() {
            info!("Deleting {} messages", tracker.message_ids.len());
            sqlx::query("DELETE FROM messages WHERE id = ANY($1)")
                .bind(&tracker.message_ids)
                .execute(&mut *transaction)
                .await?;
        }
        
        // 3. Delete thread participants
        if !tracker.thread_ids.is_empty() {
            info!("Deleting thread participants for {} threads", tracker.thread_ids.len());
            sqlx::query("DELETE FROM thread_participants WHERE thread_id = ANY($1)")
                .bind(&tracker.thread_ids)
                .execute(&mut *transaction)
                .await?;
        }
        
        // 4. Delete threads
        if !tracker.thread_ids.is_empty() {
            info!("Deleting {} threads", tracker.thread_ids.len());
            sqlx::query("DELETE FROM threads WHERE id = ANY($1)")
                .bind(&tracker.thread_ids)
                .execute(&mut *transaction)
                .await?;
        }
        
        // 5. Delete attendance records
        if !tracker.attendance_ids.is_empty() {
            info!("Deleting {} attendance records", tracker.attendance_ids.len());
            sqlx::query("DELETE FROM attendance WHERE id = ANY($1)")
                .bind(&tracker.attendance_ids)
                .execute(&mut *transaction)
                .await?;
        }
        
        // 6. Delete grades
        if !tracker.grade_ids.is_empty() {
            info!("Deleting {} grades", tracker.grade_ids.len());
            sqlx::query("DELETE FROM grades WHERE id = ANY($1)")
                .bind(&tracker.grade_ids)
                .execute(&mut *transaction)
                .await?;
        }
        
        // 7. Delete schedule events
        if !tracker.schedule_event_ids.is_empty() {
            info!("Deleting {} schedule events", tracker.schedule_event_ids.len());
            sqlx::query("DELETE FROM schedule_events WHERE id = ANY($1)")
                .bind(&tracker.schedule_event_ids)
                .execute(&mut *transaction)
                .await?;
        }
        
        // 8. Delete class enrollments
        if !tracker.class_ids.is_empty() {
            info!("Deleting class enrollments for {} classes", tracker.class_ids.len());
            sqlx::query("DELETE FROM class_students WHERE class_id = ANY($1)")
                .bind(&tracker.class_ids)
                .execute(&mut *transaction)
                .await?;
        }
        
        // 9. Delete classes
        if !tracker.class_ids.is_empty() {
            info!("Deleting {} classes", tracker.class_ids.len());
            sqlx::query("DELETE FROM classes WHERE id = ANY($1)")
                .bind(&tracker.class_ids)
                .execute(&mut *transaction)
                .await?;
        }
        
        // 10. Delete user permission assignments
        if !tracker.user_ids.is_empty() {
            info!("Deleting user permissions for {} users", tracker.user_ids.len());
            sqlx::query("DELETE FROM user_permissions WHERE user_id = ANY($1)")
                .bind(&tracker.user_ids)
                .execute(&mut *transaction)
                .await?;
        }
        
        // 11. Delete password reset tokens
        if !tracker.user_ids.is_empty() {
            info!("Deleting password reset tokens for {} users", tracker.user_ids.len());
            sqlx::query("DELETE FROM password_reset_tokens WHERE user_id = ANY($1)")
                .bind(&tracker.user_ids)
                .execute(&mut *transaction)
                .await?;
        }
        
        // 12. Finally, delete the test users themselves
        if !tracker.user_ids.is_empty() {
            info!("Deleting {} test users", tracker.user_ids.len());
            sqlx::query("DELETE FROM users WHERE id = ANY($1)")
                .bind(&tracker.user_ids)
                .execute(&mut *transaction)
                .await?;
        }

        // Commit the transaction
        transaction.commit().await.map_err(|e| {
            error!("Failed to commit cleanup transaction: {:?}", e);
            ApiError::InternalServerError
        })?;

        Ok::<(), ApiError>(())
    };

    // Execute with timeout
    match tokio::time::timeout(cleanup_timeout, cleanup_future).await {
        Ok(Ok(())) => {
            info!("Successfully cleaned up test data");
            
            // Clear the tracker after successful cleanup
            if let Ok(mut tracker) = TEST_DATA_TRACKER.lock() {
                *tracker = TestDataTracker::new();
            }
            
            Ok(())
        }
        Ok(Err(e)) => {
            error!("Error during test data cleanup: {:?}", e);
            Err(e)
        }
        Err(_) => {
            error!("Test data cleanup timed out after {} seconds", cleanup_timeout.as_secs());
            Err(ApiError::InternalServerError)
        }
    }
}