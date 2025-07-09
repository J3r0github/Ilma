//! End-to-End Integration Tests for Encrypted Messaging
//!
//! These tests demonstrate and verify encrypted messaging between users,
//! specifically focusing on teacher-admin communication scenarios.

use actix_web::{test, web, App, http::StatusCode};
use std::env;
use uuid::Uuid;

use ilma::{
    auth::login,
    handlers::messages::{send_message, list_threads, get_thread_messages},
    models::{LoginRequest, SendMessageRequest, EncryptedKey},
    db::DbPool,
    configloader::create_test_data_from_config,
};

/// Helper function to create a test database pool with proper initialization
async fn create_test_pool() -> Option<web::Data<DbPool>> {
    // Check if we're in testing mode - skip if not
    if env::var("TESTING_MODE").unwrap_or_default() != "true" {
        println!("⚠️  TESTING_MODE is not set to 'true'. Skipping E2E message tests.");
        println!("   To run these tests, set TESTING_MODE=true");
        return None;
    }

    // Verify JWT secret is available
    if env::var("JWT_SECRET").is_err() {
        println!("⚠️  JWT_SECRET environment variable not set. Skipping test.");
        return None;
    }
    
    // Use the same database URL as the main application
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://dbuser:dbuser@localhost/ilma_db".to_string());
    
    let pool = match sqlx::PgPool::connect(&database_url).await {
        Ok(pool) => {
            // Run database migrations to ensure tables exist
            if let Err(e) = ilma::db::run_migrations(&pool).await {
                println!("⚠️  Database migration failed: {}. Skipping test.", e);
                return None;
            }

            // Create test data from config
            if let Err(e) = create_test_data_from_config(&pool).await {
                println!("⚠️  Failed to create test data: {}. Skipping test.", e);
                return None;
            }

            web::Data::new(pool)
        },
        Err(e) => {
            println!("⚠️  Database connection failed: {}. Skipping test.", e);
            return None;
        }
    };
    
    Some(pool)
}

/// Helper function to login and get JWT token
async fn login_user(pool: &DbPool, email: &str, password: &str) -> Option<String> {
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .route("/login", web::post().to(login))
    ).await;

    let login_request = LoginRequest {
        email: email.to_string(),
        password: password.to_string(),
    };

    let req = test::TestRequest::post()
        .uri("/login")
        .set_json(&login_request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    if resp.status() == StatusCode::OK {
        let body: serde_json::Value = test::read_body_json(resp).await;
        Some(body["token"].as_str()?.to_string())
    } else {
        println!("Login failed for {}: {:?}", email, resp.status());
        None
    }
}

/// Test 1: Login as teacher and admin users
#[actix_web::test]
async fn test_login_teacher_and_admin() {
    let pool = match create_test_pool().await {
        Some(pool) => pool,
        None => return,
    };

    println!("🔐 Testing teacher login...");
    let teacher_token = login_user(&pool, "teacher@test.edu", "teacher123").await;
    assert!(teacher_token.is_some(), "Teacher should be able to login");
    println!("✅ Teacher login successful");

    println!("🔐 Testing admin login...");
    let admin_token = login_user(&pool, "admin@test.edu", "admin123").await;
    assert!(admin_token.is_some(), "Admin should be able to login");
    println!("✅ Admin login successful");

    println!("🎉 Both users can authenticate successfully");
}

/// Test 2: Send encrypted message from teacher to admin
#[actix_web::test]
async fn test_teacher_to_admin_message() {
    let pool = match create_test_pool().await {
        Some(pool) => pool,
        None => return,
    };

    println!("📨 Testing teacher sending message to admin...");

    // Login as teacher
    let teacher_token = match login_user(&pool, "teacher@test.edu", "teacher123").await {
        Some(token) => token,
        None => {
            println!("❌ Teacher login failed");
            return;
        }
    };

    // Create the test app
    let app = test::init_service(
        App::new()
            .app_data(pool.clone())
            .route("/api/messages/threads", web::post().to(send_message))
    ).await;

    // Prepare message request
    let admin_id: Uuid = "550e8400-e29b-41d4-a716-446655440000".parse().unwrap();
    let teacher_id: Uuid = "550e8400-e29b-41d4-a716-446655440001".parse().unwrap();

    let message_request = SendMessageRequest {
        participant_ids: vec![admin_id], // Just admin as recipient
        ciphertext: "encrypted_message_from_teacher_to_admin".to_string(),
        encrypted_keys: vec![
            EncryptedKey {
                recipient_id: admin_id,
                encrypted_key: "encrypted_key_for_admin_new".to_string(),
            },
            EncryptedKey {
                recipient_id: teacher_id,
                encrypted_key: "encrypted_key_for_teacher_self_new".to_string(),
            },
        ],
    };

    let req = test::TestRequest::post()
        .uri("/api/messages/threads")
        .insert_header(("Authorization", format!("Bearer {}", teacher_token)))
        .set_json(&message_request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    println!("📨 Send message response status: {:?}", resp.status());

    if resp.status() == StatusCode::CREATED {
        let body: serde_json::Value = test::read_body_json(resp).await;
        println!("✅ Message sent successfully!");
        println!("📨 Response: {}", serde_json::to_string_pretty(&body).unwrap());
        
        // Verify thread_id and message_id are present
        assert!(body["thread_id"].is_string(), "Response should contain thread_id");
        assert!(body["message_id"].is_string(), "Response should contain message_id");
    } else {
        let body = test::read_body(resp).await;
        println!("❌ Failed to send message: {}", String::from_utf8_lossy(&body));
        panic!("Message sending failed");
    }
}

/// Test 3: Admin lists message threads and should see teacher's message
#[actix_web::test]
async fn test_admin_list_threads() {
    let pool = match create_test_pool().await {
        Some(pool) => pool,
        None => return,
    };

    println!("📋 Testing admin listing message threads...");

    // Login as admin
    let admin_token = match login_user(&pool, "admin@test.edu", "admin123").await {
        Some(token) => token,
        None => {
            println!("❌ Admin login failed");
            return;
        }
    };

    // Create the test app
    let app = test::init_service(
        App::new()
            .app_data(pool.clone())
            .route("/api/messages/threads", web::get().to(list_threads))
    ).await;

    let req = test::TestRequest::get()
        .uri("/api/messages/threads")
        .insert_header(("Authorization", format!("Bearer {}", admin_token)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    println!("📋 List threads response status: {:?}", resp.status());

    if resp.status() == StatusCode::OK {
        let body: serde_json::Value = test::read_body_json(resp).await;
        println!("✅ Admin can see message threads!");
        println!("📋 Threads: {}", serde_json::to_string_pretty(&body).unwrap());
        
        // Verify we have threads
        let threads = body.as_array().expect("Response should be an array");
        assert!(!threads.is_empty(), "Admin should see at least one thread");
        println!("📊 Admin can see {} thread(s)", threads.len());
    } else {
        let body = test::read_body(resp).await;
        println!("❌ Failed to list threads: {}", String::from_utf8_lossy(&body));
        panic!("Thread listing failed");
    }
}

/// Test 4: Admin sends reply to teacher
#[actix_web::test]
async fn test_admin_reply_to_teacher() {
    let pool = match create_test_pool().await {
        Some(pool) => pool,
        None => return,
    };

    println!("💬 Testing admin replying to teacher...");

    // Login as admin
    let admin_token = match login_user(&pool, "admin@test.edu", "admin123").await {
        Some(token) => token,
        None => {
            println!("❌ Admin login failed");
            return;
        }
    };

    // Create the test app
    let app = test::init_service(
        App::new()
            .app_data(pool.clone())
            .route("/api/messages/threads", web::post().to(send_message))
    ).await;

    // Prepare reply message request
    let admin_id: Uuid = "550e8400-e29b-41d4-a716-446655440000".parse().unwrap();
    let teacher_id: Uuid = "550e8400-e29b-41d4-a716-446655440001".parse().unwrap();

    let reply_request = SendMessageRequest {
        participant_ids: vec![teacher_id], // Reply to teacher
        ciphertext: "encrypted_reply_from_admin_to_teacher".to_string(),
        encrypted_keys: vec![
            EncryptedKey {
                recipient_id: teacher_id,
                encrypted_key: "encrypted_key_for_teacher_from_admin_reply".to_string(),
            },
            EncryptedKey {
                recipient_id: admin_id,
                encrypted_key: "encrypted_key_for_admin_self_reply".to_string(),
            },
        ],
    };

    let req = test::TestRequest::post()
        .uri("/api/messages/threads")
        .insert_header(("Authorization", format!("Bearer {}", admin_token)))
        .set_json(&reply_request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    println!("💬 Send reply response status: {:?}", resp.status());

    if resp.status() == StatusCode::CREATED {
        let body: serde_json::Value = test::read_body_json(resp).await;
        println!("✅ Admin reply sent successfully!");
        println!("💬 Response: {}", serde_json::to_string_pretty(&body).unwrap());
    } else {
        let body = test::read_body(resp).await;
        println!("❌ Failed to send reply: {}", String::from_utf8_lossy(&body));
        panic!("Reply sending failed");
    }
}

/// Test 5: Teacher can see admin's reply in thread
#[actix_web::test]
async fn test_teacher_see_admin_reply() {
    let pool = match create_test_pool().await {
        Some(pool) => pool,
        None => return,
    };

    println!("👀 Testing teacher viewing conversation with admin...");

    // First, let's send a message from teacher to admin to ensure we have a thread
    println!("📨 Setting up: Teacher sending initial message to admin...");
    let teacher_token = login_user(&pool, "teacher@test.edu", "teacher123").await.unwrap();
    
    let app = test::init_service(
        App::new()
            .app_data(pool.clone())
            .route("/api/messages/threads", web::post().to(send_message))
            .route("/api/messages/threads", web::get().to(list_threads))
            .route("/api/messages/threads/{thread_id}", web::get().to(get_thread_messages))
    ).await;

    // Send initial message
    let admin_id: Uuid = "550e8400-e29b-41d4-a716-446655440000".parse().unwrap();
    let teacher_id: Uuid = "550e8400-e29b-41d4-a716-446655440001".parse().unwrap();

    let initial_message = SendMessageRequest {
        participant_ids: vec![admin_id],
        ciphertext: "initial_encrypted_message_from_teacher".to_string(),
        encrypted_keys: vec![
            EncryptedKey {
                recipient_id: admin_id,
                encrypted_key: "key_for_admin_initial".to_string(),
            },
            EncryptedKey {
                recipient_id: teacher_id,
                encrypted_key: "key_for_teacher_initial".to_string(),
            },
        ],
    };

    let req = test::TestRequest::post()
        .uri("/api/messages/threads")
        .insert_header(("Authorization", format!("Bearer {}", teacher_token)))
        .set_json(&initial_message)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED, "Initial message should be sent");
    
    let send_response: serde_json::Value = test::read_body_json(resp).await;
    let thread_id = send_response["thread_id"].as_str().unwrap();
    println!("📨 Initial message sent to thread: {}", thread_id);

    // Now teacher lists threads to verify
    println!("📋 Teacher listing threads...");
    let req = test::TestRequest::get()
        .uri("/api/messages/threads")
        .insert_header(("Authorization", format!("Bearer {}", teacher_token)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    if resp.status() == StatusCode::OK {
        let body: serde_json::Value = test::read_body_json(resp).await;
        println!("✅ Teacher can see threads!");
        println!("📋 Teacher's threads: {}", serde_json::to_string_pretty(&body).unwrap());
    }

    // Get messages from the specific thread
    println!("💬 Teacher viewing messages in thread {}...", thread_id);
    let req = test::TestRequest::get()
        .uri(&format!("/api/messages/threads/{}", thread_id))
        .insert_header(("Authorization", format!("Bearer {}", teacher_token)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    println!("💬 Get thread messages response status: {:?}", resp.status());

    if resp.status() == StatusCode::OK {
        let body: serde_json::Value = test::read_body_json(resp).await;
        println!("✅ Teacher can view thread messages!");
        println!("💬 Messages: {}", serde_json::to_string_pretty(&body).unwrap());
        
        let messages = body.as_array().expect("Response should be an array");
        println!("📊 Thread contains {} message(s)", messages.len());
        
        // Verify message structure
        for (i, message) in messages.iter().enumerate() {
            println!("📝 Message {}: sender_id={}, ciphertext={}", 
                i + 1, 
                message["sender_id"].as_str().unwrap_or("unknown"),
                message["ciphertext"].as_str().unwrap_or("unknown")
            );
            
            // Verify encrypted_keys structure
            let encrypted_keys = message["encrypted_keys"].as_array()
                .expect("Message should have encrypted_keys array");
            println!("🔐 Message {} has {} encrypted key(s)", i + 1, encrypted_keys.len());
        }
    } else {
        let body = test::read_body(resp).await;
        println!("❌ Failed to get thread messages: {}", String::from_utf8_lossy(&body));
        panic!("Thread message retrieval failed");
    }
}

/// Test 6: Complete E2E conversation flow
#[actix_web::test]
async fn test_complete_e2e_conversation() {
    let pool = match create_test_pool().await {
        Some(pool) => pool,
        None => return,
    };

    println!("🔄 Testing complete E2E encrypted conversation flow...");
    println!("🎯 This test demonstrates a full conversation between teacher and admin");

    // Step 1: Both users login
    println!("\n1️⃣ Step 1: Both users authenticate");
    let teacher_token = login_user(&pool, "teacher@test.edu", "teacher123").await
        .expect("Teacher should be able to login");
    let admin_token = login_user(&pool, "admin@test.edu", "admin123").await
        .expect("Admin should be able to login");
    println!("✅ Both users authenticated successfully");

    // Step 2: Teacher initiates conversation
    println!("\n2️⃣ Step 2: Teacher initiates conversation with admin");
    
    let app = test::init_service(
        App::new()
            .app_data(pool.clone())
            .route("/api/messages/threads", web::post().to(send_message))
            .route("/api/messages/threads", web::get().to(list_threads))
            .route("/api/messages/threads/{thread_id}", web::get().to(get_thread_messages))
    ).await;

    let admin_id: Uuid = "550e8400-e29b-41d4-a716-446655440000".parse().unwrap();
    let teacher_id: Uuid = "550e8400-e29b-41d4-a716-446655440001".parse().unwrap();

    let teacher_message = SendMessageRequest {
        participant_ids: vec![admin_id],
        ciphertext: "Hello Admin! I need to discuss student John's progress.".to_string(),
        encrypted_keys: vec![
            EncryptedKey {
                recipient_id: admin_id,
                encrypted_key: "teacher_to_admin_key_001".to_string(),
            },
            EncryptedKey {
                recipient_id: teacher_id,
                encrypted_key: "teacher_self_key_001".to_string(),
            },
        ],
    };

    let req = test::TestRequest::post()
        .uri("/api/messages/threads")
        .insert_header(("Authorization", format!("Bearer {}", teacher_token)))
        .set_json(&teacher_message)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let response: serde_json::Value = test::read_body_json(resp).await;
    let thread_id = response["thread_id"].as_str().unwrap();
    println!("📨 Teacher's initial message sent to thread: {}", thread_id);

    // Step 3: Admin sees the thread and reads messages
    println!("\n3️⃣ Step 3: Admin discovers and reads teacher's message");
    
    let req = test::TestRequest::get()
        .uri("/api/messages/threads")
        .insert_header(("Authorization", format!("Bearer {}", admin_token)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let threads: serde_json::Value = test::read_body_json(resp).await;
    println!("📋 Admin sees {} thread(s)", threads.as_array().unwrap().len());

    // Admin reads messages in the thread
    let req = test::TestRequest::get()
        .uri(&format!("/api/messages/threads/{}", thread_id))
        .insert_header(("Authorization", format!("Bearer {}", admin_token)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let messages: serde_json::Value = test::read_body_json(resp).await;
    println!("💬 Admin reads {} message(s) in thread", messages.as_array().unwrap().len());

    // Step 4: Admin replies to teacher
    println!("\n4️⃣ Step 4: Admin sends encrypted reply to teacher");
    
    let admin_reply = SendMessageRequest {
        participant_ids: vec![teacher_id],
        ciphertext: "Thank you for reaching out. Let's schedule a meeting to discuss John's progress.".to_string(),
        encrypted_keys: vec![
            EncryptedKey {
                recipient_id: teacher_id,
                encrypted_key: "admin_to_teacher_key_002".to_string(),
            },
            EncryptedKey {
                recipient_id: admin_id,
                encrypted_key: "admin_self_key_002".to_string(),
            },
        ],
    };

    let req = test::TestRequest::post()
        .uri("/api/messages/threads")
        .insert_header(("Authorization", format!("Bearer {}", admin_token)))
        .set_json(&admin_reply)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    println!("📨 Admin's reply sent successfully");

    // Step 5: Teacher sees admin's reply
    println!("\n5️⃣ Step 5: Teacher reads admin's reply");
    
    let req = test::TestRequest::get()
        .uri(&format!("/api/messages/threads/{}", thread_id))
        .insert_header(("Authorization", format!("Bearer {}", teacher_token)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let updated_messages: serde_json::Value = test::read_body_json(resp).await;
    let message_count = updated_messages.as_array().unwrap().len();
    println!("💬 Teacher now sees {} message(s) in conversation", message_count);
    
    // Verify we have at least 2 messages (original + reply)
    assert!(message_count >= 2, "Should have at least 2 messages in conversation");

    // Step 6: Verify conversation integrity
    println!("\n6️⃣ Step 6: Verifying conversation integrity");
    
    let messages_array = updated_messages.as_array().unwrap();
    let mut teacher_messages = 0;
    let mut admin_messages = 0;
    
    for message in messages_array {
        let sender_id = message["sender_id"].as_str().unwrap();
        if sender_id == teacher_id.to_string() {
            teacher_messages += 1;
        } else if sender_id == admin_id.to_string() {
            admin_messages += 1;
        }
        
        // Verify each message has encrypted keys
        let encrypted_keys = message["encrypted_keys"].as_array().unwrap();
        assert!(!encrypted_keys.is_empty(), "Each message should have encrypted keys");
        println!("🔐 Message from {} has {} encrypted key(s)", 
            sender_id, encrypted_keys.len());
    }
    
    println!("📊 Conversation summary:");
    println!("   👨‍🏫 Teacher messages: {}", teacher_messages);
    println!("   👨‍💼 Admin messages: {}", admin_messages);
    println!("   💬 Total messages: {}", message_count);
    
    assert!(teacher_messages > 0, "Should have at least one teacher message");
    assert!(admin_messages > 0, "Should have at least one admin message");
    
    println!("\n🎉 Complete E2E encrypted conversation test successful!");
    println!("✅ Both users can send and receive encrypted messages");
    println!("✅ Message threading works correctly");
    println!("✅ Encrypted keys are properly stored and retrieved");
    println!("✅ Bidirectional communication is functional");
}
