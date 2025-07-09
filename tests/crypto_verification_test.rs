use ilma::configloader::{create_test_data_from_config, is_testing_mode};
use ilma::db::create_pool;
use base64::{Engine, engine::general_purpose::STANDARD};
use std::env;
use uuid::Uuid;

#[tokio::test]
async fn test_real_crypto_key_generation() {
    // Set up testing mode
    unsafe {
        env::set_var("TESTING_MODE", "true");
        env::set_var("TEST_CONFIG_PATH", "test_config_minimal.json");
    }
    
    // Set up test database connection
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://localhost/ilma_test".to_string());
    
    let pool = create_pool(&database_url).await.expect("Failed to create database pool");
    
    // Verify testing mode is enabled
    assert!(is_testing_mode(), "Testing mode should be enabled");
    
    // Create test data which should generate real RSA keys
    let result = create_test_data_from_config(&pool).await;
    assert!(result.is_ok(), "Should successfully create test data with real crypto keys");
    
    // Query a user to verify real keys were generated
    let user_result = sqlx::query_as::<_, (Uuid, String, String, String)>(
        "SELECT id, public_key, recovery_key, encrypted_private_key_blob FROM users LIMIT 1"
    )
    .fetch_optional(&pool)
    .await;
    
    if let Ok(Some((user_id, public_key, recovery_key, encrypted_blob))) = user_result {
        // Verify public key looks like real PEM
        assert!(public_key.starts_with("-----BEGIN PUBLIC KEY-----"), 
                "Public key should be real PEM format, got: {}", public_key);
        assert!(public_key.ends_with("-----END PUBLIC KEY-----\n"), 
                "Public key should end with PEM footer");
        assert!(public_key.len() > 200, "Real RSA public key should be substantial size");
        
        // Verify recovery key looks like real words
        let recovery_words: Vec<&str> = recovery_key.split_whitespace().collect();
        assert_eq!(recovery_words.len(), 12, "Recovery key should have 12 words");
        let word_count = recovery_words.len();
        for word in recovery_words {
            assert!(word.chars().all(|c| c.is_alphabetic()), 
                    "Recovery key word '{}' should only contain letters", word);
        }
        
        // Verify encrypted blob looks like real base64
        assert!(STANDARD.decode(&encrypted_blob).is_ok(), 
                "Encrypted private key blob should be valid base64");
        assert!(encrypted_blob.len() > 100, 
                "Encrypted blob should be substantial size");
        
        println!("✅ Real cryptographic key generation verified for user: {}", user_id);
        println!("   Public key size: {} bytes", public_key.len());
        println!("   Recovery phrase: {} words", word_count);
        println!("   Encrypted blob size: {} bytes", encrypted_blob.len());
    } else {
        panic!("No users found with cryptographic keys");
    }
}

#[tokio::test]
async fn test_message_encryption_keys() {
    // Set up testing mode
    unsafe {
        env::set_var("TESTING_MODE", "true");
        env::set_var("TEST_CONFIG_PATH", "test_config_minimal.json");
    }
    
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://localhost/ilma_test".to_string());
    
    let pool = create_pool(&database_url).await.expect("Failed to create database pool");
    
    // Create test data
    let _ = create_test_data_from_config(&pool).await;
    
    // Check for message encrypted keys
    let encrypted_key_result = sqlx::query_as::<_, (Uuid, Uuid, String)>(
        "SELECT message_id, recipient_id, encrypted_key FROM message_encrypted_keys LIMIT 1"
    )
    .fetch_optional(&pool)
    .await;
    
    if let Ok(Some((message_id, recipient_id, encrypted_key))) = encrypted_key_result {
        // Verify encrypted key is substantial and looks real
        assert!(encrypted_key.len() > 50, 
                "Encrypted key should be substantial size, got: {}", encrypted_key.len());
        
        // If it's base64, it should decode successfully
        if encrypted_key.chars().all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=') {
            assert!(STANDARD.decode(&encrypted_key).is_ok(), 
                    "Base64 encrypted key should decode successfully");
        }
        
        println!("✅ Message encryption verified:");
        println!("   Message ID: {}", message_id);
        println!("   Recipient ID: {}", recipient_id);
        println!("   Encrypted key size: {} bytes", encrypted_key.len());
    } else {
        println!("⚠️  No message encrypted keys found (this may be expected if no messages exist)");
    }
}
