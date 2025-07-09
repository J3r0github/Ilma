use ilma::test_config::TestConfig;

// Helper function to check if testing mode is enabled
fn ensure_testing_mode() {
    if !ilma::configloader::is_testing_mode() {
        println!("Skipping test - TESTING_MODE not enabled");
        return;
    }
}

#[test]
fn test_new_simplified_config_loading() {
    ensure_testing_mode();
    if !ilma::configloader::is_testing_mode() {
        return;
    }
    
    // Test loading the new simplified configuration
    let config = TestConfig::load_from_file("test_config_new.json")
        .expect("Should be able to load new simplified test configuration");
    
    // Verify the configuration structure
    assert_eq!(config.version, "1.0");
    assert_eq!(config.users.len(), 4);
    assert_eq!(config.classes.len(), 1);
    assert_eq!(config.grades.len(), 1);
    assert_eq!(config.attendance.len(), 1);
    assert_eq!(config.schedule_events.len(), 1);
    assert_eq!(config.messages.len(), 4);
    assert_eq!(config.threads.len(), 3);
    assert_eq!(config.permissions.len(), 2);
    
    println!("✅ New simplified config loaded successfully");
}

#[test]
fn test_new_config_validation() {
    ensure_testing_mode();
    if !ilma::configloader::is_testing_mode() {
        return;
    }
    
    let config = TestConfig::load_from_file("test_config_new.json")
        .expect("Should be able to load new simplified test configuration");
    
    // Test validation
    config.validate()
        .expect("New configuration validation should pass");
        
    println!("✅ New config validation passed");
}

#[test]
fn test_user_configuration_without_keys() {
    ensure_testing_mode();
    if !ilma::configloader::is_testing_mode() {
        return;
    }
    
    let config = TestConfig::load_from_file("test_config_new.json")
        .expect("Should be able to load new simplified test configuration");
    
    // Verify user structure
    let admin_user = &config.users[0];
    assert_eq!(admin_user.email, "admin@test.edu");
    assert_eq!(admin_user.role.to_string(), "principal");
    assert_eq!(admin_user.is_superuser, true);
    
    // Verify that users don't have hardcoded keys (they'll be auto-generated)
    // Note: The TestUser struct no longer has public_key, recovery_key, or encrypted_private_key_blob fields
    
    let teacher_user = &config.users[1];
    assert_eq!(teacher_user.email, "teacher@test.edu");
    assert_eq!(teacher_user.role.to_string(), "teacher");
    assert_eq!(teacher_user.is_superuser, false);
    
    println!("✅ User configuration without hardcoded keys verified");
}

#[test]
fn test_message_configuration_with_content() {
    ensure_testing_mode();
    if !ilma::configloader::is_testing_mode() {
        return;
    }
    
    let config = TestConfig::load_from_file("test_config_new.json")
        .expect("Should be able to load new simplified test configuration");
    
    // Verify message structure with plain text content
    let first_message = &config.messages[0];
    assert_eq!(first_message.content, "Hello Dr. Johnson, how are you today?");
    assert_eq!(first_message.sender_id.to_string(), "550e8400-e29b-41d4-a716-446655440001");
    
    let second_message = &config.messages[1];
    assert_eq!(second_message.content, "Hello Ms. Wilson! I'm doing well, thank you for asking.");
    
    // Verify that messages now have plain text content instead of ciphertext and encrypted_keys
    // The TestMessage struct now has a 'content' field instead of 'ciphertext' and 'encrypted_keys'
    
    println!("✅ Message configuration with plain text content verified");
}

#[test]
fn test_thread_participant_integrity() {
    ensure_testing_mode();
    if !ilma::configloader::is_testing_mode() {
        return;
    }
    
    let config = TestConfig::load_from_file("test_config_new.json")
        .expect("Should be able to load new simplified test configuration");
    
    // Collect all user IDs
    let user_ids: std::collections::HashSet<_> = config.users.iter().map(|u| u.id).collect();
    
    // Verify thread participants exist
    for thread in &config.threads {
        for participant_id in &thread.participants {
            assert!(user_ids.contains(participant_id), 
                    "Thread participant {} should exist as a user", participant_id);
        }
    }
    
    // Verify message senders exist and are participants in their threads
    let thread_participants: std::collections::HashMap<_, _> = config.threads.iter()
        .map(|t| (t.id, &t.participants))
        .collect();
        
    for message in &config.messages {
        assert!(user_ids.contains(&message.sender_id), 
                "Message sender {} should exist as a user", message.sender_id);
                
        if let Some(participants) = thread_participants.get(&message.thread_id) {
            assert!(participants.contains(&message.sender_id),
                    "Message sender {} should be a participant in thread {}", 
                    message.sender_id, message.thread_id);
        }
    }
    
    println!("✅ Thread and message integrity verified");
}

#[test]
fn test_config_completeness() {
    ensure_testing_mode();
    if !ilma::configloader::is_testing_mode() {
        return;
    }
    
    let config = TestConfig::load_from_file("test_config_new.json")
        .expect("Should be able to load new simplified test configuration");
    
    // Verify all required sections are present
    assert!(!config.users.is_empty(), "Should have users");
    assert!(!config.classes.is_empty(), "Should have classes");
    assert!(!config.messages.is_empty(), "Should have messages");
    assert!(!config.threads.is_empty(), "Should have threads");
    
    // Verify user roles are diverse
    let roles: std::collections::HashSet<_> = config.users.iter().map(|u| &u.role).collect();
    assert!(roles.len() > 1, "Should have users with different roles");
    
    // Verify there's at least one admin
    let has_admin = config.users.iter().any(|u| u.is_superuser);
    assert!(has_admin, "Should have at least one superuser");
    
    println!("✅ Configuration completeness verified");
}
