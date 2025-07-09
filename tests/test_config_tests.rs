use ilma::test_config::TestConfig;

// Helper function to check if testing mode is enabled
fn ensure_testing_mode() {
    if !ilma::configloader::is_testing_mode() {
        println!("Skipping test - TESTING_MODE not enabled");
        return;
    }
}

#[test]
fn test_json_config_loading() {
    ensure_testing_mode();
    if !ilma::configloader::is_testing_mode() {
        return;
    }
    
    // Test loading the configuration
    let config = TestConfig::load_from_file("test_config.json")
        .expect("Should be able to load test configuration");
    
    // Verify the configuration structure
    assert_eq!(config.version, "1.0");
    assert_eq!(config.users.len(), 4);
    assert_eq!(config.classes.len(), 2);
    assert_eq!(config.grades.len(), 2);
    assert_eq!(config.attendance.len(), 2);
    assert_eq!(config.schedule_events.len(), 2);
    assert_eq!(config.messages.len(), 4);
    assert_eq!(config.threads.len(), 3);
    assert_eq!(config.permissions.len(), 2);
}

#[test]
fn test_config_validation() {
    ensure_testing_mode();
    if !ilma::configloader::is_testing_mode() {
        return;
    }
    
    let config = TestConfig::load_from_file("test_config.json")
        .expect("Should be able to load test configuration");
    
    // Test validation
    config.validate()
        .expect("Configuration validation should pass");
}

#[test]
fn test_user_configuration() {
    ensure_testing_mode();
    if !ilma::configloader::is_testing_mode() {
        return;
    }
    
    let config = TestConfig::load_from_file("test_config.json")
        .expect("Should be able to load test configuration");
    
    // Verify we have the expected users
    let admin_user = config.users.iter()
        .find(|u| u.email == "admin@test.edu")
        .expect("Should have admin test user");
    
    assert_eq!(admin_user.role, ilma::models::UserRole::Principal);
    assert!(admin_user.is_superuser);
    assert_eq!(admin_user.email, "admin@test.edu");
    
    let teacher_user = config.users.iter()
        .find(|u| u.email == "teacher@test.edu")
        .expect("Should have teacher test user");
    
    assert_eq!(teacher_user.role, ilma::models::UserRole::Teacher);
    assert!(!teacher_user.is_superuser);
    
    // Verify we have student users
    let student_count = config.users.iter()
        .filter(|u| matches!(u.role, ilma::models::UserRole::Student))
        .count();
    assert_eq!(student_count, 2);
}

#[test]
fn test_class_configuration() {
    ensure_testing_mode();
    if !ilma::configloader::is_testing_mode() {
        return;
    }
    
    let config = TestConfig::load_from_file("test_config.json")
        .expect("Should be able to load test configuration");
    
    // Verify classes have proper structure
    let math_class = config.classes.iter()
        .find(|c| c.name == "Test Math Class")
        .expect("Should have Test Math Class");
    
    assert_eq!(math_class.students.len(), 2);
    
    let english_class = config.classes.iter()
        .find(|c| c.name == "Test English Class")
        .expect("Should have Test English Class");
    
    assert_eq!(english_class.students.len(), 1);
}

#[test]
fn test_reference_integrity() {
    ensure_testing_mode();
    if !ilma::configloader::is_testing_mode() {
        return;
    }
    
    let config = TestConfig::load_from_file("test_config.json")
        .expect("Should be able to load test configuration");
    
    let user_ids: std::collections::HashSet<_> = config.users.iter().map(|u| u.id).collect();
    let class_ids: std::collections::HashSet<_> = config.classes.iter().map(|c| c.id).collect();
    
    // Check class teacher references
    for class in &config.classes {
        assert!(user_ids.contains(&class.teacher_id), 
                "Class '{}' references non-existent teacher", class.name);
        
        for student_id in &class.students {
            assert!(user_ids.contains(student_id), 
                    "Class '{}' references non-existent student", class.name);
        }
    }
    
    // Check grade references
    for grade in &config.grades {
        assert!(user_ids.contains(&grade.student_id), 
                "Grade references non-existent student");
        assert!(class_ids.contains(&grade.class_id), 
                "Grade references non-existent class");
        assert!(user_ids.contains(&grade.teacher_id), 
                "Grade references non-existent teacher");
    }
    
    // Check attendance references
    for attendance in &config.attendance {
        assert!(user_ids.contains(&attendance.student_id), 
                "Attendance references non-existent student");
        assert!(class_ids.contains(&attendance.class_id), 
                "Attendance references non-existent class");
        assert!(user_ids.contains(&attendance.recorded_by), 
                "Attendance references non-existent recorder");
    }
}

#[test]
fn test_message_thread_integrity() {
    ensure_testing_mode();
    if !ilma::configloader::is_testing_mode() {
        return;
    }
    
    let config = TestConfig::load_from_file("test_config.json")
        .expect("Should be able to load test configuration");
    
    let user_ids: std::collections::HashSet<_> = config.users.iter().map(|u| u.id).collect();
    let thread_ids: std::collections::HashSet<_> = config.threads.iter().map(|t| t.id).collect();
    
    // Check thread participants
    for thread in &config.threads {
        for participant_id in &thread.participants {
            assert!(user_ids.contains(participant_id), 
                    "Thread references non-existent participant");
        }
    }
    
    // Check message references
    for message in &config.messages {
        assert!(thread_ids.contains(&message.thread_id), 
                "Message references non-existent thread");
        assert!(user_ids.contains(&message.sender_id), 
                "Message references non-existent sender");
        
        // Note: encrypted_keys validation removed - keys are now auto-generated
        // for encrypted_key in &message.encrypted_keys {
        //     assert!(user_ids.contains(&encrypted_key.recipient_id), 
        //             "Message encrypted key references non-existent recipient");
        // }
    }
}

#[test]
fn test_permission_integrity() {
    ensure_testing_mode();
    if !ilma::configloader::is_testing_mode() {
        return;
    }
    
    let config = TestConfig::load_from_file("test_config.json")
        .expect("Should be able to load test configuration");
    
    let user_ids: std::collections::HashSet<_> = config.users.iter().map(|u| u.id).collect();
    
    // Check permission assignments
    for permission in &config.permissions {
        assert!(user_ids.contains(&permission.user_id), 
                "Permission assignment references non-existent user");
        
        // Verify permission IDs are reasonable (assuming permissions 1-10 exist)
        for &permission_id in &permission.permission_ids {
            assert!(permission_id >= 1 && permission_id <= 10, 
                    "Permission ID {} seems out of reasonable range", permission_id);
        }
    }
}

#[test]
fn test_invalid_config_handling() {
    ensure_testing_mode();
    if !ilma::configloader::is_testing_mode() {
        return;
    }
    
    // Test with non-existent file
    let result = TestConfig::load_from_file("non_existent_config.json");
    assert!(result.is_err(), "Should fail to load non-existent file");
}

#[test]
fn test_minimal_config() {
    ensure_testing_mode();
    if !ilma::configloader::is_testing_mode() {
        return;
    }
    
    let config = TestConfig::load_from_file("test_config_minimal.json")
        .expect("Should load minimal configuration");
    
    // Test minimal configuration structure
    assert_eq!(config.version, "1.0");
    assert_eq!(config.users.len(), 1);
    assert_eq!(config.classes.len(), 0);
    assert_eq!(config.grades.len(), 0);
    assert_eq!(config.attendance.len(), 0);
    assert_eq!(config.schedule_events.len(), 0);
    assert_eq!(config.messages.len(), 0);
    assert_eq!(config.threads.len(), 0);
    assert_eq!(config.permissions.len(), 0);
    
    // Validate the minimal configuration
    config.validate()
        .expect("Minimal configuration should validate successfully");
    
    // Check the single user
    let user = &config.users[0];
    assert_eq!(user.email, "minimal@example.com");
    assert_eq!(user.role, ilma::models::UserRole::Student);
    assert!(!user.is_superuser);
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    
    #[test]
    fn test_complete_config_workflow() {
        ensure_testing_mode();
        if !ilma::configloader::is_testing_mode() {
            return;
        }
        
        // This test verifies the complete workflow works
        let config = TestConfig::load_from_file("test_config.json")
            .expect("Should load configuration");
        
        // Validate the entire configuration
        config.validate()
            .expect("Should validate successfully");
        
        // Verify we have a complete test scenario
        assert!(!config.users.is_empty(), "Should have users");
        assert!(!config.classes.is_empty(), "Should have classes");
        
        // Verify the configuration represents a realistic scenario
        let has_admin = config.users.iter().any(|u| u.is_superuser);
        let has_teacher = config.users.iter().any(|u| matches!(u.role, ilma::models::UserRole::Teacher));
        let has_students = config.users.iter().any(|u| matches!(u.role, ilma::models::UserRole::Student));
        
        assert!(has_admin, "Should have at least one admin user");
        assert!(has_teacher, "Should have at least one teacher");
        assert!(has_students, "Should have at least one student");
    }
}

#[test]
fn test_invalid_references() {
    ensure_testing_mode();
    if !ilma::configloader::is_testing_mode() {
        return;
    }
    
    let config = TestConfig::load_from_file("test_config_invalid.json")
        .expect("Should load invalid configuration file");
    
    // The configuration should load but validation should fail
    let validation_result = config.validate();
    assert!(validation_result.is_err(), "Validation should fail for invalid references");
    
    let error_message = validation_result.unwrap_err();
    assert!(error_message.contains("non-existent teacher"), 
            "Error should mention non-existent teacher reference");
}

#[test]
fn test_error_messages_are_helpful() {
    ensure_testing_mode();
    if !ilma::configloader::is_testing_mode() {
        return;
    }
    
    let config = TestConfig::load_from_file("test_config_invalid.json")
        .expect("Should load invalid configuration file");
    
    let validation_result = config.validate();
    assert!(validation_result.is_err());
    
    let error_message = validation_result.unwrap_err();
    
    // The error message should be specific and helpful
    assert!(error_message.contains("Invalid Class"), 
            "Error should mention the specific class name");
    assert!(error_message.contains("99999999-9999-9999-9999-999999999999"), 
            "Error should mention the specific invalid UUID");
}
