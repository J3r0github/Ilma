use chrono::{DateTime, Utc, NaiveDate};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::models::{UserRole, AttendanceStatus, EncryptedKey};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestConfig {
    pub version: String,
    pub description: Option<String>,
    pub rollback_on_shutdown: bool,
    pub users: Vec<TestUser>,
    pub classes: Vec<TestClass>,
    pub grades: Vec<TestGrade>,
    pub attendance: Vec<TestAttendance>,
    pub schedule_events: Vec<TestScheduleEvent>,
    pub messages: Vec<TestMessage>,
    pub threads: Vec<TestThread>,
    pub permissions: Vec<TestUserPermissions>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestUser {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub password: String,
    pub role: UserRole,
    pub is_superuser: bool,
    pub public_key: String,
    pub recovery_key: Option<String>,
    pub encrypted_private_key_blob: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestClass {
    pub id: Uuid,
    pub name: String,
    pub teacher_id: Uuid,
    pub students: Vec<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestGrade {
    pub id: Uuid,
    pub student_id: Uuid,
    pub class_id: Uuid,
    pub teacher_id: Uuid,
    pub grade: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestAttendance {
    pub id: Uuid,
    pub student_id: Uuid,
    pub class_id: Uuid,
    pub status: AttendanceStatus,
    pub recorded_by: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestScheduleEvent {
    pub id: Uuid,
    pub title: String,
    pub description: Option<String>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub date: NaiveDate,
    pub class_id: Option<Uuid>,
    pub teacher_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestMessage {
    pub id: Uuid,
    pub thread_id: Uuid,
    pub sender_id: Uuid,
    pub ciphertext: String,
    pub encrypted_keys: Vec<EncryptedKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestThread {
    pub id: Uuid,
    pub participants: Vec<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestUserPermissions {
    pub user_id: Uuid,
    pub permission_ids: Vec<i32>,
}

#[derive(Debug, Clone)]
pub struct TestDataTracker {
    pub user_ids: Vec<Uuid>,
    pub class_ids: Vec<Uuid>,
    pub grade_ids: Vec<Uuid>,
    pub attendance_ids: Vec<Uuid>,
    pub schedule_event_ids: Vec<Uuid>,
    pub message_ids: Vec<Uuid>,
    pub thread_ids: Vec<Uuid>,
}

impl TestDataTracker {
    pub fn new() -> Self {
        Self {
            user_ids: Vec::new(),
            class_ids: Vec::new(),
            grade_ids: Vec::new(),
            attendance_ids: Vec::new(),
            schedule_event_ids: Vec::new(),
            message_ids: Vec::new(),
            thread_ids: Vec::new(),
        }
    }

    pub fn add_user(&mut self, id: Uuid) {
        self.user_ids.push(id);
    }

    pub fn add_class(&mut self, id: Uuid) {
        self.class_ids.push(id);
    }

    pub fn add_grade(&mut self, id: Uuid) {
        self.grade_ids.push(id);
    }

    pub fn add_attendance(&mut self, id: Uuid) {
        self.attendance_ids.push(id);
    }

    pub fn add_schedule_event(&mut self, id: Uuid) {
        self.schedule_event_ids.push(id);
    }

    pub fn add_message(&mut self, id: Uuid) {
        self.message_ids.push(id);
    }

    pub fn add_thread(&mut self, id: Uuid) {
        self.thread_ids.push(id);
    }
}

impl TestConfig {
    pub fn load_from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: TestConfig = serde_json::from_str(&content)?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), String> {
        // Check if all referenced IDs exist
        let user_ids: std::collections::HashSet<_> = self.users.iter().map(|u| u.id).collect();
        
        // Validate class teacher references
        for class in &self.classes {
            if !user_ids.contains(&class.teacher_id) {
                return Err(format!("Class '{}' references non-existent teacher ID: {}", class.name, class.teacher_id));
            }
            for student_id in &class.students {
                if !user_ids.contains(student_id) {
                    return Err(format!("Class '{}' references non-existent student ID: {}", class.name, student_id));
                }
            }
        }

        // Validate grade references
        let class_ids: std::collections::HashSet<_> = self.classes.iter().map(|c| c.id).collect();
        for grade in &self.grades {
            if !user_ids.contains(&grade.student_id) {
                return Err(format!("Grade references non-existent student ID: {}", grade.student_id));
            }
            if !class_ids.contains(&grade.class_id) {
                return Err(format!("Grade references non-existent class ID: {}", grade.class_id));
            }
            if !user_ids.contains(&grade.teacher_id) {
                return Err(format!("Grade references non-existent teacher ID: {}", grade.teacher_id));
            }
        }

        // Validate attendance references
        for attendance in &self.attendance {
            if !user_ids.contains(&attendance.student_id) {
                return Err(format!("Attendance references non-existent student ID: {}", attendance.student_id));
            }
            if !class_ids.contains(&attendance.class_id) {
                return Err(format!("Attendance references non-existent class ID: {}", attendance.class_id));
            }
            if !user_ids.contains(&attendance.recorded_by) {
                return Err(format!("Attendance references non-existent recorder ID: {}", attendance.recorded_by));
            }
        }

        // Validate schedule event references
        for event in &self.schedule_events {
            if let Some(class_id) = event.class_id {
                if !class_ids.contains(&class_id) {
                    return Err(format!("Schedule event '{}' references non-existent class ID: {}", event.title, class_id));
                }
            }
            if let Some(teacher_id) = event.teacher_id {
                if !user_ids.contains(&teacher_id) {
                    return Err(format!("Schedule event '{}' references non-existent teacher ID: {}", event.title, teacher_id));
                }
            }
        }

        // Validate message and thread references
        let thread_ids: std::collections::HashSet<_> = self.threads.iter().map(|t| t.id).collect();
        for message in &self.messages {
            if !thread_ids.contains(&message.thread_id) {
                return Err(format!("Message references non-existent thread ID: {}", message.thread_id));
            }
            if !user_ids.contains(&message.sender_id) {
                return Err(format!("Message references non-existent sender ID: {}", message.sender_id));
            }
            for encrypted_key in &message.encrypted_keys {
                if !user_ids.contains(&encrypted_key.recipient_id) {
                    return Err(format!("Message encrypted key references non-existent recipient ID: {}", encrypted_key.recipient_id));
                }
            }
        }

        // Validate thread participants
        for thread in &self.threads {
            for participant_id in &thread.participants {
                if !user_ids.contains(participant_id) {
                    return Err(format!("Thread references non-existent participant ID: {}", participant_id));
                }
            }
        }

        // Validate permissions
        for permission in &self.permissions {
            if !user_ids.contains(&permission.user_id) {
                return Err(format!("Permission assignment references non-existent user ID: {}", permission.user_id));
            }
        }

        Ok(())
    }
}
