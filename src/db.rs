use sentry;
use sqlx::{PgPool, Postgres, migrate::MigrateDatabase};
use log::{info, error};
use std::process;

pub type DbPool = PgPool;

pub async fn create_pool(database_url: &str) -> Result<DbPool, sqlx::Error> {
    // Create database if it doesn't exist
    if !Postgres::database_exists(database_url).await.unwrap_or(false) {
        info!("Creating database...");
        match Postgres::create_database(database_url).await {
            Ok(_) => info!("Database created successfully."),
            Err(error) => {
                error!("Error creating database: {}", error);
                sentry::capture_error(&error);
                process::exit(1);
            }
        }
    } else {
        info!("Database already exists");
    }

    // Create connection pool
    PgPool::connect(database_url).await
}

pub async fn run_migrations(pool: &DbPool) -> Result<(), sqlx::Error> {
    info!("Running database migrations...");
    
    // Create user_role enum type
    let migration_result = sqlx::query(r#"
        DO $$ BEGIN
            CREATE TYPE user_role AS ENUM ('student', 'teacher', 'principal');
        EXCEPTION
            WHEN duplicate_object THEN null;
        END $$;
    "#)
    .execute(pool)
    .await;
    if let Err(e) = migration_result {
        error!("Migration error (user_role): {}", e);
        sentry::capture_error(&e);
        return Err(e);
    }

    // Create attendance_status enum type
    sqlx::query(r#"
        DO $$ BEGIN
            CREATE TYPE attendance_status AS ENUM ('present', 'absent', 'late');
        EXCEPTION
            WHEN duplicate_object THEN null;
        END $$;
    "#)
    .execute(pool)
    .await?;

    // Create users table
    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            role user_role NOT NULL,
            is_superuser BOOLEAN DEFAULT FALSE,
            public_key TEXT NOT NULL,
            recovery_key TEXT,
            encrypted_private_key_blob TEXT,
            first_names VARCHAR(255),
            chosen_name VARCHAR(255),
            last_name VARCHAR(255),
            name_short VARCHAR(50),
            birthday DATE,
            ssn VARCHAR(20),
            learner_number VARCHAR(100),
            person_oid VARCHAR(100),
            avatar_url TEXT,
            phone VARCHAR(50),
            address TEXT,
            enrollment_date DATE,
            graduation_date DATE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )
    "#)
    .execute(pool)
    .await?;

    // Add new fields to existing users table if they don't exist
    sqlx::query(r#"
        ALTER TABLE users 
        ADD COLUMN IF NOT EXISTS first_names VARCHAR(255),
        ADD COLUMN IF NOT EXISTS chosen_name VARCHAR(255),
        ADD COLUMN IF NOT EXISTS last_name VARCHAR(255),
        ADD COLUMN IF NOT EXISTS name_short VARCHAR(50),
        ADD COLUMN IF NOT EXISTS birthday DATE,
        ADD COLUMN IF NOT EXISTS ssn VARCHAR(20),
        ADD COLUMN IF NOT EXISTS learner_number VARCHAR(100),
        ADD COLUMN IF NOT EXISTS person_oid VARCHAR(100),
        ADD COLUMN IF NOT EXISTS avatar_url TEXT,
        ADD COLUMN IF NOT EXISTS phone VARCHAR(50),
        ADD COLUMN IF NOT EXISTS address TEXT,
        ADD COLUMN IF NOT EXISTS enrollment_date DATE,
        ADD COLUMN IF NOT EXISTS graduation_date DATE;
    "#)
    .execute(pool)
    .await?;

    // Add recovery_key column if it doesn't exist
    sqlx::query(r#"
        ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_key TEXT;
    "#)
    .execute(pool)
    .await?;

    // Add encrypted_private_key_blob column if it doesn't exist
    sqlx::query(r#"
        ALTER TABLE users ADD COLUMN IF NOT EXISTS encrypted_private_key_blob TEXT;
    "#)
    .execute(pool)
    .await?;

    // Drop username column and its constraint if they exist (removing deprecated field)
    sqlx::query(r#"
        DO $$ BEGIN
            IF EXISTS (
                SELECT 1 FROM information_schema.table_constraints 
                WHERE constraint_name = 'users_username_key' 
                AND table_name = 'users'
            ) THEN
                ALTER TABLE users DROP CONSTRAINT users_username_key;
            END IF;
        END $$;
    "#)
    .execute(pool)
    .await?;

    sqlx::query(r#"
        ALTER TABLE users DROP COLUMN IF EXISTS username;
    "#)
    .execute(pool)
    .await?;

    // Create password reset tokens table
    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token VARCHAR(255) UNIQUE NOT NULL,
            expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            used BOOLEAN DEFAULT FALSE
        )
    "#)
    .execute(pool)
    .await?;

    // Create permissions table
    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS permissions (
            id SERIAL PRIMARY KEY,
            name VARCHAR(100) UNIQUE NOT NULL,
            description TEXT
        )
    "#)
    .execute(pool)
    .await?;

    // Create permission_sets table
    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS permission_sets (
            id SERIAL PRIMARY KEY,
            name VARCHAR(100) UNIQUE NOT NULL
        )
    "#)
    .execute(pool)
    .await?;

    // Create permission_set_permissions table
    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS permission_set_permissions (
            permission_set_id INTEGER REFERENCES permission_sets(id) ON DELETE CASCADE,
            permission_id INTEGER REFERENCES permissions(id) ON DELETE CASCADE,
            PRIMARY KEY (permission_set_id, permission_id)
        )
    "#)
    .execute(pool)
    .await?;

    // Create user_permissions table
    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS user_permissions (
            user_id UUID REFERENCES users(id) ON DELETE CASCADE,
            permission_id INTEGER REFERENCES permissions(id) ON DELETE CASCADE,
            PRIMARY KEY (user_id, permission_id)
        )
    "#)
    .execute(pool)
    .await?;

    // Create classes table
    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS classes (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name VARCHAR(255) NOT NULL,
            teacher_id UUID REFERENCES users(id) ON DELETE CASCADE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )
    "#)
    .execute(pool)
    .await?;

    // Create class_students table
    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS class_students (
            class_id UUID REFERENCES classes(id) ON DELETE CASCADE,
            student_id UUID REFERENCES users(id) ON DELETE CASCADE,
            PRIMARY KEY (class_id, student_id)
        )
    "#)
    .execute(pool)
    .await?;

    // Create grades table
    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS grades (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            student_id UUID REFERENCES users(id) ON DELETE CASCADE,
            class_id UUID REFERENCES classes(id) ON DELETE CASCADE,
            teacher_id UUID REFERENCES users(id) ON DELETE CASCADE,
            grade VARCHAR(10) NOT NULL,
            assigned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )
    "#)
    .execute(pool)
    .await?;

    // Create attendance table
    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS attendance (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            student_id UUID REFERENCES users(id) ON DELETE CASCADE,
            class_id UUID REFERENCES classes(id) ON DELETE CASCADE,
            status attendance_status NOT NULL,
            recorded_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            recorded_by UUID REFERENCES users(id) ON DELETE CASCADE
        )
    "#)
    .execute(pool)
    .await?;

    // Create threads table
    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS threads (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )
    "#)
    .execute(pool)
    .await?;

    // Create thread_participants table
    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS thread_participants (
            thread_id UUID REFERENCES threads(id) ON DELETE CASCADE,
            user_id UUID REFERENCES users(id) ON DELETE CASCADE,
            PRIMARY KEY (thread_id, user_id)
        )
    "#)
    .execute(pool)
    .await?;

    // Create messages table
    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS messages (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            thread_id UUID REFERENCES threads(id) ON DELETE CASCADE,
            sender_id UUID REFERENCES users(id) ON DELETE CASCADE,
            ciphertext TEXT NOT NULL,
            sent_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )
    "#)
    .execute(pool)
    .await?;

    // Create message_encrypted_keys table
    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS message_encrypted_keys (
            message_id UUID REFERENCES messages(id) ON DELETE CASCADE,
            recipient_id UUID REFERENCES users(id) ON DELETE CASCADE,
            encrypted_key TEXT NOT NULL,
            PRIMARY KEY (message_id, recipient_id)
        )
    "#)
    .execute(pool)
    .await?;

    // Create schedule_events table
    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS schedule_events (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            title VARCHAR(255) NOT NULL,
            description TEXT,
            start_time TIMESTAMP WITH TIME ZONE NOT NULL,
            end_time TIMESTAMP WITH TIME ZONE NOT NULL,
            date DATE NOT NULL,
            class_id UUID REFERENCES classes(id) ON DELETE CASCADE,
            teacher_id UUID REFERENCES users(id) ON DELETE CASCADE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )
    "#)
    .execute(pool)
    .await?;

    // Insert default permissions
    sqlx::query(r#"
        INSERT INTO permissions (name, description) VALUES
        ('create_user', 'Create new users'),
        ('manage_classes', 'Create and manage classes'),
        ('assign_grades', 'Assign grades to students'),
        ('record_attendance', 'Record student attendance'),
        ('send_messages', 'Send encrypted messages'),
        ('view_all_users', 'View all users in the system')
        ON CONFLICT (name) DO NOTHING
    "#)
    .execute(pool)
    .await?;

    info!("Database migrations completed successfully.");
    Ok(())
}
