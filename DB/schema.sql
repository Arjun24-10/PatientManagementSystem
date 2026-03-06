-- =================================================================================
-- PATIENT MANAGEMENT SYSTEM - Enterprise Schema
-- Architecture: Decoupled Clinical Modules + Active Defense Security
-- =================================================================================

-- 1. CLEANUP
DROP TABLE IF EXISTS consent_log CASCADE;
DROP TABLE IF EXISTS audit_logs CASCADE;
DROP TABLE IF EXISTS lab_tests CASCADE;
DROP TABLE IF EXISTS vital_signs CASCADE;
DROP TABLE IF EXISTS prescriptions CASCADE;
DROP TABLE IF EXISTS medical_records CASCADE;
DROP TABLE IF EXISTS appointments CASCADE;
DROP TABLE IF EXISTS doctor_profiles CASCADE;
DROP TABLE IF EXISTS patient_profiles CASCADE;
DROP TABLE IF EXISTS sessions CASCADE;
DROP TABLE IF EXISTS login CASCADE;

-- 2. ENUMS (Kept for strict typing where JPA doesn't conflict)
CREATE TYPE request_status AS ENUM ('PENDING', 'APPROVED', 'REJECTED');
CREATE TYPE user_role_type AS ENUM ('PATIENT', 'DOCTOR', 'NURSE', 'ADMIN', 'LAB_TECH');

-- =================================================================================
-- CORE IDENTITY & SECURITY (Epic 1 & 5)
-- =================================================================================

CREATE TABLE login (
    user_id BIGSERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'PATIENT', 

    -- Identity Verification
    is_active BOOLEAN DEFAULT TRUE,
    is_verified BOOLEAN DEFAULT FALSE,
    
    -- 2FA Fields (Email + Google Auth)
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    otp VARCHAR(10),
    otp_expiry TIMESTAMP,
    otp_secret VARCHAR(255),  

    -- Active Defense (Lockout Logic)
    failed_attempts INT DEFAULT 0,
    is_locked BOOLEAN DEFAULT FALSE,
    lockout_until TIMESTAMP,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

CREATE TABLE sessions (
    session_id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES login(user_id) ON DELETE CASCADE,
    refresh_token_hash VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    is_revoked BOOLEAN DEFAULT FALSE, 
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =================================================================================
-- CLINICAL PROFILES (Epic 2 & 3)
-- =================================================================================

CREATE TABLE patient_profiles (
    profile_id BIGSERIAL PRIMARY KEY,
    user_id BIGINT UNIQUE REFERENCES login(user_id) ON DELETE CASCADE,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    date_of_birth DATE,
    gender VARCHAR(20),
    contact_number VARCHAR(20),
    emergency_contact VARCHAR(100),
    
    -- Privacy / HIPAA Compliance
    address_encrypted TEXT, 
    medical_history_encrypted TEXT
);

CREATE TABLE doctor_profiles (
    profile_id BIGSERIAL PRIMARY KEY,
    user_id BIGINT UNIQUE REFERENCES login(user_id) ON DELETE CASCADE,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    license_number VARCHAR(50) UNIQUE NOT NULL,
    specialization VARCHAR(100),
    contact_number VARCHAR(20),
    
    -- Scheduling Logic
    shift_start_time TIME,
    shift_end_time TIME,
    working_days VARCHAR(100)
);

-- =================================================================================
-- CLINICAL WORKFLOW (The Decoupled Architecture)
-- =================================================================================

CREATE TABLE appointments (
    appointment_id BIGSERIAL PRIMARY KEY,
    patient_profile_id BIGINT REFERENCES patient_profiles(profile_id) ON DELETE CASCADE,
    doctor_id BIGINT REFERENCES login(user_id) ON DELETE CASCADE,
    appointment_date TIMESTAMP NOT NULL,
    status VARCHAR(50) DEFAULT 'PENDING_APPROVAL', 
    reason_for_visit TEXT
);

CREATE TABLE medical_records (
    record_id BIGSERIAL PRIMARY KEY,
    patient_profile_id BIGINT REFERENCES patient_profiles(profile_id) ON DELETE CASCADE,
    doctor_id BIGINT REFERENCES login(user_id) ON DELETE CASCADE,
    diagnosis TEXT,
    symptoms TEXT,
    treatment_provided TEXT,
    recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE prescriptions (
    prescription_id BIGSERIAL PRIMARY KEY,
    patient_profile_id BIGINT REFERENCES patient_profiles(profile_id) ON DELETE CASCADE,
    doctor_id BIGINT REFERENCES login(user_id) ON DELETE CASCADE,
    medication_name VARCHAR(255) NOT NULL,
    dosage VARCHAR(100) NOT NULL,
    frequency VARCHAR(100) NOT NULL,
    duration VARCHAR(100),
    special_instructions TEXT,
    status VARCHAR(50) DEFAULT 'ACTIVE',
    issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE vital_signs (
    vital_id BIGSERIAL PRIMARY KEY,
    patient_profile_id BIGINT REFERENCES patient_profiles(profile_id) ON DELETE CASCADE,
    nurse_id BIGINT REFERENCES login(user_id) ON DELETE CASCADE,
    blood_pressure VARCHAR(20),
    heart_rate INT,
    temperature DECIMAL(5,2),
    respiratory_rate INT,
    oxygen_saturation INT,
    weight DECIMAL(6,2),
    height DECIMAL(6,2),
    recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE lab_tests (
    test_id BIGSERIAL PRIMARY KEY,
    patient_profile_id BIGINT REFERENCES patient_profiles(profile_id) ON DELETE CASCADE,
    ordered_by_id BIGINT REFERENCES login(user_id) ON DELETE CASCADE,
    test_name VARCHAR(255) NOT NULL,
    test_category VARCHAR(100),
    result_value VARCHAR(255),
    unit VARCHAR(50),
    reference_range VARCHAR(100),
    remarks TEXT,
    file_url VARCHAR(255), 
    status VARCHAR(50) DEFAULT 'PENDING', 
    ordered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =================================================================================
-- SECURITY & AUDIT LOGS (Epic 4)
-- =================================================================================

CREATE TABLE audit_logs (
    log_id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES login(user_id),
    email VARCHAR(255), 
    event_type VARCHAR(50) NOT NULL, 
    ip_address VARCHAR(45),
    user_agent TEXT,
    severity VARCHAR(20) DEFAULT 'INFO', 
    details TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE consent_log (
    log_id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES login(user_id),
    consent_type VARCHAR(50) NOT NULL, 
    is_granted BOOLEAN NOT NULL,
    ip_address VARCHAR(45),
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 7. INITIAL CONFIGURATION
UPDATE login SET two_factor_enabled = true WHERE role IN ('DOCTOR', 'ADMIN');