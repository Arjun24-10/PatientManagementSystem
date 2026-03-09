-- =================================================================================
-- COMPLETE DATABASE RESET AND RESEED - PRODUCTION READY
-- =================================================================================

-- PART 1: DROP ALL EXISTING DATA & TYPES
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
DROP TYPE IF EXISTS request_status CASCADE;
DROP TYPE IF EXISTS user_role_type CASCADE;

-- PART 2: RECREATE SCHEMA
CREATE TYPE request_status AS ENUM ('PENDING', 'APPROVED', 'REJECTED');
CREATE TYPE user_role_type AS ENUM ('PATIENT', 'DOCTOR', 'NURSE', 'ADMIN', 'LAB_TECHNICIAN');

-- =================================================================================
-- CORE IDENTITY & SECURITY - INCLUDES ARCHIVED & LAST_LOGIN_AT COLUMNS
-- =================================================================================

CREATE TABLE login (
    user_id BIGSERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'PATIENT',
    is_active BOOLEAN DEFAULT TRUE,
    is_verified BOOLEAN DEFAULT FALSE,
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    otp VARCHAR(10),
    otp_expiry TIMESTAMP,
    otp_secret VARCHAR(255),
    failed_attempts INT DEFAULT 0,
    is_locked BOOLEAN DEFAULT FALSE,
    lockout_until TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login_at TIMESTAMP,
    archived BOOLEAN DEFAULT FALSE
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
-- CLINICAL PROFILES
-- =================================================================================

CREATE TABLE patient_profiles (
    profile_id BIGSERIAL PRIMARY KEY,
    user_id BIGINT UNIQUE REFERENCES login(user_id) ON DELETE CASCADE,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    date_of_birth DATE,
    gender VARCHAR(20),
    contact_number VARCHAR(20),
    address VARCHAR(255),
    medical_history TEXT,
    assigned_doctor_id BIGINT REFERENCES login(user_id),
    assigned_nurse_id BIGINT REFERENCES login(user_id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE doctor_profiles (
    profile_id BIGSERIAL PRIMARY KEY,
    user_id BIGINT UNIQUE REFERENCES login(user_id) ON DELETE CASCADE,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    license_number VARCHAR(50) UNIQUE NOT NULL,
    specialization VARCHAR(100),
    contact_number VARCHAR(20),
    shift_start_time TIME,
    shift_end_time TIME,
    working_days VARCHAR(100)
);

-- =================================================================================
-- CLINICAL WORKFLOW
-- =================================================================================

CREATE TABLE appointments (
    appointment_id BIGSERIAL PRIMARY KEY,
    patient_profile_id BIGINT REFERENCES patient_profiles(profile_id) ON DELETE CASCADE,
    doctor_id BIGINT REFERENCES login(user_id) ON DELETE CASCADE,
    appointment_date TIMESTAMP NOT NULL,
    status VARCHAR(50) DEFAULT 'PENDING_APPROVAL',
    reason_for_visit TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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

-- =================================================================================
-- PART 3: SEED FRESH TEST DATA
-- =================================================================================

-- Admin User (password: SecurePassword2024 - 19 chars)
INSERT INTO login (email, password_hash, role, is_active, is_verified, two_factor_enabled)
VALUES ('admin@securehealth.com', '$2a$10$dXJ3SW6G7P50eS3Q.Wbz2eH.kEnyCcLHVCyqY9KrJ2dPWx6HJ.0Ou', 'ADMIN', TRUE, TRUE, TRUE);

-- Doctor Users (password: SecurePassword2024 - 19 chars)
INSERT INTO login (email, password_hash, role, is_active, is_verified, two_factor_enabled)
VALUES 
('doctor1@securehealth.com', '$2a$10$dXJ3SW6G7P50eS3Q.Wbz2eH.kEnyCcLHVCyqY9KrJ2dPWx6HJ.0Ou', 'DOCTOR', TRUE, TRUE, TRUE),
('doctor2@securehealth.com', '$2a$10$dXJ3SW6G7P50eS3Q.Wbz2eH.kEnyCcLHVCyqY9KrJ2dPWx6HJ.0Ou', 'DOCTOR', TRUE, TRUE, TRUE);

-- Doctor Profiles
INSERT INTO doctor_profiles (user_id, first_name, last_name, license_number, specialization)
SELECT user_id, 'John', 'Smith', 'DOC-001', 'General Practice'
FROM login WHERE email = 'doctor1@securehealth.com';

INSERT INTO doctor_profiles (user_id, first_name, last_name, license_number, specialization)
SELECT user_id, 'Sarah', 'Johnson', 'DOC-002', 'Cardiology'
FROM login WHERE email = 'doctor2@securehealth.com';

-- Nurse Users (password: SecurePassword2024 - 19 chars)
INSERT INTO login (email, password_hash, role, is_active, is_verified, two_factor_enabled)
VALUES 
('nurse1@securehealth.com', '$2a$10$dXJ3SW6G7P50eS3Q.Wbz2eH.kEnyCcLHVCyqY9KrJ2dPWx6HJ.0Ou', 'NURSE', TRUE, TRUE, FALSE),
('nurse2@securehealth.com', '$2a$10$dXJ3SW6G7P50eS3Q.Wbz2eH.kEnyCcLHVCyqY9KrJ2dPWx6HJ.0Ou', 'NURSE', TRUE, TRUE, FALSE);

-- Lab Technician Users (password: SecurePassword2024 - 19 chars)
INSERT INTO login (email, password_hash, role, is_active, is_verified)
VALUES 
('lab1@securehealth.com', '$2a$10$dXJ3SW6G7P50eS3Q.Wbz2eH.kEnyCcLHVCyqY9KrJ2dPWx6HJ.0Ou', 'LAB_TECHNICIAN', TRUE, TRUE),
('lab2@securehealth.com', '$2a$10$dXJ3SW6G7P50eS3Q.Wbz2eH.kEnyCcLHVCyqY9KrJ2dPWx6HJ.0Ou', 'LAB_TECHNICIAN', TRUE, TRUE);

-- Patient Users (password: SecurePassword2024 - 19 chars)
INSERT INTO login (email, password_hash, role, is_active, is_verified)
VALUES 
('patient1@securehealth.com', '$2a$10$dXJ3SW6G7P50eS3Q.Wbz2eH.kEnyCcLHVCyqY9KrJ2dPWx6HJ.0Ou', 'PATIENT', TRUE, TRUE),
('patient2@securehealth.com', '$2a$10$dXJ3SW6G7P50eS3Q.Wbz2eH.kEnyCcLHVCyqY9KrJ2dPWx6HJ.0Ou', 'PATIENT', TRUE, TRUE),
('patient3@securehealth.com', '$2a$10$dXJ3SW6G7P50eS3Q.Wbz2eH.kEnyCcLHVCyqY9KrJ2dPWx6HJ.0Ou', 'PATIENT', TRUE, TRUE),
('patient4@securehealth.com', '$2a$10$dXJ3SW6G7P50eS3Q.Wbz2eH.kEnyCcLHVCyqY9KrJ2dPWx6HJ.0Ou', 'PATIENT', TRUE, TRUE),
('patient5@securehealth.com', '$2a$10$dXJ3SW6G7P50eS3Q.Wbz2eH.kEnyCcLHVCyqY9KrJ2dPWx6HJ.0Ou', 'PATIENT', TRUE, TRUE);

-- Patient Profiles
INSERT INTO patient_profiles (user_id, first_name, last_name, date_of_birth, gender, contact_number, address)
SELECT user_id, 'Alice', 'Williams', '1985-03-15', 'Female', '555-0101', '123 Main St'
FROM login WHERE email = 'patient1@securehealth.com';

INSERT INTO patient_profiles (user_id, first_name, last_name, date_of_birth, gender, contact_number, address)
SELECT user_id, 'Bob', 'Brown', '1990-07-22', 'Male', '555-0102', '456 Oak Ave'
FROM login WHERE email = 'patient2@securehealth.com';

INSERT INTO patient_profiles (user_id, first_name, last_name, date_of_birth, gender, contact_number, address)
SELECT user_id, 'Carol', 'Davis', '1988-11-10', 'Female', '555-0103', '789 Pine Rd'
FROM login WHERE email = 'patient3@securehealth.com';

INSERT INTO patient_profiles (user_id, first_name, last_name, date_of_birth, gender, contact_number, address)
SELECT user_id, 'David', 'Miller', '1992-05-30', 'Male', '555-0104', '321 Elm St'
FROM login WHERE email = 'patient4@securehealth.com';

INSERT INTO patient_profiles (user_id, first_name, last_name, date_of_birth, gender, contact_number, address)
SELECT user_id, 'Emma', 'Wilson', '1987-09-18', 'Female', '555-0105', '654 Maple Dr'
FROM login WHERE email = 'patient5@securehealth.com';

-- Sample Appointments (3 per patient)
INSERT INTO appointments (patient_profile_id, doctor_id, appointment_date, status, reason_for_visit)
SELECT pp.profile_id, l.user_id, NOW() + INTERVAL '7 days', 'APPROVED', 'Regular Checkup'
FROM patient_profiles pp, login l
WHERE l.email = 'doctor1@securehealth.com'
LIMIT 5;

INSERT INTO appointments (patient_profile_id, doctor_id, appointment_date, status, reason_for_visit)
SELECT pp.profile_id, l.user_id, NOW() + INTERVAL '14 days', 'PENDING_APPROVAL', 'Follow-up Visit'
FROM patient_profiles pp, login l
WHERE l.email = 'doctor2@securehealth.com'
LIMIT 5;

INSERT INTO appointments (patient_profile_id, doctor_id, appointment_date, status, reason_for_visit)
SELECT pp.profile_id, l.user_id, NOW() + INTERVAL '21 days', 'APPROVED', 'Consultation'
FROM patient_profiles pp, login l
WHERE l.email = 'doctor1@securehealth.com'
LIMIT 5;

-- Sample Prescriptions
INSERT INTO prescriptions (patient_profile_id, doctor_id, medication_name, dosage, frequency, duration, status)
SELECT pp.profile_id, l.user_id, 'Lisinopril', '10mg', 'Once daily', '30 days', 'ACTIVE'
FROM patient_profiles pp, login l
WHERE l.email = 'doctor1@securehealth.com'
LIMIT 5;

INSERT INTO prescriptions (patient_profile_id, doctor_id, medication_name, dosage, frequency, duration, status)
SELECT pp.profile_id, l.user_id, 'Metformin', '500mg', 'Twice daily', '90 days', 'ACTIVE'
FROM patient_profiles pp, login l
WHERE l.email = 'doctor2@securehealth.com'
LIMIT 5;

INSERT INTO prescriptions (patient_profile_id, doctor_id, medication_name, dosage, frequency, duration, status)
SELECT pp.profile_id, l.user_id, 'Aspirin', '100mg', 'Once daily', '60 days', 'ACTIVE'
FROM patient_profiles pp, login l
WHERE l.email = 'doctor1@securehealth.com'
LIMIT 5;

-- Sample Vital Signs
INSERT INTO vital_signs (patient_profile_id, nurse_id, blood_pressure, heart_rate, temperature, respiratory_rate, oxygen_saturation, weight, height, recorded_at)
SELECT pp.profile_id, l.user_id, '120/80', 72, 98.6, 16, 98, 70.5, 175, NOW()
FROM patient_profiles pp, login l
WHERE l.email = 'nurse1@securehealth.com'
LIMIT 5;

INSERT INTO vital_signs (patient_profile_id, nurse_id, blood_pressure, heart_rate, temperature, respiratory_rate, oxygen_saturation, weight, height, recorded_at)
SELECT pp.profile_id, l.user_id, '118/78', 70, 98.4, 16, 99, 68.0, 172, NOW() - INTERVAL '1 day'
FROM patient_profiles pp, login l
WHERE l.email = 'nurse2@securehealth.com'
LIMIT 5;

INSERT INTO vital_signs (patient_profile_id, nurse_id, blood_pressure, heart_rate, temperature, respiratory_rate, oxygen_saturation, weight, height, recorded_at)
SELECT pp.profile_id, l.user_id, '122/82', 74, 98.7, 17, 98, 72.0, 178, NOW() - INTERVAL '2 days'
FROM patient_profiles pp, login l
WHERE l.email = 'nurse1@securehealth.com'
LIMIT 5;

-- Sample Lab Tests
INSERT INTO lab_tests (patient_profile_id, ordered_by_id, test_name, test_category, result_value, unit, status, ordered_at)
SELECT pp.profile_id, l.user_id, 'Blood Glucose', 'Chemistry', '95', 'mg/dL', 'COMPLETED', NOW() - INTERVAL '7 days'
FROM patient_profiles pp, login l
WHERE l.email = 'doctor1@securehealth.com'
LIMIT 5;

INSERT INTO lab_tests (patient_profile_id, ordered_by_id, test_name, test_category, result_value, unit, status, ordered_at)
SELECT pp.profile_id, l.user_id, 'Hemoglobin A1C', 'Chemistry', '5.8', '%', 'COMPLETED', NOW() - INTERVAL '5 days'
FROM patient_profiles pp, login l
WHERE l.email = 'doctor2@securehealth.com'
LIMIT 5;

INSERT INTO lab_tests (patient_profile_id, ordered_by_id, test_name, test_category, result_value, unit, status, ordered_at)
SELECT pp.profile_id, l.user_id, 'Complete Blood Count', 'Hematology', 'Normal', 'cells/µL', 'COMPLETED', NOW() - INTERVAL '3 days'
FROM patient_profiles pp, login l
WHERE l.email = 'doctor1@securehealth.com'
LIMIT 5;

-- Sample Medical Records
INSERT INTO medical_records (patient_profile_id, doctor_id, diagnosis, symptoms, treatment_provided, recorded_at)
SELECT pp.profile_id, l.user_id, 'Hypertension', 'Elevated blood pressure', 'Prescribed Lisinopril', NOW() - INTERVAL '10 days'
FROM patient_profiles pp, login l
WHERE l.email = 'doctor1@securehealth.com'
LIMIT 5;

INSERT INTO medical_records (patient_profile_id, doctor_id, diagnosis, symptoms, treatment_provided, recorded_at)
SELECT pp.profile_id, l.user_id, 'Type 2 Diabetes', 'High glucose levels', 'Prescribed Metformin', NOW() - INTERVAL '15 days'
FROM patient_profiles pp, login l
WHERE l.email = 'doctor2@securehealth.com'
LIMIT 5;

-- =================================================================================
-- VERIFICATION
-- =================================================================================
SELECT 'Reset and reseed completed successfully' as status;
