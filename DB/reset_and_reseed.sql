-- =================================================================================
-- PATIENT MANAGEMENT SYSTEM - Entity-Aligned Reset and Reseed
-- Source of truth: backend JPA entities under backend/Backend/src/main/java/.../model
-- =================================================================================

-- 1. CLEANUP
DROP TABLE IF EXISTS consent_log CASCADE;
DROP TABLE IF EXISTS doctor_working_days CASCADE;
DROP TABLE IF EXISTS patient_consents CASCADE;
DROP TABLE IF EXISTS nurse_tasks CASCADE;
DROP TABLE IF EXISTS handover_notes CASCADE;
DROP TABLE IF EXISTS archived_users CASCADE;
DROP TABLE IF EXISTS password_reset_tokens CASCADE;
DROP TABLE IF EXISTS password_history CASCADE;
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

-- 2. ENUMS (optional app-level compatibility)
CREATE TYPE request_status AS ENUM ('PENDING', 'APPROVED', 'REJECTED');
CREATE TYPE user_role_type AS ENUM ('PATIENT', 'DOCTOR', 'NURSE', 'ADMIN', 'LAB_TECHNICIAN');

-- =================================================================================
-- CORE IDENTITY & SECURITY
-- =================================================================================

CREATE TABLE login (
    user_id BIGSERIAL PRIMARY KEY,
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    otp VARCHAR(10),
    otp_expiry TIMESTAMP,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL,
    failed_attempts INT DEFAULT 0,
    is_locked BOOLEAN DEFAULT FALSE,
    lockout_until TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login_at TIMESTAMP,
    archived BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    is_verified BOOLEAN DEFAULT FALSE,
    otp_secret VARCHAR(255)
);

CREATE TABLE sessions (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES login(user_id) ON DELETE CASCADE,
    refresh_token_hash VARCHAR(255) UNIQUE NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    expires_at TIMESTAMP NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE password_history (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES login(user_id) ON DELETE CASCADE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE password_reset_tokens (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES login(user_id) ON DELETE CASCADE,
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE archived_users (
    id BIGSERIAL PRIMARY KEY,
    original_user_id BIGINT NOT NULL,
    email VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL,
    last_active_at TIMESTAMP,
    archived_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reason TEXT
);

CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    action VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    details TEXT,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- =================================================================================
-- CLINICAL PROFILES
-- =================================================================================

CREATE TABLE patient_profiles (
    profile_id BIGSERIAL PRIMARY KEY,
    user_id BIGINT UNIQUE NOT NULL REFERENCES login(user_id) ON DELETE CASCADE,
    assigned_doctor_id BIGINT REFERENCES login(user_id),
    assigned_nurse_id BIGINT REFERENCES login(user_id),
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    date_of_birth DATE NOT NULL,
    gender VARCHAR(20),
    contact_number VARCHAR(20),
    address TEXT,
    medical_history TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE doctor_profiles (
    profile_id BIGSERIAL PRIMARY KEY,
    user_id BIGINT UNIQUE NOT NULL REFERENCES login(user_id) ON DELETE CASCADE,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    specialty VARCHAR(100) NOT NULL,
    contact_number VARCHAR(20),
    department VARCHAR(100),
    shift_start_time TIME NOT NULL DEFAULT '09:00:00',
    shift_end_time TIME NOT NULL DEFAULT '17:00:00',
    slot_duration_minutes INT NOT NULL DEFAULT 30
);

CREATE TABLE doctor_working_days (
    doctor_profile_id BIGINT NOT NULL REFERENCES doctor_profiles(profile_id) ON DELETE CASCADE,
    working_days VARCHAR(20) NOT NULL
);

-- =================================================================================
-- CLINICAL WORKFLOW
-- =================================================================================

CREATE TABLE appointments (
    appointment_id BIGSERIAL PRIMARY KEY,
    patient_profile_id BIGINT NOT NULL REFERENCES patient_profiles(profile_id) ON DELETE CASCADE,
    doctor_id BIGINT NOT NULL REFERENCES login(user_id) ON DELETE CASCADE,
    appointment_date TIMESTAMP NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'PENDING_APPROVAL',
    reason_for_visit TEXT,
    doctor_notes TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE medical_records (
    record_id BIGSERIAL PRIMARY KEY,
    patient_profile_id BIGINT NOT NULL REFERENCES patient_profiles(profile_id) ON DELETE CASCADE,
    doctor_id BIGINT NOT NULL REFERENCES login(user_id) ON DELETE CASCADE,
    diagnosis VARCHAR(255) NOT NULL,
    symptoms TEXT,
    treatment_provided TEXT,
    attachment_url VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE prescriptions (
    prescription_id BIGSERIAL PRIMARY KEY,
    patient_profile_id BIGINT NOT NULL REFERENCES patient_profiles(profile_id) ON DELETE CASCADE,
    doctor_id BIGINT NOT NULL REFERENCES login(user_id) ON DELETE CASCADE,
    medication_name VARCHAR(255) NOT NULL,
    dosage VARCHAR(100) NOT NULL,
    frequency VARCHAR(100) NOT NULL,
    duration VARCHAR(100) NOT NULL,
    special_instructions TEXT,
    issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    start_date TIMESTAMP,
    end_date TIMESTAMP,
    refills_remaining INT DEFAULT 0,
    status VARCHAR(50) DEFAULT 'ACTIVE'
);

CREATE TABLE vital_signs (
    vital_id BIGSERIAL PRIMARY KEY,
    patient_profile_id BIGINT NOT NULL REFERENCES patient_profiles(profile_id) ON DELETE CASCADE,
    nurse_id BIGINT NOT NULL REFERENCES login(user_id) ON DELETE CASCADE,
    blood_pressure VARCHAR(20),
    heart_rate INT,
    temperature DOUBLE PRECISION,
    respiratory_rate INT,
    oxygen_saturation INT,
    weight DOUBLE PRECISION,
    height DOUBLE PRECISION,
    recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE lab_tests (
    test_id BIGSERIAL PRIMARY KEY,
    patient_profile_id BIGINT NOT NULL REFERENCES patient_profiles(profile_id) ON DELETE CASCADE,
    ordered_by_id BIGINT NOT NULL REFERENCES login(user_id) ON DELETE CASCADE,
    test_name VARCHAR(255),
    test_category VARCHAR(100),
    result_value VARCHAR(255),
    unit VARCHAR(50),
    reference_range VARCHAR(100),
    remarks TEXT,
    status VARCHAR(50),
    file_url VARCHAR(255),
    ordered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE patient_consents (
    id BIGSERIAL PRIMARY KEY,
    patient_id BIGINT NOT NULL REFERENCES patient_profiles(profile_id) ON DELETE CASCADE,
    granted_to_id BIGINT NOT NULL REFERENCES login(user_id) ON DELETE CASCADE,
    consent_type VARCHAR(100) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    granted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    revoked_at TIMESTAMP,
    reason TEXT
);

CREATE TABLE handover_notes (
    id BIGSERIAL PRIMARY KEY,
    author_id BIGINT NOT NULL REFERENCES login(user_id) ON DELETE CASCADE,
    patient_id BIGINT REFERENCES patient_profiles(profile_id) ON DELETE SET NULL,
    type VARCHAR(50) NOT NULL DEFAULT 'general',
    priority VARCHAR(20) NOT NULL DEFAULT 'normal',
    content TEXT NOT NULL,
    is_read BOOLEAN DEFAULT FALSE,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    shift_direction VARCHAR(50)
);

CREATE TABLE nurse_tasks (
    id BIGSERIAL PRIMARY KEY,
    assigned_nurse_id BIGINT NOT NULL REFERENCES login(user_id) ON DELETE CASCADE,
    patient_id BIGINT REFERENCES patient_profiles(profile_id) ON DELETE SET NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(100) NOT NULL,
    priority VARCHAR(20) NOT NULL,
    due_time TIMESTAMP NOT NULL,
    completed BOOLEAN DEFAULT FALSE,
    status VARCHAR(50) DEFAULT 'upcoming',
    previous_status VARCHAR(50)
);

-- Legacy compatibility table still used by older code paths/scripts.
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
VALUES ('admin@securehealth.com', '$argon2id$v=19$m=4096,t=3,p=1$Vhabqz80TH4fFH9ehhbWKw$wBgy4sxJmmj3WLPlzGQLbqK9dEJbnslWc/J7xbwVmQ0', 'ADMIN', TRUE, TRUE, TRUE);

-- Doctor Users (password: SecurePassword2024 - 19 chars)
INSERT INTO login (email, password_hash, role, is_active, is_verified, two_factor_enabled)
VALUES 
('doctor1@securehealth.com', '$argon2id$v=19$m=4096,t=3,p=1$Vhabqz80TH4fFH9ehhbWKw$wBgy4sxJmmj3WLPlzGQLbqK9dEJbnslWc/J7xbwVmQ0', 'DOCTOR', TRUE, TRUE, TRUE),
('doctor2@securehealth.com', '$argon2id$v=19$m=4096,t=3,p=1$Vhabqz80TH4fFH9ehhbWKw$wBgy4sxJmmj3WLPlzGQLbqK9dEJbnslWc/J7xbwVmQ0', 'DOCTOR', TRUE, TRUE, TRUE);

-- Doctor Profiles (updated to match new schema)
INSERT INTO doctor_profiles (user_id, first_name, last_name, specialty, department, contact_number)
SELECT user_id, 'John', 'Smith', 'General Practice', 'Internal Medicine', '555-0201'
FROM login WHERE email = 'doctor1@securehealth.com';

INSERT INTO doctor_profiles (user_id, first_name, last_name, specialty, department, contact_number)
SELECT user_id, 'Sarah', 'Johnson', 'Cardiology', 'Cardiology', '555-0202'
FROM login WHERE email = 'doctor2@securehealth.com';

-- Working days for doctors
INSERT INTO doctor_working_days (doctor_profile_id, working_days)
SELECT dp.profile_id, 'MONDAY'
FROM doctor_profiles dp 
JOIN login l ON dp.user_id = l.user_id 
WHERE l.email = 'doctor1@securehealth.com';

INSERT INTO doctor_working_days (doctor_profile_id, working_days)
SELECT dp.profile_id, 'TUESDAY'
FROM doctor_profiles dp 
JOIN login l ON dp.user_id = l.user_id 
WHERE l.email = 'doctor1@securehealth.com';

INSERT INTO doctor_working_days (doctor_profile_id, working_days)
SELECT dp.profile_id, 'WEDNESDAY'
FROM doctor_profiles dp 
JOIN login l ON dp.user_id = l.user_id 
WHERE l.email = 'doctor1@securehealth.com';

INSERT INTO doctor_working_days (doctor_profile_id, working_days)
SELECT dp.profile_id, 'THURSDAY'
FROM doctor_profiles dp 
JOIN login l ON dp.user_id = l.user_id 
WHERE l.email = 'doctor1@securehealth.com';

INSERT INTO doctor_working_days (doctor_profile_id, working_days)
SELECT dp.profile_id, 'FRIDAY'
FROM doctor_profiles dp 
JOIN login l ON dp.user_id = l.user_id 
WHERE l.email = 'doctor1@securehealth.com';

-- Nurse Users (password: SecurePassword2024 - 19 chars)
INSERT INTO login (email, password_hash, role, is_active, is_verified, two_factor_enabled)
VALUES 
('nurse1@securehealth.com', '$argon2id$v=19$m=4096,t=3,p=1$Vhabqz80TH4fFH9ehhbWKw$wBgy4sxJmmj3WLPlzGQLbqK9dEJbnslWc/J7xbwVmQ0', 'NURSE', TRUE, TRUE, FALSE),
('nurse2@securehealth.com', '$argon2id$v=19$m=4096,t=3,p=1$Vhabqz80TH4fFH9ehhbWKw$wBgy4sxJmmj3WLPlzGQLbqK9dEJbnslWc/J7xbwVmQ0', 'NURSE', TRUE, TRUE, FALSE);

-- Lab Technician Users (password: SecurePassword2024 - 19 chars)
INSERT INTO login (email, password_hash, role, is_active, is_verified)
VALUES 
('lab1@securehealth.com', '$argon2id$v=19$m=4096,t=3,p=1$Vhabqz80TH4fFH9ehhbWKw$wBgy4sxJmmj3WLPlzGQLbqK9dEJbnslWc/J7xbwVmQ0', 'LAB_TECHNICIAN', TRUE, TRUE),
('lab2@securehealth.com', '$argon2id$v=19$m=4096,t=3,p=1$Vhabqz80TH4fFH9ehhbWKw$wBgy4sxJmmj3WLPlzGQLbqK9dEJbnslWc/J7xbwVmQ0', 'LAB_TECHNICIAN', TRUE, TRUE);

-- Patient Users (password: SecurePassword2024 - 19 chars)
INSERT INTO login (email, password_hash, role, is_active, is_verified)
VALUES 
('patient1@securehealth.com', '$argon2id$v=19$m=4096,t=3,p=1$Vhabqz80TH4fFH9ehhbWKw$wBgy4sxJmmj3WLPlzGQLbqK9dEJbnslWc/J7xbwVmQ0', 'PATIENT', TRUE, TRUE),
('patient2@securehealth.com', '$argon2id$v=19$m=4096,t=3,p=1$Vhabqz80TH4fFH9ehhbWKw$wBgy4sxJmmj3WLPlzGQLbqK9dEJbnslWc/J7xbwVmQ0', 'PATIENT', TRUE, TRUE),
('patient3@securehealth.com', '$argon2id$v=19$m=4096,t=3,p=1$Vhabqz80TH4fFH9ehhbWKw$wBgy4sxJmmj3WLPlzGQLbqK9dEJbnslWc/J7xbwVmQ0', 'PATIENT', TRUE, TRUE),
('patient4@securehealth.com', '$argon2id$v=19$m=4096,t=3,p=1$Vhabqz80TH4fFH9ehhbWKw$wBgy4sxJmmj3WLPlzGQLbqK9dEJbnslWc/J7xbwVmQ0', 'PATIENT', TRUE, TRUE),
('patient5@securehealth.com', '$argon2id$v=19$m=4096,t=3,p=1$Vhabqz80TH4fFH9ehhbWKw$wBgy4sxJmmj3WLPlzGQLbqK9dEJbnslWc/J7xbwVmQ0', 'PATIENT', TRUE, TRUE);

-- Patient Profiles (updated to match new schema)
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
SELECT pp.profile_id, l.user_id, NOW() + INTERVAL '7 days', 'SCHEDULED', 'Regular Checkup'
FROM patient_profiles pp, login l
WHERE l.email = 'doctor1@securehealth.com'
LIMIT 5;

INSERT INTO appointments (patient_profile_id, doctor_id, appointment_date, status, reason_for_visit)
SELECT pp.profile_id, l.user_id, NOW() + INTERVAL '14 days', 'PENDING_APPROVAL', 'Follow-up Visit'
FROM patient_profiles pp, login l
WHERE l.email = 'doctor2@securehealth.com'
LIMIT 5;

INSERT INTO appointments (patient_profile_id, doctor_id, appointment_date, status, reason_for_visit)
SELECT pp.profile_id, l.user_id, NOW() + INTERVAL '21 days', 'COMPLETED', 'Consultation'
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

-- Sample Medical Records (updated to use created_at instead of recorded_at)
INSERT INTO medical_records (patient_profile_id, doctor_id, diagnosis, symptoms, treatment_provided)
SELECT pp.profile_id, l.user_id, 'Hypertension', 'Elevated blood pressure', 'Prescribed Lisinopril'
FROM patient_profiles pp, login l
WHERE l.email = 'doctor1@securehealth.com'
LIMIT 5;

INSERT INTO medical_records (patient_profile_id, doctor_id, diagnosis, symptoms, treatment_provided)
SELECT pp.profile_id, l.user_id, 'Type 2 Diabetes', 'High glucose levels', 'Prescribed Metformin'
FROM patient_profiles pp, login l
WHERE l.email = 'doctor2@securehealth.com'
LIMIT 5;

-- =================================================================================
-- VERIFICATION
-- =================================================================================
SELECT 'Reset and reseed completed successfully' as status;
FROM login WHERE email = 'patient3@securehealth.com';

INSERT INTO patient_profiles (user_id, first_name, last_name, date_of_birth, gender, contact_number, address)
SELECT user_id, 'David', 'Miller', '1992-05-30', 'Male', '555-0104', '321 Elm St'
FROM login WHERE email = 'patient4@securehealth.com';

INSERT INTO patient_profiles (user_id, first_name, last_name, date_of_birth, gender, contact_number, address)
SELECT user_id, 'Emma', 'Wilson', '1987-09-18', 'Female', '555-0105', '654 Maple Dr'
FROM login WHERE email = 'patient5@securehealth.com';

-- Sample Appointments (3 per patient)
INSERT INTO appointments (patient_profile_id, doctor_id, appointment_date, status, reason_for_visit)
SELECT pp.profile_id, l.user_id, NOW() + INTERVAL '7 days', 'SCHEDULED', 'Regular Checkup'
FROM patient_profiles pp, login l
WHERE l.email = 'doctor1@securehealth.com'
LIMIT 5;

INSERT INTO appointments (patient_profile_id, doctor_id, appointment_date, status, reason_for_visit)
SELECT pp.profile_id, l.user_id, NOW() + INTERVAL '14 days', 'PENDING_APPROVAL', 'Follow-up Visit'
FROM patient_profiles pp, login l
WHERE l.email = 'doctor2@securehealth.com'
LIMIT 5;

INSERT INTO appointments (patient_profile_id, doctor_id, appointment_date, status, reason_for_visit)
SELECT pp.profile_id, l.user_id, NOW() + INTERVAL '21 days', 'COMPLETED', 'Consultation'
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
SELECT pp.profile_id, l.user_id, 'Complete Blood Count', 'Hematology', 'Normal', 'cells/ÂµL', 'COMPLETED', NOW() - INTERVAL '3 days'
FROM patient_profiles pp, login l
WHERE l.email = 'doctor1@securehealth.com'
LIMIT 5;

-- =================================================================================
-- VERIFICATION
-- =================================================================================
SELECT 'Reset and reseed completed successfully' as status;

