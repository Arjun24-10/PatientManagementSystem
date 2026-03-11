-- =================================================================================
-- CUSTOM USER SEED — PatientManagementSystem
-- Run against: healthcare_auth_db (live PostgreSQL)
-- SAFE: insert-only, no DROP/CREATE — schema already managed by JPA/Hibernate
--
-- Password for ALL users: SecurePassword2024
-- Hash: argon2id $argon2id$v=19$m=4096,t=3,p=1$Vhabqz80TH4fFH9ehhbWKw$wBgy4sxJmmj3WLPlzGQLbqK9dEJbnslWc/J7xbwVmQ0
-- =================================================================================

-- ---------------------------------------------------------------------------------
-- 1. LOGIN ACCOUNTS
-- ---------------------------------------------------------------------------------

-- Admin (2FA enabled)
INSERT INTO login (email, password_hash, role, is_active, is_verified, two_factor_enabled)
VALUES (
    'manvitha3626@gmail.com',
    '$argon2id$v=19$m=4096,t=3,p=1$Vhabqz80TH4fFH9ehhbWKw$wBgy4sxJmmj3WLPlzGQLbqK9dEJbnslWc/J7xbwVmQ0',
    'ADMIN', TRUE, TRUE, TRUE
);

-- Doctors (2FA enabled)
INSERT INTO login (email, password_hash, role, is_active, is_verified, two_factor_enabled)
VALUES
    ('riyomen.mikey@gmail.com',
     '$argon2id$v=19$m=4096,t=3,p=1$Vhabqz80TH4fFH9ehhbWKw$wBgy4sxJmmj3WLPlzGQLbqK9dEJbnslWc/J7xbwVmQ0',
     'DOCTOR', TRUE, TRUE, TRUE),
    ('2004arjunk@gmail.com',
     '$argon2id$v=19$m=4096,t=3,p=1$Vhabqz80TH4fFH9ehhbWKw$wBgy4sxJmmj3WLPlzGQLbqK9dEJbnslWc/J7xbwVmQ0',
     'DOCTOR', TRUE, TRUE, TRUE);

-- Nurse (no 2FA)
INSERT INTO login (email, password_hash, role, is_active, is_verified, two_factor_enabled)
VALUES (
    'abhirambikkina@gmail.com',
    '$argon2id$v=19$m=4096,t=3,p=1$Vhabqz80TH4fFH9ehhbWKw$wBgy4sxJmmj3WLPlzGQLbqK9dEJbnslWc/J7xbwVmQ0',
    'NURSE', TRUE, TRUE, FALSE
);

-- Lab Technician (no 2FA)
INSERT INTO login (email, password_hash, role, is_active, is_verified, two_factor_enabled)
VALUES (
    'abhiramamrita@gmail.com',
    '$argon2id$v=19$m=4096,t=3,p=1$Vhabqz80TH4fFH9ehhbWKw$wBgy4sxJmmj3WLPlzGQLbqK9dEJbnslWc/J7xbwVmQ0',
    'LAB_TECHNICIAN', TRUE, TRUE, FALSE
);

-- Patients (no 2FA)
INSERT INTO login (email, password_hash, role, is_active, is_verified, two_factor_enabled)
VALUES
    ('diyabhat2005@gmail.com',
     '$argon2id$v=19$m=4096,t=3,p=1$Vhabqz80TH4fFH9ehhbWKw$wBgy4sxJmmj3WLPlzGQLbqK9dEJbnslWc/J7xbwVmQ0',
     'PATIENT', TRUE, TRUE, FALSE),
    ('editzzz.ani@gmail.com',
     '$argon2id$v=19$m=4096,t=3,p=1$Vhabqz80TH4fFH9ehhbWKw$wBgy4sxJmmj3WLPlzGQLbqK9dEJbnslWc/J7xbwVmQ0',
     'PATIENT', TRUE, TRUE, FALSE);

-- ---------------------------------------------------------------------------------
-- 2. DOCTOR PROFILES
-- ---------------------------------------------------------------------------------

INSERT INTO doctor_profiles (user_id, first_name, last_name, specialty, department, contact_number, shift_start_time, shift_end_time, slot_duration_minutes)
SELECT user_id, 'Mikey', 'Riyomen', 'General Practice', 'Internal Medicine', '555-1001', '09:00:00', '17:00:00', 30
FROM login WHERE email = 'riyomen.mikey@gmail.com';

INSERT INTO doctor_profiles (user_id, first_name, last_name, specialty, department, contact_number, shift_start_time, shift_end_time, slot_duration_minutes)
SELECT user_id, 'Arjun', 'Kumar', 'Cardiology', 'Cardiology', '555-1002', '09:00:00', '17:00:00', 30
FROM login WHERE email = '2004arjunk@gmail.com';

-- Working days — both doctors: Mon–Fri
INSERT INTO doctor_working_days (doctor_profile_id, working_days)
SELECT dp.profile_id, day
FROM doctor_profiles dp
JOIN login l ON dp.user_id = l.user_id,
LATERAL (VALUES ('MONDAY'), ('TUESDAY'), ('WEDNESDAY'), ('THURSDAY'), ('FRIDAY')) AS days(day)
WHERE l.email IN ('riyomen.mikey@gmail.com', '2004arjunk@gmail.com');

-- ---------------------------------------------------------------------------------
-- 3. PATIENT PROFILES
-- ---------------------------------------------------------------------------------

-- Diya Bhat → assigned to doctor Mikey, nurse Abhiram Bikkina
INSERT INTO patient_profiles (user_id, first_name, last_name, date_of_birth, gender, contact_number, address, medical_history, assigned_doctor_id, assigned_nurse_id)
SELECT
    pl.user_id,
    'Diya', 'Bhat',
    '2005-04-12', 'Female', '555-2001', '12 Rose Lane, Sydney',
    'No known chronic conditions. Seasonal allergies (pollen).',
    (SELECT user_id FROM login WHERE email = 'riyomen.mikey@gmail.com'),
    (SELECT user_id FROM login WHERE email = 'abhirambikkina@gmail.com')
FROM login pl WHERE pl.email = 'diyabhat2005@gmail.com';

-- Ani → assigned to doctor Arjun, nurse Abhiram Bikkina
INSERT INTO patient_profiles (user_id, first_name, last_name, date_of_birth, gender, contact_number, address, medical_history, assigned_doctor_id, assigned_nurse_id)
SELECT
    pl.user_id,
    'Ani', 'Edit',
    '1998-09-25', 'Female', '555-2002', '78 Blue St, Melbourne',
    'Mild hypertension — monitored. No medication currently.',
    (SELECT user_id FROM login WHERE email = '2004arjunk@gmail.com'),
    (SELECT user_id FROM login WHERE email = 'abhirambikkina@gmail.com')
FROM login pl WHERE pl.email = 'editzzz.ani@gmail.com';

-- ---------------------------------------------------------------------------------
-- 4. APPOINTMENTS
-- ---------------------------------------------------------------------------------

-- Diya with Dr. Mikey — upcoming SCHEDULED
INSERT INTO appointments (patient_profile_id, doctor_id, appointment_date, status, reason_for_visit)
SELECT pp.profile_id, l.user_id, NOW() + INTERVAL '5 days', 'SCHEDULED', 'Routine annual checkup'
FROM patient_profiles pp
JOIN login pl ON pp.user_id = pl.user_id AND pl.email = 'diyabhat2005@gmail.com',
login l WHERE l.email = 'riyomen.mikey@gmail.com';

-- Diya with Dr. Mikey — past COMPLETED
INSERT INTO appointments (patient_profile_id, doctor_id, appointment_date, status, reason_for_visit, doctor_notes)
SELECT pp.profile_id, l.user_id, NOW() - INTERVAL '14 days', 'COMPLETED', 'Follow-up for seasonal allergies', 'Prescribed antihistamines. Patient improving.'
FROM patient_profiles pp
JOIN login pl ON pp.user_id = pl.user_id AND pl.email = 'diyabhat2005@gmail.com',
login l WHERE l.email = 'riyomen.mikey@gmail.com';

-- Ani with Dr. Arjun — upcoming PENDING_APPROVAL
INSERT INTO appointments (patient_profile_id, doctor_id, appointment_date, status, reason_for_visit)
SELECT pp.profile_id, l.user_id, NOW() + INTERVAL '3 days', 'PENDING_APPROVAL', 'Blood pressure review'
FROM patient_profiles pp
JOIN login pl ON pp.user_id = pl.user_id AND pl.email = 'editzzz.ani@gmail.com',
login l WHERE l.email = '2004arjunk@gmail.com';

-- Ani with Dr. Arjun — past COMPLETED
INSERT INTO appointments (patient_profile_id, doctor_id, appointment_date, status, reason_for_visit, doctor_notes)
SELECT pp.profile_id, l.user_id, NOW() - INTERVAL '21 days', 'COMPLETED', 'Initial hypertension assessment', 'BP 138/88. Lifestyle changes recommended. Schedule 3-week follow-up.'
FROM patient_profiles pp
JOIN login pl ON pp.user_id = pl.user_id AND pl.email = 'editzzz.ani@gmail.com',
login l WHERE l.email = '2004arjunk@gmail.com';

-- ---------------------------------------------------------------------------------
-- 5. VITAL SIGNS (recorded by Abhiram Bikkina - nurse)
-- ---------------------------------------------------------------------------------

-- Diya — 3 readings over last 3 days
INSERT INTO vital_signs (patient_profile_id, nurse_id, blood_pressure, heart_rate, temperature, respiratory_rate, oxygen_saturation, weight, height, recorded_at)
SELECT pp.profile_id, l.user_id, '118/76', 68, 98.4, 15, 99, 55.0, 162, NOW() - INTERVAL '2 days'
FROM patient_profiles pp
JOIN login pl ON pp.user_id = pl.user_id AND pl.email = 'diyabhat2005@gmail.com',
login l WHERE l.email = 'abhirambikkina@gmail.com';

INSERT INTO vital_signs (patient_profile_id, nurse_id, blood_pressure, heart_rate, temperature, respiratory_rate, oxygen_saturation, weight, height, recorded_at)
SELECT pp.profile_id, l.user_id, '116/74', 70, 98.6, 16, 99, 55.0, 162, NOW() - INTERVAL '1 day'
FROM patient_profiles pp
JOIN login pl ON pp.user_id = pl.user_id AND pl.email = 'diyabhat2005@gmail.com',
login l WHERE l.email = 'abhirambikkina@gmail.com';

INSERT INTO vital_signs (patient_profile_id, nurse_id, blood_pressure, heart_rate, temperature, respiratory_rate, oxygen_saturation, weight, height, recorded_at)
SELECT pp.profile_id, l.user_id, '120/78', 72, 98.5, 16, 98, 55.0, 162, NOW()
FROM patient_profiles pp
JOIN login pl ON pp.user_id = pl.user_id AND pl.email = 'diyabhat2005@gmail.com',
login l WHERE l.email = 'abhirambikkina@gmail.com';

-- Ani — 3 readings (elevated BP trend)
INSERT INTO vital_signs (patient_profile_id, nurse_id, blood_pressure, heart_rate, temperature, respiratory_rate, oxygen_saturation, weight, height, recorded_at)
SELECT pp.profile_id, l.user_id, '140/90', 78, 98.8, 17, 97, 62.0, 165, NOW() - INTERVAL '2 days'
FROM patient_profiles pp
JOIN login pl ON pp.user_id = pl.user_id AND pl.email = 'editzzz.ani@gmail.com',
login l WHERE l.email = 'abhirambikkina@gmail.com';

INSERT INTO vital_signs (patient_profile_id, nurse_id, blood_pressure, heart_rate, temperature, respiratory_rate, oxygen_saturation, weight, height, recorded_at)
SELECT pp.profile_id, l.user_id, '138/88', 75, 98.6, 16, 97, 62.0, 165, NOW() - INTERVAL '1 day'
FROM patient_profiles pp
JOIN login pl ON pp.user_id = pl.user_id AND pl.email = 'editzzz.ani@gmail.com',
login l WHERE l.email = 'abhirambikkina@gmail.com';

INSERT INTO vital_signs (patient_profile_id, nurse_id, blood_pressure, heart_rate, temperature, respiratory_rate, oxygen_saturation, weight, height, recorded_at)
SELECT pp.profile_id, l.user_id, '136/86', 74, 98.5, 16, 98, 62.0, 165, NOW()
FROM patient_profiles pp
JOIN login pl ON pp.user_id = pl.user_id AND pl.email = 'editzzz.ani@gmail.com',
login l WHERE l.email = 'abhirambikkina@gmail.com';

-- ---------------------------------------------------------------------------------
-- 6. PRESCRIPTIONS (ordered by respective doctors)
-- ---------------------------------------------------------------------------------

-- Diya — antihistamine for allergies (Dr. Mikey)
INSERT INTO prescriptions (patient_profile_id, doctor_id, medication_name, dosage, frequency, duration, special_instructions, status, start_date, end_date, refills_remaining)
SELECT pp.profile_id, l.user_id,
    'Cetirizine', '10mg', 'Once daily at night', '30 days',
    'Take with water. Avoid alcohol.',
    'ACTIVE', NOW() - INTERVAL '14 days', NOW() + INTERVAL '16 days', 1
FROM patient_profiles pp
JOIN login pl ON pp.user_id = pl.user_id AND pl.email = 'diyabhat2005@gmail.com',
login l WHERE l.email = 'riyomen.mikey@gmail.com';

-- Ani — antihypertensive (Dr. Arjun)
INSERT INTO prescriptions (patient_profile_id, doctor_id, medication_name, dosage, frequency, duration, special_instructions, status, start_date, end_date, refills_remaining)
SELECT pp.profile_id, l.user_id,
    'Amlodipine', '5mg', 'Once daily in the morning', '90 days',
    'Monitor BP weekly. Report any swelling in legs.',
    'ACTIVE', NOW() - INTERVAL '21 days', NOW() + INTERVAL '69 days', 2
FROM patient_profiles pp
JOIN login pl ON pp.user_id = pl.user_id AND pl.email = 'editzzz.ani@gmail.com',
login l WHERE l.email = '2004arjunk@gmail.com';

-- ---------------------------------------------------------------------------------
-- 7. MEDICAL RECORDS
-- ---------------------------------------------------------------------------------

-- Diya — allergy visit (Dr. Mikey)
INSERT INTO medical_records (patient_profile_id, doctor_id, diagnosis, symptoms, treatment_provided)
SELECT pp.profile_id, l.user_id,
    'Seasonal Allergic Rhinitis',
    'Sneezing, nasal congestion, itchy eyes — worse in spring.',
    'Prescribed Cetirizine 10mg daily. Advised to avoid outdoor exposure during high pollen days.'
FROM patient_profiles pp
JOIN login pl ON pp.user_id = pl.user_id AND pl.email = 'diyabhat2005@gmail.com',
login l WHERE l.email = 'riyomen.mikey@gmail.com';

-- Ani — hypertension (Dr. Arjun)
INSERT INTO medical_records (patient_profile_id, doctor_id, diagnosis, symptoms, treatment_provided)
SELECT pp.profile_id, l.user_id,
    'Stage 1 Hypertension',
    'Headaches, occasional dizziness. BP consistently 138-142/88-92 over 3 readings.',
    'Prescribed Amlodipine 5mg. Lifestyle advice: reduce sodium, moderate exercise, reduce caffeine.'
FROM patient_profiles pp
JOIN login pl ON pp.user_id = pl.user_id AND pl.email = 'editzzz.ani@gmail.com',
login l WHERE l.email = '2004arjunk@gmail.com';

-- ---------------------------------------------------------------------------------
-- 8. LAB TESTS
-- ---------------------------------------------------------------------------------

-- Diya — allergy panel (COMPLETED), ordered by Dr. Mikey, resulted by lab tech Abhiramamrita
INSERT INTO lab_tests (patient_profile_id, ordered_by_id, test_name, test_category, result_value, unit, reference_range, remarks, status, ordered_at)
SELECT pp.profile_id, l.user_id,
    'Serum IgE (Total)', 'Immunology',
    '245', 'IU/mL', '0–100 IU/mL',
    'Elevated IgE consistent with allergic sensitisation.',
    'COMPLETED', NOW() - INTERVAL '13 days'
FROM patient_profiles pp
JOIN login pl ON pp.user_id = pl.user_id AND pl.email = 'diyabhat2005@gmail.com',
login l WHERE l.email = 'riyomen.mikey@gmail.com';

-- Diya — CBC pending (Dr. Mikey)
INSERT INTO lab_tests (patient_profile_id, ordered_by_id, test_name, test_category, remarks, status, ordered_at)
SELECT pp.profile_id, l.user_id,
    'Complete Blood Count', 'Hematology',
    'Baseline CBC before follow-up visit.',
    'PENDING', NOW() - INTERVAL '1 day'
FROM patient_profiles pp
JOIN login pl ON pp.user_id = pl.user_id AND pl.email = 'diyabhat2005@gmail.com',
login l WHERE l.email = 'riyomen.mikey@gmail.com';

-- Ani — lipid panel (COMPLETED), ordered by Dr. Arjun
INSERT INTO lab_tests (patient_profile_id, ordered_by_id, test_name, test_category, result_value, unit, reference_range, remarks, status, ordered_at)
SELECT pp.profile_id, l.user_id,
    'Lipid Panel', 'Chemistry',
    'LDL 128 / HDL 52 / TG 160', 'mg/dL', 'LDL <130 / HDL >40 / TG <150',
    'LDL borderline. HDL acceptable. Lifestyle modification advised.',
    'COMPLETED', NOW() - INTERVAL '20 days'
FROM patient_profiles pp
JOIN login pl ON pp.user_id = pl.user_id AND pl.email = 'editzzz.ani@gmail.com',
login l WHERE l.email = '2004arjunk@gmail.com';

-- Ani — renal function (PENDING, for upcoming review)
INSERT INTO lab_tests (patient_profile_id, ordered_by_id, test_name, test_category, remarks, status, ordered_at)
SELECT pp.profile_id, l.user_id,
    'Renal Function Test', 'Chemistry',
    'Monitor kidney function given antihypertensive therapy.',
    'PENDING', NOW() - INTERVAL '2 hours'
FROM patient_profiles pp
JOIN login pl ON pp.user_id = pl.user_id AND pl.email = 'editzzz.ani@gmail.com',
login l WHERE l.email = '2004arjunk@gmail.com';

-- ---------------------------------------------------------------------------------
-- 9. NURSE TASKS (assigned to Abhiram Bikkina)
-- ---------------------------------------------------------------------------------

-- Diya tasks
INSERT INTO nurse_tasks (assigned_nurse_id, patient_id, title, description, category, priority, due_time, completed, status)
SELECT l.user_id, pp.profile_id,
    'Record Morning Vitals — Diya Bhat',
    'Record BP, HR, temperature, SpO2 before 9 AM.',
    'vitals', 'medium', NOW() + INTERVAL '20 hours', FALSE, 'upcoming'
FROM login l,
     patient_profiles pp JOIN login pl ON pp.user_id = pl.user_id AND pl.email = 'diyabhat2005@gmail.com'
WHERE l.email = 'abhirambikkina@gmail.com';

INSERT INTO nurse_tasks (assigned_nurse_id, patient_id, title, description, category, priority, due_time, completed, status)
SELECT l.user_id, pp.profile_id,
    'Administer Cetirizine — Diya Bhat',
    'Administer Cetirizine 10mg at night as prescribed by Dr. Riyomen.',
    'medication', 'medium', NOW() + INTERVAL '8 hours', FALSE, 'upcoming'
FROM login l,
     patient_profiles pp JOIN login pl ON pp.user_id = pl.user_id AND pl.email = 'diyabhat2005@gmail.com'
WHERE l.email = 'abhirambikkina@gmail.com';

-- Ani tasks
INSERT INTO nurse_tasks (assigned_nurse_id, patient_id, title, description, category, priority, due_time, completed, status)
SELECT l.user_id, pp.profile_id,
    'Record Morning Vitals — Ani Edit',
    'Record BP, HR, temperature, SpO2. Pay attention to BP — patient is hypertensive.',
    'vitals', 'high', NOW() + INTERVAL '19 hours', FALSE, 'upcoming'
FROM login l,
     patient_profiles pp JOIN login pl ON pp.user_id = pl.user_id AND pl.email = 'editzzz.ani@gmail.com'
WHERE l.email = 'abhirambikkina@gmail.com';

INSERT INTO nurse_tasks (assigned_nurse_id, patient_id, title, description, category, priority, due_time, completed, status)
SELECT l.user_id, pp.profile_id,
    'Administer Amlodipine — Ani Edit',
    'Administer Amlodipine 5mg in the morning as prescribed by Dr. Kumar.',
    'medication', 'high', NOW() + INTERVAL '1 hour', FALSE, 'due-soon'
FROM login l,
     patient_profiles pp JOIN login pl ON pp.user_id = pl.user_id AND pl.email = 'editzzz.ani@gmail.com'
WHERE l.email = 'abhirambikkina@gmail.com';

INSERT INTO nurse_tasks (assigned_nurse_id, patient_id, title, description, category, priority, due_time, completed, status)
SELECT l.user_id, pp.profile_id,
    'Collect Blood Sample for Renal Function Test — Ani Edit',
    'Coordinate with lab for sample collection. Ensure patient is fasting.',
    'assessment', 'high', NOW() + INTERVAL '4 hours', FALSE, 'upcoming'
FROM login l,
     patient_profiles pp JOIN login pl ON pp.user_id = pl.user_id AND pl.email = 'editzzz.ani@gmail.com'
WHERE l.email = 'abhirambikkina@gmail.com';

-- ---------------------------------------------------------------------------------
-- 10. HANDOVER NOTES (from Abhiram Bikkina - nurse)
-- ---------------------------------------------------------------------------------

INSERT INTO handover_notes (author_id, patient_id, type, priority, content, shift_direction)
SELECT l.user_id, pp.profile_id,
    'clinical', 'high',
    'Ani Edit (hypertension) — BP was 136/86 this morning, down from 140/90 two days ago. Amlodipine seems to be working. Renal function test sample due today — ensure the next shift collects it.',
    'FOR_NEXT'
FROM login l,
     patient_profiles pp JOIN login pl ON pp.user_id = pl.user_id AND pl.email = 'editzzz.ani@gmail.com'
WHERE l.email = 'abhirambikkina@gmail.com';

INSERT INTO handover_notes (author_id, patient_id, type, priority, content, shift_direction)
SELECT l.user_id, pp.profile_id,
    'general', 'normal',
    'Diya Bhat — presented mild nasal congestion this morning but otherwise comfortable. Cetirizine administered on schedule. CBC test result still pending.',
    'FOR_NEXT'
FROM login l,
     patient_profiles pp JOIN login pl ON pp.user_id = pl.user_id AND pl.email = 'diyabhat2005@gmail.com'
WHERE l.email = 'abhirambikkina@gmail.com';

-- ---------------------------------------------------------------------------------
-- 11. AUDIT LOGS
-- ---------------------------------------------------------------------------------

INSERT INTO audit_logs (email, action, ip_address, details, timestamp)
VALUES
    ('manvitha3626@gmail.com',  'LOGIN_SUCCESS',       '203.0.113.10', 'method=password',                 NOW() - INTERVAL '2 hours'),
    ('riyomen.mikey@gmail.com', 'LOGIN_SUCCESS',       '203.0.113.11', 'method=password+2fa',              NOW() - INTERVAL '3 hours'),
    ('2004arjunk@gmail.com',    'LOGIN_SUCCESS',       '203.0.113.12', 'method=password+2fa',              NOW() - INTERVAL '4 hours'),
    ('abhirambikkina@gmail.com','LOGIN_SUCCESS',       '203.0.113.13', 'method=password',                 NOW() - INTERVAL '5 hours'),
    ('abhiramamrita@gmail.com', 'LOGIN_SUCCESS',       '203.0.113.14', 'method=password',                 NOW() - INTERVAL '5 hours'),
    ('diyabhat2005@gmail.com',  'LOGIN_SUCCESS',       '203.0.113.15', 'method=password',                 NOW() - INTERVAL '6 hours'),
    ('editzzz.ani@gmail.com',   'LOGIN_SUCCESS',       '203.0.113.16', 'method=password',                 NOW() - INTERVAL '6 hours'),
    ('abhirambikkina@gmail.com','VITAL_SIGNS_RECORDED','203.0.113.13', 'bp=120/78 hr=72 patient=diyabhat2005@gmail.com', NOW() - INTERVAL '1 hour'),
    ('abhirambikkina@gmail.com','VITAL_SIGNS_RECORDED','203.0.113.13', 'bp=136/86 hr=74 patient=editzzz.ani@gmail.com',  NOW() - INTERVAL '1 hour'),
    ('riyomen.mikey@gmail.com', 'PRESCRIPTION_CREATED','203.0.113.11', 'medication=Cetirizine patient=diyabhat2005@gmail.com', NOW() - INTERVAL '14 days'),
    ('2004arjunk@gmail.com',    'PRESCRIPTION_CREATED','203.0.113.12', 'medication=Amlodipine patient=editzzz.ani@gmail.com',  NOW() - INTERVAL '21 days'),
    ('riyomen.mikey@gmail.com', 'LAB_TEST_ORDERED',   '203.0.113.11', 'test=Serum IgE patient=diyabhat2005@gmail.com',        NOW() - INTERVAL '13 days'),
    ('2004arjunk@gmail.com',    'LAB_TEST_ORDERED',   '203.0.113.12', 'test=Lipid Panel patient=editzzz.ani@gmail.com',       NOW() - INTERVAL '20 days');

-- ---------------------------------------------------------------------------------
-- 12. PATIENT CONSENTS
--     Grant staff access to patient data so dashboards are not blocked.
--     consent_type values: MEDICAL_RECORDS | LAB_RESULTS | PRESCRIPTIONS | VITAL_SIGNS | ALL
--     status values: ACTIVE | REVOKED
-- ---------------------------------------------------------------------------------

-- Dr. Mikey → Diya (ALL access — treating physician)
INSERT INTO patient_consents (patient_id, granted_to_id, consent_type, status, granted_at)
SELECT pp.profile_id, l.user_id, 'ALL', 'ACTIVE', NOW() - INTERVAL '14 days'
FROM patient_profiles pp
JOIN login pl ON pp.user_id = pl.user_id AND pl.email = 'diyabhat2005@gmail.com',
login l WHERE l.email = 'riyomen.mikey@gmail.com';

-- Dr. Arjun → Ani (ALL access — treating physician)
INSERT INTO patient_consents (patient_id, granted_to_id, consent_type, status, granted_at)
SELECT pp.profile_id, l.user_id, 'ALL', 'ACTIVE', NOW() - INTERVAL '21 days'
FROM patient_profiles pp
JOIN login pl ON pp.user_id = pl.user_id AND pl.email = 'editzzz.ani@gmail.com',
login l WHERE l.email = '2004arjunk@gmail.com';

-- Nurse Abhiram → Diya (VITAL_SIGNS + MEDICAL_RECORDS access)
INSERT INTO patient_consents (patient_id, granted_to_id, consent_type, status, granted_at)
SELECT pp.profile_id, l.user_id, unnested.consent_type, 'ACTIVE', NOW() - INTERVAL '14 days'
FROM patient_profiles pp
JOIN login pl ON pp.user_id = pl.user_id AND pl.email = 'diyabhat2005@gmail.com',
login l,
(VALUES ('VITAL_SIGNS'), ('MEDICAL_RECORDS'), ('PRESCRIPTIONS')) AS unnested(consent_type)
WHERE l.email = 'abhirambikkina@gmail.com';

-- Nurse Abhiram → Ani (VITAL_SIGNS + MEDICAL_RECORDS access)
INSERT INTO patient_consents (patient_id, granted_to_id, consent_type, status, granted_at)
SELECT pp.profile_id, l.user_id, unnested.consent_type, 'ACTIVE', NOW() - INTERVAL '21 days'
FROM patient_profiles pp
JOIN login pl ON pp.user_id = pl.user_id AND pl.email = 'editzzz.ani@gmail.com',
login l,
(VALUES ('VITAL_SIGNS'), ('MEDICAL_RECORDS'), ('PRESCRIPTIONS')) AS unnested(consent_type)
WHERE l.email = 'abhirambikkina@gmail.com';

-- Lab Tech Abhiramamrita → Diya (LAB_RESULTS access)
INSERT INTO patient_consents (patient_id, granted_to_id, consent_type, status, granted_at)
SELECT pp.profile_id, l.user_id, 'LAB_RESULTS', 'ACTIVE', NOW() - INTERVAL '13 days'
FROM patient_profiles pp
JOIN login pl ON pp.user_id = pl.user_id AND pl.email = 'diyabhat2005@gmail.com',
login l WHERE l.email = 'abhiramamrita@gmail.com';

-- Lab Tech Abhiramamrita → Ani (LAB_RESULTS access)
INSERT INTO patient_consents (patient_id, granted_to_id, consent_type, status, granted_at)
SELECT pp.profile_id, l.user_id, 'LAB_RESULTS', 'ACTIVE', NOW() - INTERVAL '20 days'
FROM patient_profiles pp
JOIN login pl ON pp.user_id = pl.user_id AND pl.email = 'editzzz.ani@gmail.com',
login l WHERE l.email = 'abhiramamrita@gmail.com';
