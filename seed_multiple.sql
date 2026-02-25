
DO $$ 
DECLARE
    v_doc1 bigint; v_doc2 bigint; v_doc3 bigint;
    v_nurse1 bigint; v_nurse2 bigint;
    p_record RECORD;
    random_doc bigint;
    random_nurse bigint;
BEGIN
    -- Get doctor user IDs
    SELECT user_id INTO v_doc1 FROM login WHERE email = 'dr.smith@securehealth.com' LIMIT 1;
    SELECT user_id INTO v_doc2 FROM login WHERE email = 'dr.jones@securehealth.com' LIMIT 1;
    SELECT user_id INTO v_doc3 FROM login WHERE email = 'dr.davis@securehealth.com' LIMIT 1;
    
    -- Get nurse user IDs
    SELECT user_id INTO v_nurse1 FROM login WHERE email = 'nurse.joy@securehealth.com' LIMIT 1;
    SELECT user_id INTO v_nurse2 FROM login WHERE email = 'nurse.jack@securehealth.com' LIMIT 1;
    
    -- Loop through all patients
    FOR p_record IN 
        SELECT p.profile_id FROM patient_profiles p 
        JOIN login l ON p.user_id = l.user_id 
        WHERE l.email LIKE 'patient%@securehealth.com'
    LOOP
        -- Pick a random doctor and nurse for this patient's records
        IF p_record.profile_id % 3 = 0 THEN random_doc := v_doc1; ELSIF p_record.profile_id % 3 = 1 THEN random_doc := v_doc2; ELSE random_doc := v_doc3; END IF;
        IF p_record.profile_id % 2 = 0 THEN random_nurse := v_nurse1; ELSE random_nurse := v_nurse2; END IF;

        -- Appointments
        INSERT INTO appointments (patient_profile_id, doctor_id, appointment_date, status, reason_for_visit, created_at) VALUES 
        (p_record.profile_id, random_doc, NOW() - INTERVAL '1 month', 'COMPLETED', 'Initial Consultation', NOW() - INTERVAL '35 days'),
        (p_record.profile_id, random_doc, NOW() - INTERVAL '5 days', 'COMPLETED', 'Follow-up', NOW() - INTERVAL '10 days'),
        (p_record.profile_id, random_doc, NOW() + INTERVAL '10 days', 'SCHEDULED', 'Routine Checkup', NOW());

        -- Prescriptions
        INSERT INTO prescriptions (patient_profile_id, doctor_id, medication_name, dosage, frequency, duration, issued_at, status) VALUES 
        (p_record.profile_id, random_doc, 'Amoxicillin', '500mg', 'Twice a day', '7 days', NOW() - INTERVAL '1 month', 'COMPLETED'),
        (p_record.profile_id, random_doc, 'Lisinopril', '10mg', 'Once a day', '30 days', NOW() - INTERVAL '5 days', 'ACTIVE'),
        (p_record.profile_id, random_doc, 'Metformin', '500mg', 'Twice a day', '30 days', NOW() - INTERVAL '2 days', 'ACTIVE');

        -- Lab Tests
        INSERT INTO lab_tests (patient_profile_id, ordered_by_doctor_id, test_name, result_data, status, ordered_at, completed_at) VALUES 
        (p_record.profile_id, random_doc, 'Complete Blood Count', 'WBC: Normal, RBC: Normal', 'COMPLETED', NOW() - INTERVAL '1 month', NOW() - INTERVAL '29 days'),
        (p_record.profile_id, random_doc, 'Lipid Panel', 'Cholesterol: High', 'COMPLETED', NOW() - INTERVAL '5 days', NOW() - INTERVAL '4 days'),
        (p_record.profile_id, random_doc, 'Glucose Tolerance', NULL, 'PENDING', NOW() - INTERVAL '1 day', NULL);

        -- Medical Records
        INSERT INTO medical_records (patient_profile_id, doctor_id, diagnosis, symptoms, treatment_provided, created_at, updated_at) VALUES 
        (p_record.profile_id, random_doc, 'Mild Hypertension', 'Headaches', 'Lisinopril prescribed', NOW() - INTERVAL '1 month', NOW() - INTERVAL '1 month'),
        (p_record.profile_id, random_doc, 'Hyperlipidemia', 'Routine screening finding', 'Dietary changes recommended', NOW() - INTERVAL '5 days', NOW() - INTERVAL '5 days');

        -- Vital Signs
        INSERT INTO vital_signs (patient_profile_id, nurse_id, blood_pressure, heart_rate, temperature, oxygen_level, recorded_at) VALUES 
        (p_record.profile_id, random_nurse, '130/85', 78, 98.6, 98, NOW() - INTERVAL '1 month'),
        (p_record.profile_id, random_nurse, '125/80', 75, 98.4, 99, NOW() - INTERVAL '5 days'),
        (p_record.profile_id, random_nurse, '120/80', 72, 98.6, 99, NOW());
        
    END LOOP;
END $$;
