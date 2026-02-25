import urllib.request
import json
import subprocess
import time

def register_user(email, password, role, name, dob):
    url = "http://localhost:8081/api/auth/register"
    data = {
        "email": email,
        "password": password,
        "role": role,
        "full_name": name,
        "date_of_birth": dob,
        "address": "123 Main St"
    }
    
    req = urllib.request.Request(url, data=json.dumps(data).encode('utf-8'))
    req.add_header('Content-Type', 'application/json')
    try:
        response = urllib.request.urlopen(req)
        print(f"Registered {email}: {response.code}")
    except urllib.error.HTTPError as e:
        print(f"Failed to register {email}: {e.code} {e.reason}")
    except Exception as e:
        print(f"Failed to register {email}: {e}")

# Note: Using valid NIST 800-63B password length >= 12 characters
register_user("patient@securehealth.com", "Password123xyz!", "PATIENT", "Ben Tennyson", "1995-12-27")
register_user("doctor@securehealth.com", "Password123xyz!", "DOCTOR", "Dr. Gwen", "1980-05-15")
register_user("nurse@securehealth.com", "Password123xyz!", "NURSE", "Nurse Joy", "1990-01-01")
register_user("admin@securehealth.com", "Password123xyz!", "ADMIN", "Admin Max", "1975-01-01")

time.sleep(2)

print("Fetching IDs and generating seed SQL...")
# Now we use docker exec psql to insert seed data
sql_commands = """
DO $$ 
DECLARE
    v_patient_id bigint;
    v_patient_profile_id bigint;
    v_doctor_id bigint;
    v_nurse_id bigint;
BEGIN
    SELECT user_id INTO v_patient_id FROM login WHERE email = 'patient@securehealth.com' LIMIT 1;
    SELECT profile_id INTO v_patient_profile_id FROM patient_profiles WHERE user_id = v_patient_id LIMIT 1;
    
    SELECT user_id INTO v_doctor_id FROM login WHERE email = 'doctor@securehealth.com' LIMIT 1;
    SELECT user_id INTO v_nurse_id FROM login WHERE email = 'nurse@securehealth.com' LIMIT 1;
    
    IF v_patient_profile_id IS NOT NULL AND v_doctor_id IS NOT NULL THEN
        
        -- Delete old mock data
        DELETE FROM appointments WHERE patient_profile_id = v_patient_profile_id;
        DELETE FROM prescriptions WHERE patient_profile_id = v_patient_profile_id;
        DELETE FROM lab_tests WHERE patient_profile_id = v_patient_profile_id;
        DELETE FROM medical_records WHERE patient_profile_id = v_patient_profile_id;
        DELETE FROM vital_signs WHERE patient_profile_id = v_patient_profile_id;

        -- APPOINTMENTS
        INSERT INTO appointments (patient_profile_id, doctor_id, appointment_date, status, reason_for_visit, doctor_notes, created_at)
        VALUES 
        (v_patient_profile_id, v_doctor_id, NOW() + INTERVAL '2 days', 'SCHEDULED', 'Routine Checkup', NULL, NOW()),
        (v_patient_profile_id, v_doctor_id, NOW() - INTERVAL '1 month', 'COMPLETED', 'Flu symptoms', 'Patient is recovering well.', NOW());

        -- PRESCRIPTIONS
        INSERT INTO prescriptions (patient_profile_id, doctor_id, medication_name, dosage, frequency, duration, special_instructions, issued_at, status)
        VALUES 
        (v_patient_profile_id, v_doctor_id, 'Amoxicillin', '500mg', 'Twice a day', '7 days', 'Take with food', NOW() - INTERVAL '5 days', 'ACTIVE'),
        (v_patient_profile_id, v_doctor_id, 'Ibuprofen', '200mg', 'As needed', '5 days', NULL, NOW() - INTERVAL '1 month', 'COMPLETED');

        -- LAB TESTS
        INSERT INTO lab_tests (patient_profile_id, ordered_by_doctor_id, fulfilled_by_tech_id, test_name, result_data, status, ordered_at, completed_at)
        VALUES 
        (v_patient_profile_id, v_doctor_id, NULL, 'Complete Blood Count', 'WBC: 6.5, RBC: 4.8, Hb: 14.2 (Normal)', 'COMPLETED', NOW() - INTERVAL '2 weeks', NOW() - INTERVAL '13 days'),
        (v_patient_profile_id, v_doctor_id, NULL, 'Lipid Panel', NULL, 'PENDING', NOW() - INTERVAL '1 day', NULL);

        -- MEDICAL RECORDS
        INSERT INTO medical_records (patient_profile_id, doctor_id, diagnosis, symptoms, treatment_provided, created_at, updated_at)
        VALUES 
        (v_patient_profile_id, v_doctor_id, 'Seasonal Allergies', 'Sneezing, runny nose', 'Prescribed antihistamines.', NOW() - INTERVAL '6 months', NOW() - INTERVAL '6 months'),
        (v_patient_profile_id, v_doctor_id, 'Mild Hypertension', 'Occasional headaches', 'Advised dietary changes and exercise.', NOW() - INTERVAL '1 year', NOW() - INTERVAL '1 year');

        -- VITAL SIGNS (Assuming nurse_id is valid, use doctor_id if nurse_id is null for fallback)
        INSERT INTO vital_signs (patient_profile_id, nurse_id, blood_pressure, heart_rate, temperature, oxygen_level, recorded_at)
        VALUES 
        (v_patient_profile_id, COALESCE(v_nurse_id, v_doctor_id), '120/80', 72, 98.6, 99, NOW() - INTERVAL '2 weeks'),
        (v_patient_profile_id, COALESCE(v_nurse_id, v_doctor_id), '122/82', 74, 98.4, 98, NOW() - INTERVAL '1 month');

    END IF;
END $$;
"""

with open("seed_temp.sql", "w") as f:
    f.write(sql_commands)

print("Executing SQL in Docker...")
subprocess.run('docker exec -i secure_health_db psql -U postgres -d healthcare_auth_db < seed_temp.sql', shell=True)
print("Seeding complete! You can login with patient@securehealth.com and doctor@securehealth.com (Password: Password123xyz!)")
