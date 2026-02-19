package com.securehealth.backend.service;

import com.securehealth.backend.dto.PatientProfileRequest;
import com.securehealth.backend.model.*;
import com.securehealth.backend.repository.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class PatientService {

    @Autowired
    private LoginRepository loginRepository;

    @Autowired
    private PatientProfileRepository patientProfileRepository;

    @Autowired
    private TreatmentPlanRepository treatmentPlanRepository;

    @Autowired
    private VitalSignRepository vitalSignRepository;

    @Autowired
    private LabTestRepository labTestRepository;

    /**
     * Creates or updates the patient's personal profile.
     * The email comes securely from the JWT token, preventing users from modifying others' profiles.
     */
    @Transactional
    public PatientProfile createOrUpdateProfile(String email, PatientProfileRequest request) {
        // 1. Find the logged-in user securely via the JWT email
        Login user = loginRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // 2. Fetch existing profile or create a new one
        PatientProfile profile = patientProfileRepository.findByUser(user)
                .orElse(new PatientProfile());

        // 3. Update the fields
        profile.setUser(user);
        profile.setFirstName(request.getFirstName());
        profile.setLastName(request.getLastName());
        profile.setDateOfBirth(request.getDateOfBirth());
        profile.setGender(request.getGender());
        profile.setContactNumber(request.getContactNumber());
        profile.setAddress(request.getAddress());
        profile.setMedicalHistory(request.getMedicalHistory());

        // 4. Save to database
        return patientProfileRepository.save(profile);
    }

    /**
     * Fetches the complete Patient Dashboard summary.
     * Aggregates Profile, Vitals, Treatments, and Labs in one call.
     */
    @Transactional(readOnly = true)
    public Map<String, Object> getPatientDashboard(String email) {
        // 1. Authenticate the User
        Login user = loginRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // 2. Get the Profile (If they don't have one, prompt them to create it)
        PatientProfile profile = patientProfileRepository.findByUser(user)
                .orElseThrow(() -> new RuntimeException("PROFILE_INCOMPLETE"));

        // 3. Fetch their medical data using the repositories we just built
        List<TreatmentPlan> treatments = treatmentPlanRepository.findByPatientOrderByCreatedAtDesc(profile);
        List<VitalSign> vitals = vitalSignRepository.findByPatientOrderByRecordedAtDesc(profile);
        List<LabTest> labs = labTestRepository.findByPatientOrderByOrderedAtDesc(profile);

        // 4. Construct the Dashboard JSON Response
        Map<String, Object> dashboardData = new HashMap<>();
        
        // Basic Info
        dashboardData.put("patientName", profile.getFirstName() + " " + profile.getLastName());
        dashboardData.put("age", calculateAge(profile.getDateOfBirth())); // Helper method
        dashboardData.put("assignedDoctor", profile.getAssignedDoctor() != null ? 
                "Dr. " + profile.getAssignedDoctor().getEmail() : "Not Assigned");

        // Medical Data (Limit to recent 5 for dashboard overview)
        dashboardData.put("recentTreatments", treatments.stream().limit(5).toList());
        dashboardData.put("recentVitals", vitals.stream().limit(5).toList());
        dashboardData.put("recentLabs", labs.stream().limit(5).toList());

        return dashboardData;
    }

    // Helper method to calculate age from DOB
    private int calculateAge(java.time.LocalDate dob) {
        if (dob == null) return 0;
        return java.time.Period.between(dob, java.time.LocalDate.now()).getYears();
    }
}