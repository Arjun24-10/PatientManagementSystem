package com.securehealth.backend.security;

import com.securehealth.backend.model.PatientProfile;
import com.securehealth.backend.repository.PatientProfileRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

/**
 * Component for enforcing granular row-level access control for patient data.
 * <p>
 * Ensures that patients can only access their own records, while providing 
 * bypasses for staff roles like DOCTOR and ADMIN.
 * </p>
 */
@Component
public class PatientAccessValidator {

    @Autowired
    private PatientProfileRepository patientProfileRepository;

    /**
     * Validates if the currently authenticated user is authorized to access 
     * the specified patient's data.
     *
     * @param patientId the ID of the patient record being accessed
     * @param auth the current {@link Authentication} object
     * @throws RuntimeException if access is forbidden or the patient is not found
     */
    public void validateAccess(Long patientId, Authentication auth) {
        String role = auth.getAuthorities().stream()
                .findFirst()
                .map(GrantedAuthority::getAuthority)
                .orElse("UNKNOWN");

        // Doctors and Admins bypass this specific ownership check
        if (role.equals("DOCTOR") || role.equals("ADMIN")) {
            return;
        }

        // For patients, verify the profile belongs to their JWT email
        String email = auth.getName();
        PatientProfile profile = patientProfileRepository.findById(patientId)
                .orElseThrow(() -> new RuntimeException("404: Patient not found"));

        if (!profile.getUser().getEmail().equals(email)) {
            throw new RuntimeException("403 Forbidden: You cannot access another patient's records");
        }
    }
}