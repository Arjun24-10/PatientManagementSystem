package com.securehealth.backend.security;

import com.securehealth.backend.model.PatientProfile;
import com.securehealth.backend.repository.PatientProfileRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

@Component
public class PatientAccessValidator {

    @Autowired
    private PatientProfileRepository patientProfileRepository;

    public void validateAccess(Long patientId, Authentication auth) {
        String role = auth.getAuthorities().stream()
                .findFirst()
                .map(GrantedAuthority::getAuthority)
                .orElse("UNKNOWN");

        // Doctors, Nurses, and Admins bypass this specific ownership check
        if (role.equals("DOCTOR") || role.equals("ADMIN") || role.equals("NURSE") || role.equals("LAB_TECHNICIAN")) {
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