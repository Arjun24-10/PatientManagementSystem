package com.securehealth.backend.service;

import com.securehealth.backend.model.Consent;
import com.securehealth.backend.model.Login;
import com.securehealth.backend.model.PatientProfile;
import com.securehealth.backend.repository.ConsentRepository;
import com.securehealth.backend.repository.LoginRepository;
import com.securehealth.backend.repository.PatientProfileRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Service
@Transactional
public class ConsentService {

    @Autowired private ConsentRepository consentRepository;
    @Autowired private LoginRepository loginRepository;
    @Autowired private PatientProfileRepository patientProfileRepository;

    /**
     * Get all consents for the currently logged-in patient.
     */
    public List<Consent> getMyConsents(String patientEmail) {
        PatientProfile profile = getPatientProfile(patientEmail);
        return consentRepository.findByPatient_ProfileIdOrderByGrantedAtDesc(profile.getProfileId());
    }

    /**
     * Grant consent for a provider to access a specific data type.
     */
    public Consent grantConsent(String patientEmail, Map<String, Object> payload) {
        PatientProfile profile = getPatientProfile(patientEmail);

        Long grantedToId = Long.valueOf(payload.get("grantedToId").toString());
        String consentType = payload.getOrDefault("consentType", "ALL").toString().toUpperCase();
        String reason = payload.getOrDefault("reason", "").toString();

        // Validate the provider exists
        Login provider = loginRepository.findById(grantedToId)
                .orElseThrow(() -> new RuntimeException("Provider not found with id: " + grantedToId));

        // Check for duplicate active consent
        if (consentRepository.existsByPatient_ProfileIdAndGrantedTo_UserIdAndConsentTypeAndStatus(
                profile.getProfileId(), grantedToId, consentType, "ACTIVE")) {
            throw new RuntimeException("Active consent already exists for this provider and data type.");
        }

        Consent consent = new Consent();
        consent.setPatient(profile);
        consent.setGrantedTo(provider);
        consent.setConsentType(consentType);
        consent.setStatus("ACTIVE");
        consent.setReason(reason);

        // Optional expiry
        if (payload.containsKey("expiresAt") && payload.get("expiresAt") != null) {
            consent.setExpiresAt(LocalDateTime.parse(payload.get("expiresAt").toString()));
        }

        return consentRepository.save(consent);
    }

    /**
     * Revoke a patient's consent by ID.
     */
    public Consent revokeConsent(String patientEmail, Long consentId) {
        PatientProfile profile = getPatientProfile(patientEmail);

        Consent consent = consentRepository.findById(consentId)
                .orElseThrow(() -> new RuntimeException("Consent not found with id: " + consentId));

        // Ensure the patient owns this consent
        if (!consent.getPatient().getProfileId().equals(profile.getProfileId())) {
            throw new RuntimeException("You are not authorized to revoke this consent.");
        }

        if ("REVOKED".equals(consent.getStatus())) {
            throw new RuntimeException("This consent has already been revoked.");
        }

        consent.setStatus("REVOKED");
        consent.setRevokedAt(LocalDateTime.now());

        return consentRepository.save(consent);
    }

    /**
     * Utility: Check if a provider has active consent for a specific data type.
     * Can be called from other services to enforce consent checks.
     */
    public boolean hasConsent(Long patientProfileId, Long providerUserId, String consentType) {
        // Check for specific type OR "ALL" type
        return consentRepository.existsByPatient_ProfileIdAndGrantedTo_UserIdAndConsentTypeAndStatus(
                patientProfileId, providerUserId, consentType, "ACTIVE")
                || consentRepository.existsByPatient_ProfileIdAndGrantedTo_UserIdAndConsentTypeAndStatus(
                patientProfileId, providerUserId, "ALL", "ACTIVE");
    }

    private PatientProfile getPatientProfile(String email) {
        Login user = loginRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found with email: " + email));
        return patientProfileRepository.findByUser(user)
                .orElseThrow(() -> new RuntimeException("Patient profile not found for user: " + email));
    }
}
