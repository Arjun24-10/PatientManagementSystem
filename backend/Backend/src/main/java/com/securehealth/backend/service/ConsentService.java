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
     * Retrieves all consent records for the currently logged-in patient.
     *
     * @param patientEmail the email of the patient
     * @return a list of {@link Consent} entities
     */
    public List<Consent> getMyConsents(String patientEmail) {
        PatientProfile profile = getPatientProfile(patientEmail);
        return consentRepository.findByPatient_ProfileIdOrderByGrantedAtDesc(profile.getProfileId());
    }

    /**
     * Grants a provider access to a specific type of patient data.
     *
     * @param patientEmail the email of the patient granting consent
     * @param payload a map containing 'grantedToId', 'consentType', 'reason', and optional 'expiresAt'
     * @return the saved {@link Consent} entity
     * @throws RuntimeException if the provider is not found or an active consent already exists
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
     * Revokes an existing consent record.
     *
     * @param patientEmail the email of the patient revoking consent
     * @param consentId the ID of the consent record to revoke
     * @return the updated {@link Consent} entity
     * @throws RuntimeException if the consent is not found, not owned by the patient, or already revoked
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
     * Validates if a healthcare provider has active consent for a patient's data.
     * <p>
     * Checks for either the specific data type or a general "ALL" consent.
     * </p>
     *
     * @param patientProfileId the patient's profile ID
     * @param providerUserId the provider's user ID
     * @param consentType the type of data being accessed (e.g., "VITALS", "RECORDS")
     * @return true if active consent is found, false otherwise
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
