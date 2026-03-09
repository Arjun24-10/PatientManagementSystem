package com.securehealth.backend.repository;

import com.securehealth.backend.model.Consent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ConsentRepository extends JpaRepository<Consent, Long> {

    // All consents for a patient
    List<Consent> findByPatient_ProfileIdOrderByGrantedAtDesc(Long profileId);

    // Active consents for a patient
    List<Consent> findByPatient_ProfileIdAndStatus(Long profileId, String status);

    // What a specific provider is allowed to access
    List<Consent> findByGrantedTo_UserIdAndStatus(Long userId, String status);

    // Check if a specific consent already exists
    boolean existsByPatient_ProfileIdAndGrantedTo_UserIdAndConsentTypeAndStatus(
            Long profileId, Long userId, String consentType, String status);
}
