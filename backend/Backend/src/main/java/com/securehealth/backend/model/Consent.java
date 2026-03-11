package com.securehealth.backend.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Entity representing a patient's consent for data sharing.
 * <p>
 * Tracks permissions granted by patients to healthcare providers 
 * (doctors, nurses, technicians) for specific categories of medical data.
 * Consents can be active, expired, or revoked.
 * </p>
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "patient_consents")
public class Consent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // The patient who is granting consent
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "patient_id", referencedColumnName = "profileId", nullable = false)
    @JsonIgnoreProperties({"hibernateLazyInitializer", "handler", "user", "assignedDoctor", "assignedNurse"})
    private PatientProfile patient;

    // The provider who receives access
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "granted_to_id", referencedColumnName = "userId", nullable = false)
    @JsonIgnoreProperties({"hibernateLazyInitializer", "handler", "passwordHash", "otp", "otpExpiry"})
    private Login grantedTo;

    // Data category: MEDICAL_RECORDS, LAB_RESULTS, PRESCRIPTIONS, VITAL_SIGNS, ALL
    @Column(nullable = false)
    private String consentType;

    // ACTIVE or REVOKED
    @Column(nullable = false)
    private String status = "ACTIVE";

    @Column(updatable = false)
    private LocalDateTime grantedAt = LocalDateTime.now();

    // Optional expiry date
    private LocalDateTime expiresAt;

    // Set when the consent is revoked
    private LocalDateTime revokedAt;

    // Optional note from the patient
    @Column(columnDefinition = "TEXT")
    private String reason;
}
