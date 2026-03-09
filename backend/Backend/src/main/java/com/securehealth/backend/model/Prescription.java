package com.securehealth.backend.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@Entity
@Table(name = "prescriptions")
public class Prescription {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long prescriptionId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "patient_profile_id", nullable = false)
    private PatientProfile patient;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "doctor_id", nullable = false)
    private Login doctor;

    @Column(nullable = false)
    private String medicationName;

    @Column(nullable = false)
    private String dosage; // e.g., "500mg"

    @Column(nullable = false)
    private String frequency; // e.g., "Twice a day"

    @Column(nullable = false)
    private String duration; // e.g., "7 days"

    @Column(columnDefinition = "TEXT")
    private String specialInstructions; // e.g., "Take with food"

    @Column(updatable = false)
    private LocalDateTime issuedAt = LocalDateTime.now();
    
    private LocalDateTime startDate;
    
    private LocalDateTime endDate;
    
    private Integer refillsRemaining = 0;

    // Status: ACTIVE, COMPLETED, CANCELLED
    private String status = "ACTIVE";
}