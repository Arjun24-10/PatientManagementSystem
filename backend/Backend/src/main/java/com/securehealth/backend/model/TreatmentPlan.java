package com.securehealth.backend.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@Entity
@Table(name = "treatment_plans")
public class TreatmentPlan {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long planId;

    // The patient receiving the treatment
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "patient_profile_id", nullable = false)
    private PatientProfile patient;

    // The doctor who created the plan
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "doctor_id", nullable = false)
    private Login doctor;

    @Column(nullable = false)
    private String diagnosis;

    @Column(columnDefinition = "TEXT")
    private String prescription;

    @Column(columnDefinition = "TEXT")
    private String doctorNotes;

    @Column(updatable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    private LocalDateTime updatedAt = LocalDateTime.now();

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}