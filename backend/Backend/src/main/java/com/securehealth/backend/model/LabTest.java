package com.securehealth.backend.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@Entity
@Table(name = "lab_tests")
public class LabTest {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long testId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "patient_profile_id", nullable = false)
    private PatientProfile patient;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "ordered_by_doctor_id", nullable = false)
    private Login orderedBy;

    // Can be null until a lab tech actually processes it
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "fulfilled_by_tech_id")
    private Login fulfilledBy;

    @Column(nullable = false)
    private String testName; // e.g., "Complete Blood Count", "Lipid Panel"

    @Column(columnDefinition = "TEXT")
    private String resultData; // The actual lab results

    // Status: PENDING, COMPLETED, CANCELLED
    @Column(nullable = false)
    private String status = "PENDING";

    @Column(updatable = false)
    private LocalDateTime orderedAt = LocalDateTime.now();

    private LocalDateTime completedAt;
}