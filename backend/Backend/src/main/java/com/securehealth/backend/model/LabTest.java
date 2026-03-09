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
    @JoinColumn(name = "ordered_by_id", nullable = false)
    private Login orderedBy;

    private String testName;
    private String testCategory;
    private String resultValue;
    private String unit;
    private String referenceRange;
    private String remarks;
    private String status;

    private String fileUrl;

    @Column(updatable = false)
    private LocalDateTime orderedAt = LocalDateTime.now();
}