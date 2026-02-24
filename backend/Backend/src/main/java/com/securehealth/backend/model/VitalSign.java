package com.securehealth.backend.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@Entity
@Table(name = "vital_signs")
public class VitalSign {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long vitalId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "patient_profile_id", nullable = false)
    private PatientProfile patient;

    // The nurse who logged these vitals
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "nurse_id", nullable = false)
    private Login nurse;

    private String bloodPressure; // e.g., "120/80"
    
    private Integer heartRate;    // BPM
    
    private Double temperature;   // Celsius or Fahrenheit

    private Integer oxygenLevel;  // SpO2 Percentage

    @Column(updatable = false)
    private LocalDateTime recordedAt = LocalDateTime.now();
}