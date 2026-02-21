package com.securehealth.backend.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@Entity
@Table(name = "appointments")
public class Appointment {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long appointmentId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "patient_profile_id", nullable = false)
    private PatientProfile patient;

    // Doctor associated with the appointment
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "doctor_id", nullable = false)
    private Login doctor;

    @Column(nullable = false)
    private LocalDateTime appointmentDate;

    // Status: SCHEDULED, COMPLETED, CANCELLED, NO_SHOW
    @Column(nullable = false)
    private String status = "SCHEDULED";

    @Column(columnDefinition = "TEXT")
    private String reasonForVisit;

    @Column(columnDefinition = "TEXT")
    private String doctorNotes;

    @Column(updatable = false)
    private LocalDateTime createdAt = LocalDateTime.now();
}