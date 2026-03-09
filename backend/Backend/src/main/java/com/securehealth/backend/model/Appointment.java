package com.securehealth.backend.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
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

    // Status: PENDING_APPROVAL, SCHEDULED, COMPLETED, CANCELLED, NO_SHOW, REJECTED
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AppointmentStatus status = AppointmentStatus.PENDING_APPROVAL;

    @Column(columnDefinition = "TEXT")
    private String reasonForVisit;

    @Column(columnDefinition = "TEXT")
    private String doctorNotes;

    @Column(updatable = false)
    private LocalDateTime createdAt = LocalDateTime.now();
}