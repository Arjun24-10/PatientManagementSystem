package com.securehealth.backend.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@Entity
@Table(name = "doctor_profiles")
public class DoctorProfile {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long profileId;

    // 1-to-1 with Login (Auth)
    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", referencedColumnName = "userId", nullable = false, unique = true)
    private Login user;

    @Column(nullable = false)
    private String firstName;

    @Column(nullable = false)
    private String lastName;

    // This fulfills the frontend's GET /doctors/specialty/:specialty
    @Column(nullable = false)
    private String specialty; 

    private String contactNumber;
    
    private String department;
    
    // Optional: e.g., "Mon-Fri 9AM-5PM"
    private String availabilitySchedule; 
}