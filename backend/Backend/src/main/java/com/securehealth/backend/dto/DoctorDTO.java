package com.securehealth.backend.dto;

import lombok.Data;

@Data
public class DoctorDTO {
    private Long id; // Maps to profileId
    private String firstName;
    private String lastName;
    private String email; // From the linked Login account
    private String specialty;
    private String contactNumber;
    private String department;
    private String availabilitySchedule;
}