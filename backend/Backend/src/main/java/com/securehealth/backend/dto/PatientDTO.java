package com.securehealth.backend.dto;

import lombok.Data;
import java.time.LocalDate;

@Data
public class PatientDTO {
    private Long id; // Matches the Frontend's expectation of an 'id'
    private String firstName;
    private String lastName;
    private String email; // From the linked Login account
    private LocalDate dateOfBirth;
    private String gender;
    private String contactNumber;
    private String address;
    private String medicalHistory;
    private Long assignedDoctorId;
}