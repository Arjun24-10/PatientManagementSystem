package com.securehealth.backend.dto;

import lombok.Data;
import java.time.LocalDate;

@Data
public class PatientProfileRequest {
    private String firstName;
    private String lastName;
    private LocalDate dateOfBirth;
    private String gender;
    private String contactNumber;
    private String address;
    private String medicalHistory;
}