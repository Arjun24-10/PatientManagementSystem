package com.securehealth.backend.dto;

import lombok.Data;
import java.time.LocalDate;

@Data
public class PatientDirectoryDTO {
    private Long profileId;
    private Long userId;       // In case the Admin needs to trigger a password reset
    private String firstName;
    private String lastName;
    private String email;      // Pulled dynamically from the Login entity
    private String contactNumber;
    private LocalDate dateOfBirth;
}