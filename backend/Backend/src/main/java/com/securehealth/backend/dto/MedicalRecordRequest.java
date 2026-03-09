package com.securehealth.backend.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class MedicalRecordRequest {
    @NotNull(message = "Patient ID is required")
    private Long patientId;

    @NotBlank(message = "Diagnosis is required")
    private String diagnosis;

    @NotBlank(message = "Symptoms are required")
    private String symptoms;

    @NotBlank(message = "Treatment provided is required")
    private String treatmentProvided;
}