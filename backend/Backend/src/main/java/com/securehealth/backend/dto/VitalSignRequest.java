package com.securehealth.backend.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class VitalSignRequest {
    @NotNull(message = "Patient ID is required")
    private Long patientId;

    @NotBlank(message = "Blood pressure is required")
    private String bloodPressure;     // e.g., "120/80"

    @NotNull(message = "Heart rate is required")
    private Integer heartRate;        // e.g., 75

    @NotNull(message = "Temperature is required")
    private Double temperature;       // e.g., 98.6

    private Integer respiratoryRate;  // e.g., 16
    private Integer oxygenSaturation; // e.g., 99
    private Double weight;            // in kg or lbs
    private Double height;            // in cm or inches
}