package com.securehealth.backend.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class LabTestRequest {
    @NotNull(message = "Patient ID is required")
    private Long patientId;

    @NotBlank(message = "Test name is required")
    private String testName;         // e.g., "Complete Blood Count"

    @NotBlank(message = "Test category is required")
    private String testCategory;     // e.g., "Hematology"

    private String resultValue;      // e.g., "14.5"
    private String unit;             // e.g., "g/dL"
    private String referenceRange;   // e.g., "13.8 - 17.2"
    private String remarks;          // e.g., "Normal"
}