package com.securehealth.backend.dto;

import lombok.Data;

@Data
public class LabTestRequest {
    private Long patientId;
    private String testName;         // e.g., "Complete Blood Count"
    private String testCategory;     // e.g., "Hematology"
    private String resultValue;      // e.g., "14.5"
    private String unit;             // e.g., "g/dL"
    private String referenceRange;   // e.g., "13.8 - 17.2"
    private String remarks;          // e.g., "Normal"
}