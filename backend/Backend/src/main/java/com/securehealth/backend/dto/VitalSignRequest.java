package com.securehealth.backend.dto;

import lombok.Data;

@Data
public class VitalSignRequest {
    private Long patientId;
    private String bloodPressure;     // e.g., "120/80"
    private Integer heartRate;        // e.g., 75
    private Double temperature;       // e.g., 98.6
    private Integer respiratoryRate;  // e.g., 16
    private Integer oxygenSaturation; // e.g., 99
    private Double weight;            // in kg or lbs
    private Double height;            // in cm or inches
}