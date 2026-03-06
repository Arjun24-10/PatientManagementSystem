package com.securehealth.backend.dto;

import lombok.Data;

@Data
public class PrescriptionRequest {
    private Long patientId;
    private String medicationName;
    private String dosage;
    private String frequency;
    private String duration;
    private String specialInstructions;
}