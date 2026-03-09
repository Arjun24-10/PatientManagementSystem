package com.securehealth.backend.dto;

import lombok.Data;

@Data
public class MedicalRecordRequest {
    private Long patientId;
    private String diagnosis;
    private String symptoms;
    private String treatmentProvided;
}