package com.securehealth.backend.dto;

import lombok.Data;
import java.time.LocalDateTime;

@Data
public class VitalSignDTO {
    private Long vitalSignId;
    private Long patientProfileId;
    private String nurseEmail; // To show who recorded it
    
    private String bloodPressure;
    private Integer heartRate;
    private Double temperature;
    private Integer respiratoryRate;
    private Integer oxygenSaturation;
    private Double weight;
    private Double height;
    
    private LocalDateTime recordedAt;
}