package com.securehealth.backend.dto;
import lombok.Data;
import java.time.LocalDateTime;

@Data
public class MedicalRecordDTO {
    private Long recordId;
    private Long patientId;
    private String doctorName;
    private String diagnosis;
    private String symptoms;
    private String treatmentProvided;
    private String notes;
    private LocalDateTime recordDate;
    private LocalDateTime createdAt;
}