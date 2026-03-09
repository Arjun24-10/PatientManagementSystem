package com.securehealth.backend.dto;
import lombok.Data;
import java.time.LocalDateTime;

@Data
public class PrescriptionDTO {
    private Long prescriptionId;
    private String doctorName;
    private String medicationName;
    private String dosage;
    private String frequency;
    private String duration;
    private String specialInstructions;
    private String status;
    private LocalDateTime issuedAt;
    private LocalDateTime startDate;
    private LocalDateTime endDate;
    private Integer refillsRemaining;
}