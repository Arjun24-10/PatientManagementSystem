package com.securehealth.backend.dto;
import lombok.Data;
import java.time.LocalDateTime;

@Data
public class LabTestDTO {
    private Long testId;
    
    // Patient Info
    private String patientName;
    private String gender;
    private Long profileId;
    
    // Doctor Info
    private String orderedByName;
    private String orderedByDoctor;
    private Long orderedById;
    
    // Test Info
    private String testName;
    private String testCategory;
    private String resultValue;
    private String unit;
    private String referenceRange;
    private String remarks;
    private String status;
    private String fileUrl;
    private LocalDateTime orderedAt;
}