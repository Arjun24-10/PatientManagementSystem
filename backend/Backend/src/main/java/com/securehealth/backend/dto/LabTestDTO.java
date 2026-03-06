package com.securehealth.backend.dto;
import lombok.Data;
import java.time.LocalDateTime;

@Data
public class LabTestDTO {
    private Long testId;
    private String orderedByName;
    private String testName;
    private String testCategory;
    private String resultValue;
    private String unit;
    private String referenceRange;
    private String remarks;
    private String status;
    private LocalDateTime orderedAt;
}