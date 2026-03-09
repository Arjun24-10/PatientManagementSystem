package com.securehealth.backend.dto;

import lombok.Data;

@Data
public class AdminMetricsDTO {
    private long totalPatients;
    private long totalDoctors;
    private long todaysAppointments;
    private long pendingApprovals;
}