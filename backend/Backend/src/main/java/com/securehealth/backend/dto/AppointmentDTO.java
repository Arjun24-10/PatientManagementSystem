package com.securehealth.backend.dto;
import lombok.Data;
import java.time.LocalDateTime;

@Data
public class AppointmentDTO {
    private Long appointmentId;
    private Long doctorId;
    private String doctorName;
    private String patientName;
    private LocalDateTime appointmentDate;
    private String status;
    private String reasonForVisit;
}