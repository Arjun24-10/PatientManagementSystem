package com.securehealth.backend.dto;
import lombok.Data;
import java.time.LocalDateTime;
import com.securehealth.backend.model.AppointmentStatus;

@Data
public class AppointmentDTO {
    private Long appointmentId;
    private Long doctorId;
    private String doctorName;
    private String patientName;
    private LocalDateTime appointmentDate;
    private AppointmentStatus status;
    private String reasonForVisit;
}