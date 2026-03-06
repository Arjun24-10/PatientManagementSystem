package com.securehealth.backend.dto;

import lombok.Data;
import java.time.LocalDateTime;

@Data
public class AppointmentRequest {
    private Long doctorId; // The ID of the doctor they are booking
    private LocalDateTime appointmentDate; // The exact date and time they selected
    private String reasonForVisit; // Optional notes from the patient
}