package com.securehealth.backend.dto;

import lombok.Data;
import java.time.LocalTime;
import java.time.DayOfWeek;
import java.util.List;

/**
 * Data Transfer Object representing a doctor's profile information.
 * <p>
 * Includes basic details like name and contact information, as well as 
 * professional details like specialty, department, and working schedule.
 * </p>
 */
@Data
public class DoctorDTO {
    private Long id; 
    private String firstName;
    private String lastName;
    private String email; 
    private String specialty;
    private String contactNumber;
    private String department;
    private LocalTime shiftStartTime;
    private LocalTime shiftEndTime;
    private Integer slotDurationMinutes;
    private List<DayOfWeek> workingDays;
}