package com.securehealth.backend.service;

import com.securehealth.backend.dto.AdminMetricsDTO;
import com.securehealth.backend.model.AppointmentStatus;
import com.securehealth.backend.repository.AppointmentRepository;
import com.securehealth.backend.repository.LoginRepository;
import com.securehealth.backend.repository.PatientProfileRepository;
import com.securehealth.backend.dto.StaffDTO;
import com.securehealth.backend.model.Login;
import com.securehealth.backend.model.Role;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.securehealth.backend.dto.PatientDirectoryDTO;
import java.util.List;
import java.util.stream.Collectors;
import java.time.LocalDate;
import java.time.LocalDateTime;

/**
 * Service for administrative and management operations.
 * <p>
 * Provides high-level system metrics for the dashboard, staff account management 
 * (roles and removal), and access to the full patient directory.
 * </p>
 */
@Service
public class AdminService {

    @Autowired private PatientProfileRepository patientProfileRepository;
    @Autowired private LoginRepository loginRepository;
    @Autowired private AppointmentRepository appointmentRepository;

    /**
     * Retrieves aggregated system metrics for the admin dashboard.
     *
     * @return an {@link AdminMetricsDTO} containing counts of patients, doctors, 
     *         pending approvals, and today's appointments
     */
    @Transactional(readOnly = true)
    public AdminMetricsDTO getDashboardMetrics() {
        AdminMetricsDTO metrics = new AdminMetricsDTO();

        // 1. Total Patients
        metrics.setTotalPatients(patientProfileRepository.count());

        // 2. Total Doctors
        metrics.setTotalDoctors(loginRepository.countByRole(Role.DOCTOR));

        // 3. Pending Approvals
        metrics.setPendingApprovals(appointmentRepository.countByStatus(AppointmentStatus.PENDING_APPROVAL));

        // 4. Today's Appointments
        LocalDateTime startOfDay = LocalDate.now().atStartOfDay();
        LocalDateTime endOfDay = startOfDay.plusDays(1);
        metrics.setTodaysAppointments(appointmentRepository.countTodaysAppointments(startOfDay, endOfDay));

        return metrics;
    }

    /**
     * Retrieves a list of all non-patient staff members.
     *
     * @return a list of {@link StaffDTO} objects representing system staff
     */
    @Transactional(readOnly = true)
    public List<StaffDTO> getAllStaff() {
        // Pass the Enum to the repository, not the string "PATIENT"
        return loginRepository.findByRoleNot(Role.PATIENT).stream().map(user -> {
            StaffDTO dto = new StaffDTO();
            dto.setUserId(user.getUserId()); 
            dto.setEmail(user.getEmail());
            // Fix Line 54: Convert Enum to String for the DTO
            dto.setRole(user.getRole().name()); 
            return dto;
        }).collect(Collectors.toList());
    }

    /**
     * Updates the role of a staff member.
     *
     * @param userId the ID of the user to update
     * @param newRole the new role to assign
     * @return the updated {@link StaffDTO}
     * @throws IllegalArgumentException if the user is not found or is a patient
     */
    @Transactional
    public StaffDTO updateStaffRole(Long userId, String newRole) {
        Login user = loginRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("Staff member not found."));

        // Compare using the Enum
        if (user.getRole() == Role.PATIENT) {
            throw new IllegalArgumentException("Cannot modify patient roles through the staff management portal.");
        }

        // Fix Line 102: Convert the incoming String into your strict Role Enum
        user.setRole(Role.valueOf(newRole.toUpperCase()));
        loginRepository.save(user);

        StaffDTO dto = new StaffDTO();
        dto.setUserId(user.getUserId());
        dto.setEmail(user.getEmail());
        // Fix Line 109: Convert Enum to String for the response DTO
        dto.setRole(user.getRole().name()); 
        return dto;
    }

    /**
     * Permanently removes a staff member from the system.
     *
     * @param userId the ID of the user to remove
     * @throws IllegalArgumentException if the staff member is not found
     */
    @Transactional
    public void removeStaffMember(Long userId) {
        // Check if the user exists before trying to delete
        if (!loginRepository.existsById(userId)) {
            throw new IllegalArgumentException("Staff member not found.");
        }
        loginRepository.deleteById(userId);
    }

    /**
     * Retrieves a directory of all registered patients.
     *
     * @return a list of {@link PatientDirectoryDTO} objects
     */
    @Transactional(readOnly = true)
    public List<PatientDirectoryDTO> getAllPatients() {
        return patientProfileRepository.findAll().stream().map(patient -> {
            PatientDirectoryDTO dto = new PatientDirectoryDTO();
            dto.setProfileId(patient.getProfileId());
            dto.setFirstName(patient.getFirstName());
            dto.setLastName(patient.getLastName());
            dto.setContactNumber(patient.getContactNumber());
            dto.setDateOfBirth(patient.getDateOfBirth());
            
            // Safely grab the email from the linked Login entity (if they have an account)
            if (patient.getUser() != null) {
                dto.setUserId(patient.getUser().getUserId());
                dto.setEmail(patient.getUser().getEmail());
            } else {
                dto.setEmail("No registered account");
            }
            
            return dto;
        }).collect(Collectors.toList());
    }
}