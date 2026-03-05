package com.securehealth.backend.service;

import com.securehealth.backend.dto.AdminMetricsDTO;
import com.securehealth.backend.repository.AppointmentRepository;
import com.securehealth.backend.repository.LoginRepository;
import com.securehealth.backend.repository.PatientProfileRepository;
import com.securehealth.backend.dto.StaffDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.LocalDateTime;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class AdminService {

    @Autowired private PatientProfileRepository patientProfileRepository;
    @Autowired private LoginRepository loginRepository;
    @Autowired private AppointmentRepository appointmentRepository;

    @Transactional(readOnly = true)
    public AdminMetricsDTO getDashboardMetrics() {
        AdminMetricsDTO metrics = new AdminMetricsDTO();

        // 1. Total Patients
        metrics.setTotalPatients(patientProfileRepository.count());

        // 2. Total Doctors
        metrics.setTotalDoctors(loginRepository.countByRole("DOCTOR"));

        // 3. Pending Approvals
        metrics.setPendingApprovals(appointmentRepository.countByStatus("PENDING_APPROVAL"));

        // 4. Today's Appointments
        LocalDateTime startOfDay = LocalDate.now().atStartOfDay();
        LocalDateTime endOfDay = startOfDay.plusDays(1);
        metrics.setTodaysAppointments(appointmentRepository.countTodaysAppointments(startOfDay, endOfDay));

        return metrics;
    }

    @Transactional(readOnly = true)
    public List<StaffDTO> getAllStaff() {
        // Fetch everyone who is NOT a "PATIENT"
        return loginRepository.findByRoleNot("PATIENT").stream().map(user -> {
            StaffDTO dto = new StaffDTO();
            dto.setUserId(user.getUserId()); // Make sure this matches your Login entity's ID field name
            dto.setEmail(user.getEmail());
            dto.setRole(user.getRole());
            return dto;
        }).collect(Collectors.toList());
    }

    @Transactional
    public void removeStaffMember(Long userId) {
        // Check if the user exists before trying to delete
        if (!loginRepository.existsById(userId)) {
            throw new IllegalArgumentException("Staff member not found.");
        }
        loginRepository.deleteById(userId);
    }
}