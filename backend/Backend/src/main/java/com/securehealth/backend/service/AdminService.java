package com.securehealth.backend.service;

import com.securehealth.backend.dto.AdminMetricsDTO;
import com.securehealth.backend.repository.AppointmentRepository;
import com.securehealth.backend.repository.LoginRepository;
import com.securehealth.backend.repository.PatientProfileRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.LocalDateTime;

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
}