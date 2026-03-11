package com.securehealth.backend.service;

import com.securehealth.backend.dto.AppointmentRequest;
import com.securehealth.backend.model.Appointment;
import com.securehealth.backend.model.DoctorProfile;
import com.securehealth.backend.model.Login;
import com.securehealth.backend.model.PatientProfile;
import com.securehealth.backend.repository.AppointmentRepository;
import com.securehealth.backend.repository.DoctorProfileRepository;
import com.securehealth.backend.repository.LoginRepository;
import com.securehealth.backend.repository.PatientProfileRepository;
import com.securehealth.backend.dto.AppointmentDTO;

import java.util.List;
import java.util.stream.Collectors;
import org.springframework.transaction.annotation.Transactional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.ArrayList;
import java.util.List;

@Service
public class AppointmentService {

    @Autowired
    private AppointmentRepository appointmentRepository;

    @Autowired
    private DoctorProfileRepository doctorProfileRepository;

    @Autowired
    private LoginRepository loginRepository;

    @Autowired
    private PatientProfileRepository patientProfileRepository;

    public List<LocalTime> getAvailableSlots(Long doctorId, LocalDate targetDate) {
        // 1. Fetch Doctor Profile (Note: doctorId is the Login ID, so we find by User)
        DoctorProfile doctor = doctorProfileRepository.findByUser_UserId(doctorId)
                .orElseThrow(() -> new RuntimeException("Doctor not found"));

        // 2. Is the doctor even working on this day of the week?
        if (doctor.getWorkingDays() == null || !doctor.getWorkingDays().contains(targetDate.getDayOfWeek())) {
            return new ArrayList<>(); // Returns empty list (No slots available)
        }

        // 3. Fetch ALREADY BOOKED appointments for this exact date
        LocalDateTime startOfDay = targetDate.atStartOfDay();
        LocalDateTime endOfDay = targetDate.atTime(LocalTime.MAX);
        List<Appointment> bookedAppointments = appointmentRepository
                .findByDoctor_UserIdAndAppointmentDateBetween(doctorId, startOfDay, endOfDay);

        // Extract just the times of the booked appointments
        List<LocalTime> bookedTimes = bookedAppointments.stream()
                .filter(apt -> apt.getStatus() != com.securehealth.backend.model.AppointmentStatus.CANCELLED) // Ignore cancelled ones
                .map(apt -> apt.getAppointmentDate().toLocalTime())
                .toList();

        // 4. Generate ALL possible slots for the day based on shift hours and slot
        // duration
        List<LocalTime> availableSlots = new ArrayList<>();
        LocalTime currentSlot = doctor.getShiftStartTime();

        while (currentSlot.isBefore(doctor.getShiftEndTime())) {
            // If this time slot is NOT in the booked times list, it is available!
            if (!bookedTimes.contains(currentSlot)) {
                availableSlots.add(currentSlot);
            }
            // Move to the next slot (e.g., add 30 minutes)
            currentSlot = currentSlot.plusMinutes(doctor.getSlotDurationMinutes());
        }

        return availableSlots;
    }

    @Transactional
    public Appointment createAppointment(AppointmentRequest request, String requesterEmail) {
        Login user = loginRepository.findByEmail(requesterEmail)
                .orElseThrow(() -> new RuntimeException("User not found"));

        PatientProfile patient = patientProfileRepository.findByUser(user)
                .orElseThrow(() -> new RuntimeException("400: Please complete your patient profile before booking."));

        Login doctor = loginRepository.findById(request.getDoctorId())
                .orElseThrow(() -> new RuntimeException("404: Doctor not found"));

        // UPDATE: Check against both CANCELLED and REJECTED statuses
        boolean isSlotTaken = appointmentRepository.existsByDoctor_UserIdAndAppointmentDateAndStatusNotIn(
                doctor.getUserId(),
                request.getAppointmentDate(),
                List.of(com.securehealth.backend.model.AppointmentStatus.CANCELLED, com.securehealth.backend.model.AppointmentStatus.REJECTED));

        if (isSlotTaken) {
            throw new RuntimeException("409 Conflict: This time slot is currently unavailable or pending review.");
        }

        Appointment appointment = new Appointment();
        appointment.setPatient(patient);
        appointment.setDoctor(doctor);
        appointment.setAppointmentDate(request.getAppointmentDate());
        appointment.setReasonForVisit(request.getReasonForVisit());

        // UPDATE: Set to PENDING instead of SCHEDULED
        appointment.setStatus(com.securehealth.backend.model.AppointmentStatus.PENDING_APPROVAL);

        return appointmentRepository.save(appointment);
    }

    /**
     * ADMIN ONLY: Approves a pending appointment request.
     */
    @Transactional
    public AppointmentDTO approveAppointment(Long appointmentId) {
        Appointment appointment = appointmentRepository.findById(appointmentId)
                .orElseThrow(() -> new RuntimeException("404: Appointment not found"));

        if (appointment.getStatus() != com.securehealth.backend.model.AppointmentStatus.PENDING_APPROVAL) {
            throw new RuntimeException("400: Only pending appointments can be approved.");
        }

        appointment.setStatus(com.securehealth.backend.model.AppointmentStatus.SCHEDULED);
        Appointment saved = appointmentRepository.save(appointment);
        return toDTO(saved);
    }

    /**
     * ADMIN ONLY: Rejects a pending appointment request, freeing up the slot.
     */
    @Transactional
    public AppointmentDTO rejectAppointment(Long appointmentId, String rejectionReason) {
        Appointment appointment = appointmentRepository.findById(appointmentId)
                .orElseThrow(() -> new RuntimeException("404: Appointment not found"));

        if (appointment.getStatus() != com.securehealth.backend.model.AppointmentStatus.PENDING_APPROVAL) {
            throw new RuntimeException("400: Only pending appointments can be rejected.");
        }

        appointment.setStatus(com.securehealth.backend.model.AppointmentStatus.REJECTED);
        Appointment saved = appointmentRepository.save(appointment);
        return toDTO(saved);
    }

    private AppointmentDTO toDTO(Appointment app) {
        AppointmentDTO dto = new AppointmentDTO();
        dto.setAppointmentId(app.getAppointmentId());
        dto.setDoctorId(app.getDoctor().getUserId());
        dto.setDoctorName(app.getDoctor().getEmail());
        dto.setPatientName(app.getPatient().getFirstName() + " " + app.getPatient().getLastName());
        dto.setAppointmentDate(app.getAppointmentDate());
        dto.setStatus(app.getStatus());
        dto.setReasonForVisit(app.getReasonForVisit());
        return dto;
    }

    @Transactional(readOnly = true)
    public List<AppointmentDTO> getPendingAppointments() {
        return appointmentRepository.findByStatus(com.securehealth.backend.model.AppointmentStatus.PENDING_APPROVAL).stream()
                .map(this::toDTO)
                .collect(Collectors.toList());
    }

    @Transactional
    public Appointment completeAppointment(Long id, String doctorEmail) {
        Appointment appointment = appointmentRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("404: Appointment not found"));

        // Verify it belongs to the doctor requesting it
        if (!appointment.getDoctor().getEmail().equals(doctorEmail)) {
             throw new RuntimeException("403: You can only complete your own appointments.");
        }

        appointment.setStatus(com.securehealth.backend.model.AppointmentStatus.COMPLETED);
        return appointmentRepository.save(appointment);
    }

    @Transactional
    public Appointment updateAppointment(Long id, AppointmentDTO request, String doctorEmail) {
        Appointment appointment = appointmentRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("404: Appointment not found"));

        // Verify it belongs to the doctor requesting it
        if (!appointment.getDoctor().getEmail().equals(doctorEmail)) {
             throw new RuntimeException("403: You can only update your own appointments.");
        }
        
        if (request.getAppointmentDate() != null) {
            appointment.setAppointmentDate(request.getAppointmentDate());
        }
        
        return appointmentRepository.save(appointment);
    }

    @Transactional
    public Appointment cancelAppointment(Long id, String requesterEmail, String role) {
        Appointment appointment = appointmentRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("404: Appointment not found"));

        if (!role.equals("ADMIN") && 
            !appointment.getDoctor().getEmail().equals(requesterEmail) && 
            !appointment.getPatient().getUser().getEmail().equals(requesterEmail)) {
             throw new RuntimeException("403: You can only cancel your own appointments.");
        }

        appointment.setStatus(com.securehealth.backend.model.AppointmentStatus.CANCELLED);
        return appointmentRepository.save(appointment);
    }

    @Transactional
    public void deleteAppointment(Long id) {
        if (!appointmentRepository.existsById(id)) {
            throw new RuntimeException("404: Appointment not found");
        }
        appointmentRepository.deleteById(id);
    }


    @Transactional(readOnly = true)
    public List<AppointmentDTO> getAppointmentsByDoctor(Long doctorId) {
        return appointmentRepository.findByDoctor_UserIdOrderByAppointmentDateAsc(doctorId).stream().map(app -> {
            AppointmentDTO dto = new AppointmentDTO();
            dto.setAppointmentId(app.getAppointmentId());
            dto.setDoctorId(app.getDoctor().getUserId());
            dto.setDoctorName(app.getDoctor().getEmail());
            dto.setPatientName(app.getPatient().getFirstName() + " " + app.getPatient().getLastName());
            dto.setAppointmentDate(app.getAppointmentDate());
            dto.setStatus(app.getStatus());
            dto.setReasonForVisit(app.getReasonForVisit());
            return dto;
        }).collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<AppointmentDTO> getAppointmentsByPatient(Long patientId) {
        return appointmentRepository.findByPatient_ProfileId(patientId).stream().map(app -> {
            AppointmentDTO dto = new AppointmentDTO();
            dto.setAppointmentId(app.getAppointmentId());
            dto.setDoctorId(app.getDoctor().getUserId());
            // This safely triggers the lazy load while the connection is open!
            dto.setDoctorName(app.getDoctor().getEmail());
            dto.setPatientName(app.getPatient().getFirstName() + " " + app.getPatient().getLastName());
            dto.setAppointmentDate(app.getAppointmentDate());
            dto.setStatus(app.getStatus());
            dto.setReasonForVisit(app.getReasonForVisit());
            return dto;
        }).collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<AppointmentDTO> getAllAppointments() {
        return appointmentRepository.findAll().stream().map(app -> {
            AppointmentDTO dto = new AppointmentDTO();
            dto.setAppointmentId(app.getAppointmentId());
            dto.setDoctorId(app.getDoctor().getUserId());

            // Safely trigger lazy loading
            dto.setDoctorName(app.getDoctor() != null ? app.getDoctor().getEmail() : "Unknown");
            dto.setPatientName(
                    app.getPatient() != null ? app.getPatient().getFirstName() + " " + app.getPatient().getLastName()
                            : "Unknown");

            dto.setAppointmentDate(app.getAppointmentDate());
            dto.setStatus(app.getStatus());
            dto.setReasonForVisit(app.getReasonForVisit());
            return dto;
        }).collect(Collectors.toList());
    }
}