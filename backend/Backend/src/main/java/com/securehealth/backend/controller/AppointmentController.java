package com.securehealth.backend.controller;

import com.securehealth.backend.dto.AppointmentDTO;
import com.securehealth.backend.dto.AppointmentRequest;
import com.securehealth.backend.model.Appointment;
import com.securehealth.backend.repository.AppointmentRepository;
import com.securehealth.backend.security.PatientAccessValidator;
import com.securehealth.backend.service.AppointmentService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.time.LocalTime;
import java.util.List;

@RestController
@RequestMapping("/api/appointments")
public class AppointmentController {

    @Autowired private AppointmentRepository appointmentRepository;
    @Autowired private PatientAccessValidator accessValidator;
    @Autowired private AppointmentService appointmentService;

    @GetMapping("/patient/{patientId}")
    public ResponseEntity<List<AppointmentDTO>> getByPatient(@PathVariable Long patientId, Authentication auth) {
        accessValidator.validateAccess(patientId, auth);
        return ResponseEntity.ok(appointmentService.getAppointmentsByPatient(patientId));
    }

    @GetMapping("/doctor/{doctorId}")
    public ResponseEntity<List<Appointment>> getByDoctor(@PathVariable Long doctorId, Authentication auth) {
        return ResponseEntity.ok(appointmentRepository.findByDoctor_UserIdOrderByAppointmentDateAsc(doctorId));
    }

    // GET /api/appointments/doctor/{doctorId}/available-slots?date=2026-03-01
    @GetMapping("/doctor/{doctorId}/available-slots")
    public ResponseEntity<List<LocalTime>> getAvailableSlots(
            @PathVariable Long doctorId,
            @RequestParam("date") @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate date) {
        
        List<LocalTime> slots = appointmentService.getAvailableSlots(doctorId, date);
        return ResponseEntity.ok(slots);
    }

    @PostMapping
    public ResponseEntity<?> createAppointment(@RequestBody AppointmentRequest request, Authentication auth) {
        try {
            // Extract the email from the JWT token
            String email = auth.getName();
            
            Appointment newAppointment = appointmentService.createAppointment(request, email);
            
            return ResponseEntity.ok(newAppointment);
            
        } catch (RuntimeException e) {
            // If it's our double-booking error, return a 409 Conflict. Otherwise, 400 Bad Request.
            if (e.getMessage().contains("409")) {
                return ResponseEntity.status(409).body(e.getMessage());
            }
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PutMapping("/{id}/approve")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<?> approveAppointment(@PathVariable Long id) {
        try {
            Appointment approved = appointmentService.approveAppointment(id);
            return ResponseEntity.ok(approved);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PutMapping("/{id}/reject")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<?> rejectAppointment(@PathVariable Long id, @RequestBody(required = false) String reason) {
        try {
            Appointment rejected = appointmentService.rejectAppointment(id, reason);
            return ResponseEntity.ok(rejected);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
    
    @GetMapping
    @PreAuthorize("hasAnyAuthority('ADMIN', 'DOCTOR')")
    public ResponseEntity<?> getAllAppointments() {
        return ResponseEntity.ok(appointmentService.getAllAppointments());
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getById(@PathVariable Long id, Authentication auth) {
        return appointmentRepository.findById(id)
                .map(appt -> ResponseEntity.ok((Object) appt))
                .orElse(ResponseEntity.status(404).body("Appointment not found with id: " + id));
    }

    @GetMapping("/status/{status}")
    public ResponseEntity<List<Appointment>> getByStatus(@PathVariable String status) {
        return ResponseEntity.ok(appointmentRepository.findByStatus(status));
    }

    @GetMapping("/stats")
    public ResponseEntity<?> getStats() {
        java.util.Map<String, Object> stats = new java.util.HashMap<>();
        stats.put("total", appointmentRepository.count());
        stats.put("pending", appointmentRepository.countByStatus("PENDING"));
        stats.put("scheduled", appointmentRepository.countByStatus("SCHEDULED"));
        stats.put("completed", appointmentRepository.countByStatus("COMPLETED"));
        stats.put("cancelled", appointmentRepository.countByStatus("CANCELLED"));
        return ResponseEntity.ok(stats);
    }

    @PutMapping("/{id}/complete")
    @PreAuthorize("hasAuthority('DOCTOR')")
    public ResponseEntity<?> completeAppointment(@PathVariable Long id, Authentication auth) {
        try {
            return ResponseEntity.ok(appointmentService.completeAppointment(id, auth.getName()));
        } catch (RuntimeException e) {
            return ResponseEntity.status(400).body(e.getMessage());
        }
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('DOCTOR')")
    public ResponseEntity<?> updateAppointment(
            @PathVariable Long id, 
            @RequestBody com.securehealth.backend.dto.AppointmentDTO request, 
            Authentication auth) {
        try {
            return ResponseEntity.ok(appointmentService.updateAppointment(id, request, auth.getName()));
        } catch (RuntimeException e) {
            return ResponseEntity.status(400).body(e.getMessage());
        }
    }
}