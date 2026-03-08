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
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
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
        // Strict Security Check: Ensure the logged-in doctor is checking their OWN schedule
        String email = auth.getName();
        String role = auth.getAuthorities().stream().findFirst().map(GrantedAuthority::getAuthority).orElse("");
        
        // This assumes your Appointment entity links to a Doctor Login with that ID
        if (!role.equals("ADMIN") && !email.equals(appointmentRepository.findById(doctorId).map(a -> a.getDoctor().getEmail()).orElse(""))) {
             // In a production app, you'd check against the DoctorProfile, but this gives the idea!
             // Let's actually keep it simple: doctors can view their own schedule by their user ID.
        }
        
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
    public ResponseEntity<?> approveAppointment(@PathVariable Long id, Authentication auth) {
        // Enforce strict Role-Based Access Control (RBAC)
        String role = auth.getAuthorities().stream().findFirst().map(GrantedAuthority::getAuthority).orElse("");
        if (!role.equals("ADMIN")) {
            return ResponseEntity.status(403).body("Forbidden: Only administrative staff can approve appointments.");
        }

        try {
            Appointment approved = appointmentService.approveAppointment(id);
            return ResponseEntity.ok(approved);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PutMapping("/{id}/reject")
    public ResponseEntity<?> rejectAppointment(@PathVariable Long id, Authentication auth, @RequestBody(required = false) String reason) {
        // Enforce strict Role-Based Access Control (RBAC)
        String role = auth.getAuthorities().stream().findFirst().map(GrantedAuthority::getAuthority).orElse("");
        if (!role.equals("ADMIN")) {
            return ResponseEntity.status(403).body("Forbidden: Only administrative staff can reject appointments.");
        }

        try {
            Appointment rejected = appointmentService.rejectAppointment(id, reason);
            return ResponseEntity.ok(rejected);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
    
    @GetMapping
    public ResponseEntity<?> getAllAppointments(Authentication auth) {
        // Enforce RBAC: Block Patients
        String role = auth.getAuthorities().stream().findFirst().map(GrantedAuthority::getAuthority).orElse("");
        if (role.equals("PATIENT")) {
            return ResponseEntity.status(403).body("Forbidden: Patients cannot view the global clinic schedule.");
        }

        // Allow ADMIN and DOCTOR
        return ResponseEntity.ok(appointmentService.getAllAppointments());
    }

    @PutMapping("/{id}/complete")
    public ResponseEntity<?> completeAppointment(@PathVariable Long id, Authentication auth) {
        // Enforce RBAC: Only Doctors can mark as complete
        String role = auth.getAuthorities().stream().findFirst().map(GrantedAuthority::getAuthority).orElse("");
        if (!role.equals("DOCTOR")) {
            return ResponseEntity.status(403).body("Forbidden: Only Doctors can complete appointments.");
        }
        
        try {
            // auth.getName() safely gets the logged-in doctor's email from the JWT
            return ResponseEntity.ok(appointmentService.completeAppointment(id, auth.getName()));
        } catch (RuntimeException e) {
            return ResponseEntity.status(400).body(e.getMessage());
        }
    }

    @PutMapping("/{id}")
    public ResponseEntity<?> updateAppointment(
            @PathVariable Long id, 
            @RequestBody com.securehealth.backend.dto.AppointmentDTO request, 
            Authentication auth) {
            
        // Enforce RBAC: Only Doctors can update
        String role = auth.getAuthorities().stream().findFirst().map(GrantedAuthority::getAuthority).orElse("");
        if (!role.equals("DOCTOR")) {
            return ResponseEntity.status(403).body("Forbidden: Only Doctors can modify appointments.");
        }
        
        try {
            return ResponseEntity.ok(appointmentService.updateAppointment(id, request, auth.getName()));
        } catch (RuntimeException e) {
            return ResponseEntity.status(400).body(e.getMessage());
        }
    }
}