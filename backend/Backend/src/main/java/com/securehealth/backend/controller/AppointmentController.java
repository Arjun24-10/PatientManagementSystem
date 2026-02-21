package com.securehealth.backend.controller;

import com.securehealth.backend.model.Appointment;
import com.securehealth.backend.repository.AppointmentRepository;
import com.securehealth.backend.security.PatientAccessValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/appointments")
public class AppointmentController {

    @Autowired private AppointmentRepository appointmentRepository;
    @Autowired private PatientAccessValidator accessValidator;

    @GetMapping("/patient/{patientId}")
    public ResponseEntity<List<Appointment>> getByPatient(@PathVariable Long patientId, Authentication auth) {
        accessValidator.validateAccess(patientId, auth);
        return ResponseEntity.ok(appointmentRepository.findByPatient_ProfileIdOrderByAppointmentDateDesc(patientId));
    }
}