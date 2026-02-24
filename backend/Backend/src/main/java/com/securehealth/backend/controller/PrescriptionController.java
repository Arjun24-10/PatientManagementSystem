package com.securehealth.backend.controller;

import com.securehealth.backend.model.Prescription;
import com.securehealth.backend.repository.PrescriptionRepository;
import com.securehealth.backend.security.PatientAccessValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/prescriptions")
public class PrescriptionController {

    @Autowired private PrescriptionRepository prescriptionRepository;
    @Autowired private PatientAccessValidator accessValidator;

    @GetMapping("/patient/{patientId}")
    public ResponseEntity<List<Prescription>> getByPatient(@PathVariable Long patientId, Authentication auth) {
        accessValidator.validateAccess(patientId, auth);
        return ResponseEntity.ok(prescriptionRepository.findByPatient_ProfileIdOrderByIssuedAtDesc(patientId));
    }
}