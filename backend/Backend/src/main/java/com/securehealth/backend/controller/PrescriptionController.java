package com.securehealth.backend.controller;

import com.securehealth.backend.dto.PrescriptionDTO;
import com.securehealth.backend.model.Prescription;
import com.securehealth.backend.repository.PrescriptionRepository;
import com.securehealth.backend.service.PrescriptionService;
import com.securehealth.backend.security.PatientAccessValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/prescriptions")
public class PrescriptionController {

    @Autowired private PrescriptionRepository prescriptionRepository;
    @Autowired private PatientAccessValidator accessValidator;
    @Autowired private PrescriptionService prescriptionService;

    @GetMapping("/patient/{patientId}")
    public ResponseEntity<List<PrescriptionDTO>> getByPatient(@PathVariable Long patientId, Authentication auth) {
        accessValidator.validateAccess(patientId, auth);
        return ResponseEntity.ok(prescriptionService.getPrescriptionsByPatient(patientId));
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getById(@PathVariable Long id, Authentication auth) {
        return prescriptionRepository.findById(id)
                .map(rx -> ResponseEntity.ok((Object) rx))
                .orElse(ResponseEntity.status(404).body("Prescription not found with id: " + id));
    }

    @PostMapping
    @PreAuthorize("hasAuthority('DOCTOR')")
    public ResponseEntity<?> createPrescription(@Valid @RequestBody com.securehealth.backend.dto.PrescriptionRequest request, Authentication auth) {
        try {
            Prescription newPrescription = prescriptionService.createPrescription(request, auth.getName());
            return ResponseEntity.ok(newPrescription);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @GetMapping("/patient/{patientId}/active")
    public ResponseEntity<List<PrescriptionDTO>> getActiveByPatient(@PathVariable Long patientId, Authentication auth) {
        accessValidator.validateAccess(patientId, auth);
        return ResponseEntity.ok(prescriptionService.getActivePrescriptionsByPatient(patientId));
    }

    @PutMapping("/{id}/refill")
    @PreAuthorize("hasAuthority('DOCTOR')")
    public ResponseEntity<?> refillPrescription(@PathVariable Long id, Authentication auth) {
        try {
            return ResponseEntity.ok(prescriptionService.refillPrescription(id, auth.getName()));
        } catch (RuntimeException e) {
            return ResponseEntity.status(400).body(e.getMessage());
        }
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<?> deletePrescription(@PathVariable Long id, Authentication auth) {
        try {
            prescriptionService.deletePrescription(id, auth.getName());
            return ResponseEntity.ok("Prescription deleted successfully.");
        } catch (RuntimeException e) {
            return ResponseEntity.status(400).body(e.getMessage());
        }
    }
}