package com.securehealth.backend.controller;

import com.securehealth.backend.dto.PrescriptionDTO;
import com.securehealth.backend.model.Prescription;
import com.securehealth.backend.repository.PrescriptionRepository;
import com.securehealth.backend.service.PrescriptionService;
import com.securehealth.backend.security.PatientAccessValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
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
    public ResponseEntity<?> createPrescription(@RequestBody com.securehealth.backend.dto.PrescriptionRequest request, Authentication auth) {
        // Enforce RBAC: Only Doctors can write prescriptions
        String role = auth.getAuthorities().stream().findFirst().map(GrantedAuthority::getAuthority).orElse("");
        if (!role.equals("DOCTOR")) {
            return ResponseEntity.status(403).body("Forbidden: Only doctors can write prescriptions.");
        }

        try {
            Prescription newPrescription = prescriptionService.createPrescription(request, auth.getName());
            return ResponseEntity.ok(newPrescription);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}