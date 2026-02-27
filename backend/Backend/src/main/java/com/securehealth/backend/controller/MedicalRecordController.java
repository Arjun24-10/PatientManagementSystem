package com.securehealth.backend.controller;

import com.securehealth.backend.model.MedicalRecord;
import com.securehealth.backend.repository.MedicalRecordRepository;
import com.securehealth.backend.service.MedicalRecordService;
import com.securehealth.backend.security.PatientAccessValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/medical-records")
public class MedicalRecordController {

    @Autowired private MedicalRecordRepository medicalRecordRepository;
    @Autowired private PatientAccessValidator accessValidator;
    @Autowired private MedicalRecordService medicalRecordService;

    @GetMapping("/patient/{patientId}")
    public ResponseEntity<List<MedicalRecord>> getByPatient(@PathVariable Long patientId, Authentication auth) {
        accessValidator.validateAccess(patientId, auth);
        return ResponseEntity.ok(medicalRecordRepository.findByPatient_ProfileIdOrderByCreatedAtDesc(patientId));
    }

    @PostMapping
    public ResponseEntity<?> createMedicalRecord(@RequestBody com.securehealth.backend.dto.MedicalRecordRequest request, Authentication auth) {
        // Enforce RBAC: Only Doctors can create medical records
        String role = auth.getAuthorities().stream().findFirst().map(GrantedAuthority::getAuthority).orElse("");
        if (!role.equals("DOCTOR")) {
            return ResponseEntity.status(403).body("Forbidden: Only doctors can create medical records.");
        }

        try {
            MedicalRecord newRecord = medicalRecordService.createMedicalRecord(request, auth.getName());
            return ResponseEntity.ok(newRecord);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}