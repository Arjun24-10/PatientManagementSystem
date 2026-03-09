package com.securehealth.backend.controller;

import com.securehealth.backend.model.MedicalRecord;
import com.securehealth.backend.dto.MedicalRecordDTO;
import com.securehealth.backend.repository.MedicalRecordRepository;
import com.securehealth.backend.service.MedicalRecordService;
import com.securehealth.backend.security.PatientAccessValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/medical-records")
public class MedicalRecordController {

    @Autowired private MedicalRecordRepository medicalRecordRepository;
    @Autowired private PatientAccessValidator accessValidator;
    @Autowired private MedicalRecordService medicalRecordService;

    @GetMapping("/patient/{patientId}")
    public ResponseEntity<List<MedicalRecordDTO>> getByPatient(@PathVariable Long patientId, Authentication auth) {
        accessValidator.validateAccess(patientId, auth);
        return ResponseEntity.ok(medicalRecordService.getMedicalRecordsByPatient(patientId));
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getById(@PathVariable Long id, Authentication auth) {
        return medicalRecordRepository.findById(id)
                .map(record -> ResponseEntity.ok((Object) record))
                .orElse(ResponseEntity.status(404).body("Medical record not found with id: " + id));
    }

    @PostMapping
    @PreAuthorize("hasAuthority('DOCTOR')")
    public ResponseEntity<?> createMedicalRecord(@RequestBody com.securehealth.backend.dto.MedicalRecordRequest request, Authentication auth) {
        try {
            MedicalRecord newRecord = medicalRecordService.createMedicalRecord(request, auth.getName());
            return ResponseEntity.ok(newRecord);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}