package com.securehealth.backend.controller;

import com.securehealth.backend.model.MedicalRecord;
import com.securehealth.backend.repository.MedicalRecordRepository;
import com.securehealth.backend.security.PatientAccessValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/medical-records")
public class MedicalRecordController {

    @Autowired private MedicalRecordRepository medicalRecordRepository;
    @Autowired private PatientAccessValidator accessValidator;

    @GetMapping("/patient/{patientId}")
    public ResponseEntity<List<MedicalRecord>> getByPatient(@PathVariable Long patientId, Authentication auth) {
        accessValidator.validateAccess(patientId, auth);
        return ResponseEntity.ok(medicalRecordRepository.findByPatient_ProfileIdOrderByCreatedAtDesc(patientId));
    }
}