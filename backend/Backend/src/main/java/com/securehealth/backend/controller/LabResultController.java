package com.securehealth.backend.controller;

import com.securehealth.backend.model.LabTest;
import com.securehealth.backend.repository.LabTestRepository;
import com.securehealth.backend.security.PatientAccessValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/lab-results")
public class LabResultController {

    @Autowired private LabTestRepository labTestRepository;
    @Autowired private PatientAccessValidator accessValidator;

    @GetMapping("/patient/{patientId}")
    public ResponseEntity<List<LabTest>> getByPatient(@PathVariable Long patientId, Authentication auth) {
        accessValidator.validateAccess(patientId, auth);
        return ResponseEntity.ok(labTestRepository.findByPatient_ProfileIdOrderByOrderedAtDesc(patientId));
    }
}