package com.securehealth.backend.controller;

import com.securehealth.backend.model.VitalSign;
import com.securehealth.backend.repository.VitalSignRepository;
import com.securehealth.backend.security.PatientAccessValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/vital-signs")
public class VitalSignController {

    @Autowired private VitalSignRepository vitalSignRepository;
    @Autowired private PatientAccessValidator accessValidator;

    @GetMapping("/patient/{patientId}")
    public ResponseEntity<List<VitalSign>> getByPatient(@PathVariable Long patientId, Authentication auth) {
        accessValidator.validateAccess(patientId, auth);
        return ResponseEntity.ok(vitalSignRepository.findByPatient_ProfileIdOrderByRecordedAtDesc(patientId));
    }
}