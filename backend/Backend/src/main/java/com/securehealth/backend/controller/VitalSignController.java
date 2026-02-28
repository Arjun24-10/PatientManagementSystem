package com.securehealth.backend.controller;

import com.securehealth.backend.model.VitalSign;
import com.securehealth.backend.repository.VitalSignRepository;
import com.securehealth.backend.service.VitalSignService;
import com.securehealth.backend.security.PatientAccessValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;


import java.util.List;

@RestController
@RequestMapping("/api/vital-signs")
public class VitalSignController {

    @Autowired private VitalSignRepository vitalSignRepository;
    @Autowired private PatientAccessValidator accessValidator;
    @Autowired private VitalSignService vitalSignService;

    @GetMapping("/patient/{patientId}")
    public ResponseEntity<List<VitalSign>> getByPatient(@PathVariable Long patientId, Authentication auth) {
        accessValidator.validateAccess(patientId, auth);
        return ResponseEntity.ok(vitalSignRepository.findByPatient_ProfileIdOrderByRecordedAtDesc(patientId));
    }

    @PostMapping
    public ResponseEntity<?> createVitalSign(@RequestBody com.securehealth.backend.dto.VitalSignRequest request, Authentication auth) {
        // Allow DOCTOR or ADMIN (or NURSE if you have that role) to add vitals
        String role = auth.getAuthorities().stream().findFirst().map(GrantedAuthority::getAuthority).orElse("");
        if (!role.equals("DOCTOR") && !role.equals("ADMIN") && !role.equals("NURSE")) {
            return ResponseEntity.status(403).body("Forbidden: Insufficient privileges to add vital signs.");
        }

        try {
            VitalSign newVital = vitalSignService.createVitalSign(request, auth.getName());
            return ResponseEntity.ok(newVital);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}