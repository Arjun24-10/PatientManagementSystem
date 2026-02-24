package com.securehealth.backend.controller;

import com.securehealth.backend.dto.PatientDTO;
import com.securehealth.backend.service.PatientService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/patients")
public class PatientController {

    @Autowired
    private PatientService patientService;

    // Helper to extract email from security context
    private String getCurrentEmail(Authentication auth) {
        return auth.getName();
    }

    // Helper to extract role from security context
    private String getCurrentRole(Authentication auth) {
        return auth.getAuthorities().stream()
                .findFirst()
                .map(GrantedAuthority::getAuthority)
                .orElse("UNKNOWN");
    }

    @GetMapping
    public ResponseEntity<List<PatientDTO>> getAllPatients(Authentication auth) {
        return ResponseEntity.ok(patientService.getAllPatients(getCurrentRole(auth)));
    }

    @GetMapping("/me")
    public ResponseEntity<PatientDTO> getMyProfile(Authentication auth) {
        return ResponseEntity.ok(patientService.getPatientByEmail(getCurrentEmail(auth)));
    }

    @GetMapping("/{id}")
    public ResponseEntity<PatientDTO> getPatientById(@PathVariable Long id, Authentication auth) {
        return ResponseEntity.ok(patientService.getPatientById(id, getCurrentEmail(auth), getCurrentRole(auth)));
    }

    @PostMapping
    public ResponseEntity<PatientDTO> createPatient(@RequestBody PatientDTO patientDTO, Authentication auth) {
        return ResponseEntity.ok(patientService.createPatientProfile(patientDTO, getCurrentEmail(auth)));
    }

    @PutMapping("/{id}")
    public ResponseEntity<PatientDTO> updatePatient(@PathVariable Long id, @RequestBody PatientDTO patientDTO, Authentication auth) {
        return ResponseEntity.ok(patientService.updatePatientProfile(id, patientDTO, getCurrentEmail(auth), getCurrentRole(auth)));
    }

    // Optional: Add DELETE if required by hospital policy, though typically records are deactivated, not deleted.
}