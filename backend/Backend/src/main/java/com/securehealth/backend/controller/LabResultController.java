package com.securehealth.backend.controller;

import com.securehealth.backend.model.LabTest;
import com.securehealth.backend.dto.LabTestDTO;
import com.securehealth.backend.repository.LabTestRepository;
import com.securehealth.backend.security.PatientAccessValidator;
import com.securehealth.backend.service.LabTestService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/lab-results")
public class LabResultController {

    @Autowired private LabTestRepository labTestRepository;
    @Autowired private PatientAccessValidator accessValidator;
    @Autowired private LabTestService labTestService;

    @GetMapping("/patient/{patientId}")
    public ResponseEntity<List<LabTestDTO>> getByPatient(@PathVariable Long patientId, Authentication auth) {
        accessValidator.validateAccess(patientId, auth);
        return ResponseEntity.ok(labTestService.getLabTestsByPatient(patientId));
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getById(@PathVariable Long id, Authentication auth) {
        return labTestRepository.findById(id)
                .map(test -> ResponseEntity.ok((Object) test))
                .orElse(ResponseEntity.status(404).body("Lab result not found with id: " + id));
    }

    

    @PostMapping
    public ResponseEntity<?> createLabTest(@RequestBody com.securehealth.backend.dto.LabTestRequest request, Authentication auth) {
        // Allow DOCTOR or ADMIN to add lab results
        String role = auth.getAuthorities().stream().findFirst().map(GrantedAuthority::getAuthority).orElse("");
        if (!role.equals("DOCTOR") && !role.equals("ADMIN") && !role.equals("LAB_TECHNICIAN")) {
            return ResponseEntity.status(403).body("Forbidden: Insufficient privileges to add lab results.");
        }

        try {
            LabTest newLabTest = labTestService.createLabTest(request, auth.getName());
            return ResponseEntity.ok(newLabTest);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}