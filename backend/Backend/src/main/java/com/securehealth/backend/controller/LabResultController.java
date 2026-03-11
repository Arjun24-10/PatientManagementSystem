package com.securehealth.backend.controller;

import com.securehealth.backend.model.LabTest;
import com.securehealth.backend.dto.LabTestDTO;
import com.securehealth.backend.repository.LabTestRepository;
import com.securehealth.backend.security.PatientAccessValidator;
import com.securehealth.backend.service.LabTestService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/lab-results")
public class LabResultController {

    @Autowired private LabTestRepository labTestRepository;
    @Autowired private PatientAccessValidator accessValidator;
    @Autowired private LabTestService labTestService;

    @GetMapping
    @PreAuthorize("hasAnyAuthority('DOCTOR', 'ADMIN')")
    public ResponseEntity<List<LabTestDTO>> getAllLabTests() {
        return ResponseEntity.ok(labTestService.getAllLabTests());
    }

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
    @PreAuthorize("hasAnyAuthority('DOCTOR', 'ADMIN', 'LAB_TECHNICIAN')")
    public ResponseEntity<?> createLabTest(@Valid @RequestBody com.securehealth.backend.dto.LabTestRequest request, Authentication auth) {
        try {
            LabTest newLabTest = labTestService.createLabTest(request, auth.getName());
            return ResponseEntity.ok(newLabTest);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @GetMapping("/pending")
    @PreAuthorize("hasAnyAuthority('LAB_TECHNICIAN', 'ADMIN', 'DOCTOR')")
    public ResponseEntity<List<LabTestDTO>> getPendingLabTests() {
        return ResponseEntity.ok(labTestService.getPendingLabTests());
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<?> deleteLabTest(@PathVariable Long id) {
        try {
            labTestService.deleteLabTest(id);
            return ResponseEntity.ok("Lab result deleted successfully.");
        } catch (RuntimeException e) {
            return ResponseEntity.status(400).body(e.getMessage());
        }
    }
}