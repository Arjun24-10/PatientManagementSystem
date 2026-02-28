package com.securehealth.backend.controller;

import com.securehealth.backend.dto.DoctorDTO;
import com.securehealth.backend.service.DoctorService;
import com.securehealth.backend.service.PatientService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/doctors")
public class DoctorController {

    @Autowired
    private DoctorService doctorService;

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
    public ResponseEntity<List<DoctorDTO>> getAllDoctors() {
        return ResponseEntity.ok(doctorService.getAllDoctors());
    }

    @GetMapping("/{id}")
    public ResponseEntity<DoctorDTO> getDoctorById(@PathVariable Long id) {
        return ResponseEntity.ok(doctorService.getDoctorById(id));
    }

    @GetMapping("/specialty/{specialty}")
    public ResponseEntity<List<DoctorDTO>> getDoctorsBySpecialty(@PathVariable String specialty) {
        return ResponseEntity.ok(doctorService.getDoctorsBySpecialty(specialty));
    }

    @PutMapping("/{id}")
    public ResponseEntity<DoctorDTO> updateDoctorProfile(
            @PathVariable Long id, 
            @RequestBody DoctorDTO doctorDTO, 
            Authentication auth) {
        
        return ResponseEntity.ok(doctorService.updateDoctorProfile(
                id, 
                doctorDTO, 
                getCurrentEmail(auth), 
                getCurrentRole(auth)
        ));
    }

    @GetMapping("/{doctorId}/patients")
    public ResponseEntity<List<com.securehealth.backend.dto.PatientDTO>> getPatientsByDoctor(
            @PathVariable Long doctorId, 
            Authentication auth) {
        
        return ResponseEntity.ok(patientService.getPatientsByDoctor(
                doctorId, 
                getCurrentEmail(auth), 
                getCurrentRole(auth)
        ));
    }
}