package com.securehealth.backend.controller;

import com.securehealth.backend.service.NurseService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * REST controller for nurse-related operations.
 * <p>
 * Provides endpoints for nurses to view their dashboard, assigned patients, tasks,
 * and manage handover notes. Access is restricted to users with NURSE authority.
 * </p>
 */
@RestController
@RequestMapping("/api/nurse")
@PreAuthorize("hasAuthority('NURSE')")
public class NurseController {

    @Autowired
    private NurseService nurseService;

    @GetMapping("/dashboard")
    public ResponseEntity<?> getDashboardOverview(Authentication authentication) {
        try {
            return ResponseEntity.ok(nurseService.getDashboardOverview(authentication.getName()));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @GetMapping("/assigned-patients")
    public ResponseEntity<?> getAssignedPatients(Authentication authentication) {
        try {
            return ResponseEntity.ok(nurseService.getAssignedPatients(authentication.getName()));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @GetMapping("/tasks")
    public ResponseEntity<?> getTasks(Authentication authentication) {
        try {
            return ResponseEntity.ok(nurseService.getTasks(authentication.getName()));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PutMapping("/tasks/{taskId}/toggle")
    public ResponseEntity<?> toggleTaskStatus(@PathVariable Long taskId, Authentication authentication) {
        try {
            return ResponseEntity.ok(nurseService.toggleTaskStatus(taskId, authentication.getName()));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @GetMapping("/handover")
    public ResponseEntity<?> getHandoverNotes(Authentication authentication) {
        try {
            return ResponseEntity.ok(nurseService.getHandoverNotes(authentication.getName()));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/handover")
    public ResponseEntity<?> saveHandoverNotes(@RequestBody Map<String, Object> payload, Authentication authentication) {
        try {
            return ResponseEntity.ok(nurseService.saveHandoverNote(payload, authentication.getName()));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}
