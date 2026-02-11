package com.securehealth.backend.controller;

import com.securehealth.backend.model.AuditLog;
import com.securehealth.backend.repository.AuditLogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/admin/audit-logs")
public class AuditLogController {

    @Autowired
    private AuditLogRepository auditLogRepository;

    // 1. Get ALL Logs (For the Main Audit Table)
    @GetMapping
    @PreAuthorize("hasAuthority('ADMIN')") // <--- CRITICAL SECURITY CHECK
    public ResponseEntity<List<AuditLog>> getAllLogs() {
        // In a real app, you would use Pagination (PageRequest) here
        // forcing a limit to prevent crashing with 1 million logs.
        // For now, fetching all is fine for dev.
        return ResponseEntity.ok(auditLogRepository.findAll());
    }

    // 2. Get Logs for a Specific User (For detailed investigation)
    @GetMapping("/{email}")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<List<AuditLog>> getUserLogs(@PathVariable String email) {
        return ResponseEntity.ok(auditLogRepository.findByEmailOrderByTimestampDesc(email));
    }
}