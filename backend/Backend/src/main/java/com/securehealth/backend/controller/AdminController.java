package com.securehealth.backend.controller;

import com.securehealth.backend.dto.AdminMetricsDTO;
import com.securehealth.backend.service.AdminService;
import com.securehealth.backend.service.AppointmentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    @Autowired
    private AdminService adminService;

    @Autowired
    private AppointmentService appointmentService;

    @GetMapping("/metrics")
    public ResponseEntity<?> getDashboardMetrics(Authentication auth) {
        // Enforce strict RBAC: Only ADMIN can access metrics
        String role = auth.getAuthorities().stream().findFirst().map(GrantedAuthority::getAuthority).orElse("");
        if (!role.equals("ADMIN")) {
            return ResponseEntity.status(403).body("Forbidden: Administrator access required.");
        }

        AdminMetricsDTO metrics = adminService.getDashboardMetrics();
        return ResponseEntity.ok(metrics);
    }

    @GetMapping("/appointments/pending")
    public ResponseEntity<?> getPendingAppointments(Authentication auth) {
        // Enforce strict RBAC: Only ADMIN can view the queue
        String role = auth.getAuthorities().stream().findFirst().map(GrantedAuthority::getAuthority).orElse("");
        if (!role.equals("ADMIN")) {
            return ResponseEntity.status(403).body("Forbidden: Administrator access required.");
        }

        return ResponseEntity.ok(appointmentService.getPendingAppointments());
    }
}