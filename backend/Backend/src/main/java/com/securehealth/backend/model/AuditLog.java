package com.securehealth.backend.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;

@Entity
@Data
@NoArgsConstructor
@Table(name = "audit_logs")
public class AuditLog {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String email;          // Identity (Task #19281)

    @Column(nullable = false)
    private String action;         // e.g. "LOGIN_SUCCESS", "OTP_SENT", "LOGOUT"

    private String ipAddress;      // Metadata (Task #19282)

    private String userAgent;      // Device Metadata (Task #19282)

    private String details;        // e.g. "Failed: Invalid Password" or "OTP Required"

    @Column(nullable = false)
    private LocalDateTime timestamp = LocalDateTime.now(); // Timestamp (Task #19281)

    public AuditLog(String email, String action, String ip, String agent, String details) {
        this.email = email;
        this.action = action;
        this.ipAddress = ip;
        this.userAgent = agent;
        this.details = details;
    }
}