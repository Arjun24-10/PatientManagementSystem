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
    private String email;          // WHO performed the action

    @Column(nullable = false)
    private String action;         // WHAT (e.g., LOGIN_SUCCESS, OTP_FAILED)

    private String ipAddress;      // WHERE (IP Address)

    private String userAgent;      // HOW (Browser/Device info)

    private String details;        // CONTEXT (e.g., "Account locked due to 5 failed attempts")

    @Column(nullable = false)
    private LocalDateTime timestamp = LocalDateTime.now(); // WHEN

    // Constructor for easy saving
    public AuditLog(String email, String action, String ip, String agent, String details) {
        this.email = email;
        this.action = action;
        this.ipAddress = ip;
        this.userAgent = agent;
        this.details = details;
    }
}