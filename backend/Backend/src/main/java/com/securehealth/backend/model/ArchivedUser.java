package com.securehealth.backend.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Stores a snapshot of a user account that has been archived due to inactivity.
 * The original Login account is flagged as archived but not deleted,
 * allowing for future restoration by an admin.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "archived_users")
public class ArchivedUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Reference to the original user's Login ID
    @Column(nullable = false)
    private Long originalUserId;

    @Column(nullable = false)
    private String email;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role;

    // When the user was last active
    private LocalDateTime lastActiveAt;

    // When the archival happened
    @Column(updatable = false)
    private LocalDateTime archivedAt = LocalDateTime.now();

    // Reason for archival
    @Column(columnDefinition = "TEXT")
    private String reason;
}
