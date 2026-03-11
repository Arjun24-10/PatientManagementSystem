package com.securehealth.backend.model;

/**
 * Enumeration of possible appointment statuses.
 */
public enum AppointmentStatus {
    PENDING_APPROVAL,
    SCHEDULED,
    COMPLETED,
    CANCELLED,
    NO_SHOW,
    REJECTED
}
