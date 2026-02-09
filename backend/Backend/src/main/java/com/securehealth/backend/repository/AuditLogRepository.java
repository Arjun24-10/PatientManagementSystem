package com.securehealth.backend.repository;

import com.securehealth.backend.model.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {
    // We will use this later for the Admin Dashboard (Task #19284)
    List<AuditLog> findByEmailOrderByTimestampDesc(String email);
}