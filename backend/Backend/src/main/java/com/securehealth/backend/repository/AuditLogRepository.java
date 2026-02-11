package com.securehealth.backend.repository;

import com.securehealth.backend.model.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {
    
    // This will be used later for the Admin Dashboard (User Story 1.4)
    // "Show me the last 10 logs for manas@example.com"
    List<AuditLog> findByEmailOrderByTimestampDesc(String email);
}