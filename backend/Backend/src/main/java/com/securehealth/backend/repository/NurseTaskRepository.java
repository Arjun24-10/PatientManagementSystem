package com.securehealth.backend.repository;

import com.securehealth.backend.model.NurseTask;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface NurseTaskRepository extends JpaRepository<NurseTask, Long> {
    List<NurseTask> findByAssignedNurse_UserIdOrderByDueTimeAsc(Long nurseId);
    long countByAssignedNurse_UserIdAndCompletedFalse(Long nurseId);
    long countByAssignedNurse_UserIdAndCompletedFalseAndDueTimeBefore(Long nurseId, LocalDateTime time);
    long countByAssignedNurse_UserIdAndCompletedFalseAndPriority(Long nurseId, String priority);
}
