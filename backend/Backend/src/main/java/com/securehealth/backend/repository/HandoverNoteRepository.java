package com.securehealth.backend.repository;

import com.securehealth.backend.model.HandoverNote;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface HandoverNoteRepository extends JpaRepository<HandoverNote, Long> {
    List<HandoverNote> findByAuthor_UserIdOrderByTimestampDesc(Long authorId);
    List<HandoverNote> findByShiftDirectionOrderByTimestampDesc(String shiftDirection);
}
