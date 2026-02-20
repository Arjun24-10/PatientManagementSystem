package com.securehealth.backend.repository;

import com.securehealth.backend.model.MedicalRecord;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface MedicalRecordRepository extends JpaRepository<MedicalRecord, Long> {

    // Frontend: GET /medical-records/patient/:patientId
    List<MedicalRecord> findByPatient_ProfileIdOrderByCreatedAtDesc(Long patientId);
}