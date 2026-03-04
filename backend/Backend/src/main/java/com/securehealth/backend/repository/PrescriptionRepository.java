package com.securehealth.backend.repository;

import com.securehealth.backend.model.Prescription;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface PrescriptionRepository extends JpaRepository<Prescription, Long> {

    // Frontend: GET /prescriptions/patient/:patientId
    List<Prescription> findByPatient_ProfileIdOrderByIssuedAtDesc(Long patientId);
    
    // Optional but helpful: Find active prescriptions
    List<Prescription> findByPatient_ProfileIdAndStatus(Long patientId, String status);

    // Make sure java.util.List is imported
    List<Prescription> findByPatient_ProfileId(Long patientId);
}