package com.securehealth.backend.repository;

import com.securehealth.backend.model.Login;
import com.securehealth.backend.model.PatientProfile;
import com.securehealth.backend.model.LabTest;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface LabTestRepository extends JpaRepository<LabTest, Long> {

    // For the Patient Dashboard: "Show me my lab results"
    List<LabTest> findByPatientOrderByOrderedAtDesc(PatientProfile patient);

    // For the Lab Tech Dashboard: "Show me all tests that need to be processed"
    List<LabTest> findByStatusOrderByOrderedAtAsc(String status); // Will search for "PENDING"

    // For the Doctor Dashboard: "Show me the status of tests I ordered"
    List<LabTest> findByOrderedByOrderByOrderedAtDesc(Login doctor);

    // Frontend: GET /lab-results/patient/:patientId
    List<LabTest> findByPatient_ProfileIdOrderByOrderedAtDesc(Long patientId);

    List<LabTest> findByPatient_ProfileId(Long patientId);
}