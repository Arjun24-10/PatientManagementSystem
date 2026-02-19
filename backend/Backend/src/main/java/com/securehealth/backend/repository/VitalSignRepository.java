package com.securehealth.backend.repository;

import com.securehealth.backend.model.Login;
import com.securehealth.backend.model.PatientProfile;
import com.securehealth.backend.model.VitalSign;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface VitalSignRepository extends JpaRepository<VitalSign, Long> {

    // Fetches a chronological timeline of a patient's vitals (essential for charts/graphs)
    List<VitalSign> findByPatientOrderByRecordedAtDesc(PatientProfile patient);

    // Audit trail: "Show me all vitals recorded by this specific nurse"
    List<VitalSign> findByNurseOrderByRecordedAtDesc(Login nurse);
}