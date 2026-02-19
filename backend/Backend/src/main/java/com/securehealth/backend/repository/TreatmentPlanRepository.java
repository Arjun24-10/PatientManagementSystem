package com.securehealth.backend.repository;

import com.securehealth.backend.model.Login;
import com.securehealth.backend.model.PatientProfile;
import com.securehealth.backend.model.TreatmentPlan;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface TreatmentPlanRepository extends JpaRepository<TreatmentPlan, Long> {

    // For the Patient Dashboard: "Show me my entire treatment history"
    List<TreatmentPlan> findByPatientOrderByCreatedAtDesc(PatientProfile patient);

    // For the Doctor Dashboard: "Show me all the plans I have written"
    List<TreatmentPlan> findByDoctorOrderByCreatedAtDesc(Login doctor);

    // HIPAA Check: "Get treatments for this patient, but ONLY if written by this doctor"
    List<TreatmentPlan> findByPatientAndDoctor(PatientProfile patient, Login doctor);
}