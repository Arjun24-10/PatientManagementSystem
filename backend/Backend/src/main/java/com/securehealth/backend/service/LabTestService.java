package com.securehealth.backend.service;

import com.securehealth.backend.dto.LabTestRequest;
import com.securehealth.backend.model.Login;
import com.securehealth.backend.model.PatientProfile;
import com.securehealth.backend.model.LabTest;
import com.securehealth.backend.repository.LoginRepository;
import com.securehealth.backend.repository.PatientProfileRepository;
import com.securehealth.backend.repository.LabTestRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class LabTestService {

    @Autowired private LabTestRepository labTestRepository;
    @Autowired private LoginRepository loginRepository;
    @Autowired private PatientProfileRepository patientProfileRepository;

    @Transactional
    public LabTest createLabTest(LabTestRequest request, String staffEmail) {
        Login staff = loginRepository.findByEmail(staffEmail)
                .orElseThrow(() -> new RuntimeException("Staff member not found"));

        PatientProfile patient = patientProfileRepository.findById(request.getPatientId())
                .orElseThrow(() -> new RuntimeException("404: Patient not found"));

        LabTest labTest = new LabTest();
        labTest.setPatient(patient);
        // labTest.setOrderedBy(staff); // Optional: if your entity tracks who ordered it
        
        labTest.setTestName(request.getTestName());
        labTest.setTestCategory(request.getTestCategory());
        labTest.setResultValue(request.getResultValue());
        labTest.setUnit(request.getUnit());
        labTest.setReferenceRange(request.getReferenceRange());
        labTest.setRemarks(request.getRemarks());

        return labTestRepository.save(labTest);
    }
}