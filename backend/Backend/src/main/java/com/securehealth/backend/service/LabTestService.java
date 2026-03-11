package com.securehealth.backend.service;

import com.securehealth.backend.dto.LabTestDTO;
import com.securehealth.backend.dto.LabTestRequest;
import com.securehealth.backend.model.Login;
import com.securehealth.backend.model.PatientProfile;
import com.securehealth.backend.model.LabTest;
import com.securehealth.backend.repository.LoginRepository;
import com.securehealth.backend.repository.PatientProfileRepository;
import com.securehealth.backend.repository.LabTestRepository;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Service for clinical lab test ordering and patient-facing lookups.
 * <p>
 * Allows doctors to order new tests and patients to retrieve their existing 
 * test results and order history.
 * </p>
 */
@Service
public class LabTestService {

    @Autowired private LabTestRepository labTestRepository;
    @Autowired private LoginRepository loginRepository;
    @Autowired private PatientProfileRepository patientProfileRepository;

    /**
     * Creates a new lab test order for a patient.
     *
     * @param request the {@link LabTestRequest} details
     * @param staffEmail the email of the healthcare professional ordering the test
     * @return the saved {@link LabTest} entity
     */
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
    /**
     * Retrieves all lab tests associated with a specific patient.
     *
     * @param patientId the ID of the patient
     * @return a list of {@link LabTestDTO} objects
     */
    @Transactional(readOnly = true)
    public List<LabTestDTO> getLabTestsByPatient(Long patientId) {
        return labTestRepository.findByPatient_ProfileId(patientId).stream().map(lt -> {
            LabTestDTO dto = new LabTestDTO();
            dto.setTestId(lt.getTestId());
            
            // Safely trigger the lazy load
            dto.setOrderedByName(lt.getOrderedBy() != null ? lt.getOrderedBy().getEmail() : "Unknown Staff");
            
            dto.setTestName(lt.getTestName());
            dto.setTestCategory(lt.getTestCategory());
            dto.setResultValue(lt.getResultValue());
            dto.setUnit(lt.getUnit());
            dto.setReferenceRange(lt.getReferenceRange());
            dto.setRemarks(lt.getRemarks());
            dto.setStatus(lt.getStatus());
            dto.setOrderedAt(lt.getOrderedAt());
            return dto;
        }).collect(Collectors.toList());
    }

    /**
     * Retrieves all lab test orders currently in "PENDING" status.
     *
     * @return a list of {@link LabTestDTO} objects
     */
    @Transactional(readOnly = true)
    public List<LabTestDTO> getPendingLabTests() {
        return labTestRepository.findByStatusOrderByOrderedAtAsc("PENDING").stream().map(lt -> {
            LabTestDTO dto = new LabTestDTO();
            dto.setTestId(lt.getTestId());
            dto.setOrderedByName(lt.getOrderedBy() != null ? lt.getOrderedBy().getEmail() : "Unknown Staff");
            dto.setTestName(lt.getTestName());
            dto.setTestCategory(lt.getTestCategory());
            dto.setResultValue(lt.getResultValue());
            dto.setUnit(lt.getUnit());
            dto.setReferenceRange(lt.getReferenceRange());
            dto.setRemarks(lt.getRemarks());
            dto.setStatus(lt.getStatus());
            dto.setOrderedAt(lt.getOrderedAt());
            return dto;
        }).collect(Collectors.toList());
    }

    /**
     * Permanently deletes a lab test order.
     *
     * @param id the ID of the lab test to delete
     * @throws RuntimeException if the lab test is not found
     */
    @Transactional
    public void deleteLabTest(Long id) {
        if (!labTestRepository.existsById(id)) {
            throw new RuntimeException("404: Lab test not found");
        }
        labTestRepository.deleteById(id);
    }
}