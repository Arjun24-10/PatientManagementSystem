package com.securehealth.backend.service;

import com.securehealth.backend.dto.LabTestDTO;
import com.securehealth.backend.model.LabTest;
import com.securehealth.backend.repository.LabTestRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@Transactional
public class LabTechnicianService {

    @Autowired
    private LabTestRepository labTestRepository;

    public Map<String, Object> getDashboardOverview() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("pending", labTestRepository.countByStatusIgnoreCase("Pending"));
        stats.put("collected", labTestRepository.countByStatusIgnoreCase("Collected"));
        stats.put("resultsPending", labTestRepository.countByStatusIgnoreCase("Results Pending"));
        stats.put("completed", labTestRepository.countByStatusIgnoreCase("Completed"));
        
        // Include recent activity feed data
        List<LabTest> recentActivity = labTestRepository.findTop10ByOrderByOrderedAtDesc();
        stats.put("recentActivity", recentActivity.stream().map(this::mapToDTO).collect(Collectors.toList()));
        return stats;
    }

    public List<LabTestDTO> getAllOrders(String status) {
        List<LabTest> labTests;
        if (status != null && !status.isEmpty()) {
            labTests = labTestRepository.findByStatusOrderByOrderedAtAsc(status);
        } else {
            labTests = labTestRepository.findAll();
        }
        return labTests.stream().map(this::mapToDTO).collect(Collectors.toList());
    }

    public LabTestDTO updateOrderStatus(Long testId, String newStatus) {
        LabTest labTest = labTestRepository.findById(testId)
                .orElseThrow(() -> new RuntimeException("Lab test not found with id: " + testId));
                
        labTest.setStatus(newStatus);
        
        // Optional: If you want to track when it was completed, you could add a completedAt field here.
        
        labTest = labTestRepository.save(labTest);
        return mapToDTO(labTest);
    }
    
    public LabTestDTO uploadResults(Long testId, String resultValue, String remarks, String fileUrl) {
         LabTest labTest = labTestRepository.findById(testId)
                .orElseThrow(() -> new RuntimeException("Lab test not found with id: " + testId));
        
        labTest.setResultValue(resultValue);
        
        if (remarks != null && !remarks.isEmpty()) {
            labTest.setRemarks(remarks);
        }
        
        if (fileUrl != null && !fileUrl.isEmpty()) {
            labTest.setFileUrl(fileUrl);
        }
        
        labTest.setStatus("Completed");
        
        labTest = labTestRepository.save(labTest);
        return mapToDTO(labTest);
    }

    private LabTestDTO mapToDTO(LabTest test) {
        LabTestDTO dto = new LabTestDTO();
        dto.setTestId(test.getTestId());
        
        if(test.getPatient() != null) {
            dto.setPatientName(test.getPatient().getFirstName() + " " + test.getPatient().getLastName());
            dto.setGender(test.getPatient().getGender());
            dto.setProfileId(test.getPatient().getProfileId());
        }
        
        if(test.getOrderedBy() != null) {
            dto.setOrderedByDoctor(test.getOrderedBy().getEmail()); // Or doctor's name if you link it to DoctorProfile
            dto.setOrderedById(test.getOrderedBy().getUserId());
        }
        
        dto.setTestName(test.getTestName());
        dto.setTestCategory(test.getTestCategory());
        dto.setResultValue(test.getResultValue());
        dto.setUnit(test.getUnit());
        dto.setReferenceRange(test.getReferenceRange());
        dto.setRemarks(test.getRemarks());
        dto.setStatus(test.getStatus());
        dto.setFileUrl(test.getFileUrl());
        dto.setOrderedAt(test.getOrderedAt());
        
        return dto;
    }
}
