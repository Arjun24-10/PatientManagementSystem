package com.securehealth.backend.service;


import com.securehealth.backend.dto.PrescriptionDTO;
import com.securehealth.backend.dto.PrescriptionRequest;
import com.securehealth.backend.model.Login;
import com.securehealth.backend.model.PatientProfile;
import com.securehealth.backend.model.Prescription;
import com.securehealth.backend.repository.LoginRepository;
import com.securehealth.backend.repository.PatientProfileRepository;
import com.securehealth.backend.repository.PrescriptionRepository;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class PrescriptionService {

    @Autowired private PrescriptionRepository prescriptionRepository;
    @Autowired private LoginRepository loginRepository;
    @Autowired private PatientProfileRepository patientProfileRepository;

    @Transactional
    public Prescription createPrescription(PrescriptionRequest request, String doctorEmail) {
        Login doctor = loginRepository.findByEmail(doctorEmail)
                .orElseThrow(() -> new RuntimeException("Doctor not found"));

        PatientProfile patient = patientProfileRepository.findById(request.getPatientId())
                .orElseThrow(() -> new RuntimeException("404: Patient not found"));

        Prescription prescription = new Prescription();
        prescription.setDoctor(doctor);
        prescription.setPatient(patient);
        prescription.setMedicationName(request.getMedicationName());
        prescription.setDosage(request.getDosage());
        prescription.setFrequency(request.getFrequency());
        prescription.setDuration(request.getDuration());
        prescription.setSpecialInstructions(request.getSpecialInstructions());
        prescription.setStatus("ACTIVE");

        return prescriptionRepository.save(prescription);
    }
    @Transactional(readOnly = true)
    public List<PrescriptionDTO> getPrescriptionsByPatient(Long patientId) {
        return prescriptionRepository.findByPatient_ProfileId(patientId).stream().map(p -> {
            PrescriptionDTO dto = new PrescriptionDTO();
            dto.setPrescriptionId(p.getPrescriptionId());
            
            // Safely trigger the lazy load
            dto.setDoctorName(p.getDoctor() != null ? p.getDoctor().getEmail() : "Unknown Doctor");
            
            dto.setMedicationName(p.getMedicationName());
            dto.setDosage(p.getDosage());
            dto.setFrequency(p.getFrequency());
            dto.setDuration(p.getDuration());
            dto.setSpecialInstructions(p.getSpecialInstructions());
            dto.setStatus(p.getStatus());
            dto.setIssuedAt(p.getIssuedAt());
            return dto;
        }).collect(Collectors.toList());
    }
}