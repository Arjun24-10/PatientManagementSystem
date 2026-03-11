package com.securehealth.backend.service;


import com.securehealth.backend.dto.PrescriptionDTO;
import com.securehealth.backend.dto.PrescriptionRequest;
import com.securehealth.backend.model.Login;
import com.securehealth.backend.model.PatientProfile;
import com.securehealth.backend.model.Prescription;
import com.securehealth.backend.model.AuditLog;
import com.securehealth.backend.repository.AuditLogRepository;
import com.securehealth.backend.repository.LoginRepository;
import com.securehealth.backend.repository.PatientProfileRepository;
import com.securehealth.backend.repository.PrescriptionRepository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Service for managing medication prescriptions.
 * <p>
 * Handles the creation of prescriptions by doctors, chronological 
 * retrieval for patients, refill management, and administrative cleanup.
 * </p>
 */
@Service
public class PrescriptionService {

    @Autowired private PrescriptionRepository prescriptionRepository;
    @Autowired private LoginRepository loginRepository;
    @Autowired private PatientProfileRepository patientProfileRepository;
    @Autowired private AuditLogRepository auditLogRepository;

    /**
     * Issues a new medication prescription for a patient.
     * <p>
     * Automatically captures the prescribing doctor and generates an audit log.
     * </p>
     *
     * @param request the {@link PrescriptionRequest} details
     * @param doctorEmail the email of the issuing doctor
     * @return the saved {@link Prescription} entity
     */
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
        
        // Default start date to now, end date dependent on duration parsing or frontend
        prescription.setStartDate(LocalDateTime.now());
        prescription.setRefillsRemaining(0);

        Prescription saved = prescriptionRepository.save(prescription);

        // Audit Log
        auditLogRepository.save(new AuditLog(doctorEmail, "PRESCRIPTION_CREATED", "INTERNAL", "SYSTEM", 
            "Prescribed " + prescription.getMedicationName() + " to patient ID: " + patient.getProfileId()));

        return saved;
    }
    /**
     * Retrieves all prescriptions associated with a specific patient.
     *
     * @param patientId the ID of the patient
     * @return a list of {@link PrescriptionDTO} objects
     */
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
            dto.setStartDate(p.getStartDate());
            dto.setEndDate(p.getEndDate());
            dto.setRefillsRemaining(p.getRefillsRemaining());
            return dto;
        }).collect(Collectors.toList());
    }

    /**
     * Retrieves only the current "ACTIVE" prescriptions for a specific patient.
     *
     * @param patientId the ID of the patient
     * @return a list of {@link PrescriptionDTO} objects
     */
    @Transactional(readOnly = true)
    public List<PrescriptionDTO> getActivePrescriptionsByPatient(Long patientId) {
        return prescriptionRepository.findByPatient_ProfileIdAndStatus(patientId, "ACTIVE")
                .stream().map(p -> {
                    PrescriptionDTO dto = new PrescriptionDTO();
                    dto.setPrescriptionId(p.getPrescriptionId());
                    dto.setDoctorName(p.getDoctor() != null ? p.getDoctor().getEmail() : "Unknown Doctor");
                    dto.setMedicationName(p.getMedicationName());
                    dto.setDosage(p.getDosage());
                    dto.setFrequency(p.getFrequency());
                    dto.setDuration(p.getDuration());
                    dto.setSpecialInstructions(p.getSpecialInstructions());
                    dto.setStatus(p.getStatus());
                    dto.setIssuedAt(p.getIssuedAt());
                    dto.setStartDate(p.getStartDate());
                    dto.setEndDate(p.getEndDate());
                    dto.setRefillsRemaining(p.getRefillsRemaining());
                    return dto;
                }).collect(Collectors.toList());
    }

    /**
     * Decrements the refill count of an existing prescription.
     *
     * @param id the ID of the prescription to refill
     * @param doctorEmail the email of the doctor authorizing the refill
     * @return the updated {@link Prescription} entity
     * @throws RuntimeException if the prescription is not found, unauthorized, or no refills remain
     */
    @Transactional
    public Prescription refillPrescription(Long id, String doctorEmail) {
        Prescription prescription = prescriptionRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("404: Prescription not found"));

        if (!prescription.getDoctor().getEmail().equals(doctorEmail)) {
            throw new RuntimeException("403: You can only refill prescriptions you issued.");
        }

        if (prescription.getRefillsRemaining() <= 0) {
            throw new RuntimeException("400: No refills remaining. Please create a new prescription.");
        }

        prescription.setRefillsRemaining(prescription.getRefillsRemaining() - 1);
        return prescriptionRepository.save(prescription);
    }

    /**
     * Permanently deletes a prescription from the system.
     * <p>
     * Restricted administrative action that generates an audit log entry.
     * </p>
     *
     * @param id the ID of the prescription to delete
     * @param adminEmail the email of the administrator performing the deletion
     * @throws RuntimeException if the prescription is not found
     */
    @Transactional
    public void deletePrescription(Long id, String adminEmail) {
        Prescription prescription = prescriptionRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("404: Prescription not found"));
        
        prescriptionRepository.delete(prescription);

        auditLogRepository.save(new AuditLog(adminEmail, "PRESCRIPTION_DELETED", "INTERNAL", "SYSTEM", 
            "Deleted prescription ID: " + id + " for patient ID: " + prescription.getPatient().getProfileId()));
    }
}