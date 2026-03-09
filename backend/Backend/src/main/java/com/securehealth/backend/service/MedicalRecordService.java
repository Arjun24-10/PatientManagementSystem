package com.securehealth.backend.service;

import com.securehealth.backend.dto.MedicalRecordDTO;
import com.securehealth.backend.dto.MedicalRecordRequest;
import com.securehealth.backend.model.Login;
import com.securehealth.backend.model.MedicalRecord;
import com.securehealth.backend.model.PatientProfile;
import com.securehealth.backend.model.AuditLog;
import com.securehealth.backend.repository.AuditLogRepository;
import com.securehealth.backend.repository.LoginRepository;
import com.securehealth.backend.repository.MedicalRecordRepository;
import com.securehealth.backend.repository.PatientProfileRepository;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class MedicalRecordService {

    @Autowired private MedicalRecordRepository medicalRecordRepository;
    @Autowired private LoginRepository loginRepository;
    @Autowired private PatientProfileRepository patientProfileRepository;
    @Autowired private AuditLogRepository auditLogRepository;

    @Transactional
    public MedicalRecord createMedicalRecord(MedicalRecordRequest request, String doctorEmail) {
        Login doctor = loginRepository.findByEmail(doctorEmail)
                .orElseThrow(() -> new RuntimeException("Doctor not found"));

        PatientProfile patient = patientProfileRepository.findById(request.getPatientId())
                .orElseThrow(() -> new RuntimeException("404: Patient not found"));

        MedicalRecord record = new MedicalRecord();
        record.setDoctor(doctor);
        record.setPatient(patient);
        record.setDiagnosis(request.getDiagnosis());
        record.setSymptoms(request.getSymptoms());
        record.setTreatmentProvided(request.getTreatmentProvided());

        MedicalRecord saved = medicalRecordRepository.save(record);

        // Audit Log
        auditLogRepository.save(new AuditLog(doctorEmail, "MEDICAL_RECORD_CREATED", "INTERNAL", "SYSTEM", 
            "Created medical record for patient ID: " + patient.getProfileId() + ", Diagnosis: " + record.getDiagnosis()));

        return saved;
    }
    @Transactional(readOnly = true)
    public List<MedicalRecordDTO> getMedicalRecordsByPatient(Long patientId) {
        return medicalRecordRepository.findByPatient_ProfileId(patientId).stream().map(mr -> {
            MedicalRecordDTO dto = new MedicalRecordDTO();
            dto.setRecordId(mr.getRecordId());
            dto.setPatientId(mr.getPatient().getProfileId());
            dto.setDoctorName(mr.getDoctor() != null ? mr.getDoctor().getEmail() : "Unknown Doctor");
            dto.setDiagnosis(mr.getDiagnosis());
            dto.setSymptoms(mr.getSymptoms());
            dto.setTreatmentProvided(mr.getTreatmentProvided());
            dto.setNotes(mr.getSymptoms()); // Using symptoms as notes if no explicit notes exist
            dto.setRecordDate(mr.getUpdatedAt());
            dto.setCreatedAt(mr.getCreatedAt());
            return dto;
        }).collect(Collectors.toList());
    }

    @Transactional
    public void deleteMedicalRecord(Long id, String adminEmail) {
        MedicalRecord record = medicalRecordRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("404: Medical Record not found"));
        
        medicalRecordRepository.delete(record);

        auditLogRepository.save(new AuditLog(adminEmail, "MEDICAL_RECORD_DELETED", "INTERNAL", "SYSTEM", 
            "Deleted medical record ID: " + id + " for patient ID: " + record.getPatient().getProfileId()));
    }
}