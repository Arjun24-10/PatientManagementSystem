package com.securehealth.backend.service;

import com.securehealth.backend.dto.VitalSignRequest;
import com.securehealth.backend.model.Login;
import com.securehealth.backend.model.PatientProfile;
import com.securehealth.backend.model.VitalSign;
import com.securehealth.backend.repository.LoginRepository;
import com.securehealth.backend.repository.PatientProfileRepository;
import com.securehealth.backend.repository.VitalSignRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class VitalSignService {

    @Autowired private VitalSignRepository vitalSignRepository;
    @Autowired private LoginRepository loginRepository;
    @Autowired private PatientProfileRepository patientProfileRepository;

    @Transactional
    public VitalSign createVitalSign(VitalSignRequest request, String recorderEmail) {
        Login recorder = loginRepository.findByEmail(recorderEmail)
                .orElseThrow(() -> new RuntimeException("Staff member not found"));

        PatientProfile patient = patientProfileRepository.findById(request.getPatientId())
                .orElseThrow(() -> new RuntimeException("404: Patient not found"));

        VitalSign vitalSign = new VitalSign();
        vitalSign.setPatient(patient);
        vitalSign.setNurse(recorder);
        
        vitalSign.setBloodPressure(request.getBloodPressure());
        vitalSign.setHeartRate(request.getHeartRate());
        vitalSign.setTemperature(request.getTemperature());
        vitalSign.setRespiratoryRate(request.getRespiratoryRate());
        vitalSign.setOxygenSaturation(request.getOxygenSaturation());
        vitalSign.setWeight(request.getWeight());
        vitalSign.setHeight(request.getHeight());

        return vitalSignRepository.save(vitalSign);
    }

    @Transactional(readOnly = true)
    public java.util.List<com.securehealth.backend.dto.VitalSignDTO> getVitalSignsByPatient(Long patientId) {
        return vitalSignRepository.findByPatient_ProfileIdOrderByRecordedAtDesc(patientId)
                .stream().map(this::mapToDTO).collect(java.util.stream.Collectors.toList());
    }

    @Transactional(readOnly = true)
    public com.securehealth.backend.dto.VitalSignDTO getLatestVitalSignByPatient(Long patientId) {
        return vitalSignRepository.findFirstByPatient_ProfileIdOrderByRecordedAtDesc(patientId)
                .map(this::mapToDTO)
                .orElseThrow(() -> new RuntimeException("404: No vital signs found for patient"));
    }

    @Transactional
    public void deleteVitalSign(Long id) {
        if (!vitalSignRepository.existsById(id)) {
            throw new RuntimeException("404: Vital sign not found");
        }
        vitalSignRepository.deleteById(id);
    }

    private com.securehealth.backend.dto.VitalSignDTO mapToDTO(VitalSign v) {
        com.securehealth.backend.dto.VitalSignDTO dto = new com.securehealth.backend.dto.VitalSignDTO();
        dto.setVitalSignId(v.getVitalSignId());
        dto.setPatientProfileId(v.getPatient().getProfileId());
        dto.setNurseEmail(v.getNurse().getEmail());
        dto.setBloodPressure(v.getBloodPressure());
        dto.setHeartRate(v.getHeartRate());
        dto.setTemperature(v.getTemperature());
        dto.setRespiratoryRate(v.getRespiratoryRate());
        dto.setOxygenSaturation(v.getOxygenSaturation());
        dto.setWeight(v.getWeight());
        dto.setHeight(v.getHeight());
        dto.setRecordedAt(v.getRecordedAt());
        return dto;
    }
}