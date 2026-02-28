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
}