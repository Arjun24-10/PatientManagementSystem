package com.securehealth.backend.service;

import com.securehealth.backend.dto.PatientDTO;
import com.securehealth.backend.model.Login;
import com.securehealth.backend.model.PatientProfile;
import com.securehealth.backend.model.Role; // Assuming you have a Role enum
import com.securehealth.backend.repository.LoginRepository;
import com.securehealth.backend.repository.PatientProfileRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class PatientService {

    @Autowired
    private PatientProfileRepository patientProfileRepository;

    @Autowired
    private LoginRepository loginRepository;

    /**
     * GET /patients
     * Only Doctors and Admins should be able to pull a full list of patients.
     */
    @Transactional(readOnly = true)
    public List<PatientDTO> getAllPatients(String requesterRole) {
        if (!requesterRole.equals("DOCTOR") && !requesterRole.equals("ADMIN")) {
            throw new RuntimeException("403 Forbidden: Insufficient privileges");
        }
        
        return patientProfileRepository.findAll().stream()
                .map(this::mapToDTO)
                .collect(Collectors.toList());
    }

    /**
     * GET /patients/:id
     * SECURITY CORE: Prevents IDOR. 
     */
    @Transactional(readOnly = true)
    public PatientDTO getPatientById(Long id, String requesterEmail, String requesterRole) {
        PatientProfile profile = patientProfileRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("404: Patient not found"));

        // Admin and Doctor access check (In a strict system, you'd check if this specific doctor is assigned to this patient)
        if (requesterRole.equals("ADMIN") || requesterRole.equals("DOCTOR")) {
            return mapToDTO(profile);
        }

        // Patient access check: They can only see the profile if it belongs to their own Login
        if (profile.getUser().getEmail().equals(requesterEmail)) {
            return mapToDTO(profile);
        }

        // If they reach here, they are trying to access someone else's profile
        throw new RuntimeException("403 Forbidden: Unauthorized access to patient records");
    }

    /**
     * GET /patients/me
     * SECURITY CORE: Gets the currently logged in patient's profile.
     */
    @Transactional(readOnly = true)
    public PatientDTO getPatientByEmail(String email) {
        Login user = loginRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));
        PatientProfile profile = patientProfileRepository.findByUser(user)
                .orElseThrow(() -> new RuntimeException("404: Patient profile not found"));
        return mapToDTO(profile);
    }

    /**
     * POST /patients
     * Creates a profile and links it to the logged-in user.
     */
    @Transactional
    public PatientDTO createPatientProfile(PatientDTO dto, String requesterEmail) {
        Login user = loginRepository.findByEmail(requesterEmail)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (patientProfileRepository.findByUser(user).isPresent()) {
            throw new RuntimeException("400: Profile already exists for this user");
        }

        PatientProfile profile = new PatientProfile();
        profile.setUser(user);
        updateProfileFields(profile, dto);
        
        // Optional: Link doctor if provided and requester is Admin
        if (dto.getAssignedDoctorId() != null) {
             loginRepository.findById(dto.getAssignedDoctorId())
                 .ifPresent(profile::setAssignedDoctor);
        }

        return mapToDTO(patientProfileRepository.save(profile));
    }

    /**
     * PUT /patients/:id
     */
    @Transactional
    public PatientDTO updatePatientProfile(Long id, PatientDTO dto, String requesterEmail, String requesterRole) {
        PatientProfile profile = patientProfileRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("404: Patient not found"));

        // Authorization check
        if (!requesterRole.equals("ADMIN") && !profile.getUser().getEmail().equals(requesterEmail)) {
            throw new RuntimeException("403 Forbidden: Cannot update another patient's profile");
        }

        updateProfileFields(profile, dto);
        return mapToDTO(patientProfileRepository.save(profile));
    }

    // --- Helper Methods ---

    private void updateProfileFields(PatientProfile profile, PatientDTO dto) {
        profile.setFirstName(dto.getFirstName());
        profile.setLastName(dto.getLastName());
        profile.setDateOfBirth(dto.getDateOfBirth());
        profile.setGender(dto.getGender());
        profile.setContactNumber(dto.getContactNumber());
        profile.setAddress(dto.getAddress());
        profile.setMedicalHistory(dto.getMedicalHistory());
    }

    private PatientDTO mapToDTO(PatientProfile profile) {
        PatientDTO dto = new PatientDTO();
        dto.setId(profile.getProfileId());
        dto.setFirstName(profile.getFirstName());
        dto.setLastName(profile.getLastName());
        dto.setEmail(profile.getUser().getEmail());
        dto.setDateOfBirth(profile.getDateOfBirth());
        dto.setGender(profile.getGender());
        dto.setContactNumber(profile.getContactNumber());
        dto.setAddress(profile.getAddress());
        dto.setMedicalHistory(profile.getMedicalHistory());
        
        if (profile.getAssignedDoctor() != null) {
            dto.setAssignedDoctorId(profile.getAssignedDoctor().getUserId());
        }
        return dto;
    }
}