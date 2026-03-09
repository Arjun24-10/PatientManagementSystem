package com.securehealth.backend.service;

import com.securehealth.backend.dto.DoctorDTO;
import com.securehealth.backend.model.DoctorProfile;
import com.securehealth.backend.repository.DoctorProfileRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class DoctorService {

    @Autowired
    private DoctorProfileRepository doctorProfileRepository;

    @Transactional(readOnly = true)
    public List<DoctorDTO> getAllDoctors() {
        return doctorProfileRepository.findAll().stream()
                .map(this::mapToDTO)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public DoctorDTO getDoctorById(Long id) {
        DoctorProfile profile = doctorProfileRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("404: Doctor not found"));
        return mapToDTO(profile);
    }

    @Transactional(readOnly = true)
    public List<DoctorDTO> getDoctorsBySpecialty(String specialty) {
        return doctorProfileRepository.findBySpecialtyIgnoreCase(specialty).stream()
                .map(this::mapToDTO)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<DoctorDTO> getDoctorsByDepartment(String department) {
        return doctorProfileRepository.findByDepartmentIgnoreCase(department).stream()
                .map(this::mapToDTO)
                .collect(Collectors.toList());
    }

    @Transactional
    public DoctorDTO updateDoctorProfile(Long id, DoctorDTO dto, String requesterEmail, String requesterRole) {
        DoctorProfile profile = doctorProfileRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("404: Doctor not found"));

        // Security Check: Only the owning Doctor or an Admin can edit this profile
        if (!requesterRole.equals("ADMIN") && !profile.getUser().getEmail().equals(requesterEmail)) {
            throw new RuntimeException("403 Forbidden: You can only update your own profile");
        }

        profile.setFirstName(dto.getFirstName());
        profile.setLastName(dto.getLastName());
        profile.setSpecialty(dto.getSpecialty());
        profile.setContactNumber(dto.getContactNumber());
        profile.setDepartment(dto.getDepartment());
        
        // Update Scheduling Fields
        if (dto.getShiftStartTime() != null) profile.setShiftStartTime(dto.getShiftStartTime());
        if (dto.getShiftEndTime() != null) profile.setShiftEndTime(dto.getShiftEndTime());
        if (dto.getSlotDurationMinutes() != null) profile.setSlotDurationMinutes(dto.getSlotDurationMinutes());
        if (dto.getWorkingDays() != null) profile.setWorkingDays(dto.getWorkingDays());

        return mapToDTO(doctorProfileRepository.save(profile));
    }

    // --- Helper Method ---
    private DoctorDTO mapToDTO(DoctorProfile profile) {
        DoctorDTO dto = new DoctorDTO();
        dto.setId(profile.getProfileId());
        dto.setFirstName(profile.getFirstName());
        dto.setLastName(profile.getLastName());
        dto.setEmail(profile.getUser().getEmail());
        dto.setSpecialty(profile.getSpecialty());
        dto.setContactNumber(profile.getContactNumber());
        dto.setDepartment(profile.getDepartment());
        
        // Map Scheduling Fields to DTO
        dto.setShiftStartTime(profile.getShiftStartTime());
        dto.setShiftEndTime(profile.getShiftEndTime());
        dto.setSlotDurationMinutes(profile.getSlotDurationMinutes());
        dto.setWorkingDays(profile.getWorkingDays());
        
        return dto;
    }
}