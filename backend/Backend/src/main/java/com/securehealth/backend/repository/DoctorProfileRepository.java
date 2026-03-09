package com.securehealth.backend.repository;

import com.securehealth.backend.model.DoctorProfile;
import com.securehealth.backend.model.Login;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface DoctorProfileRepository extends JpaRepository<DoctorProfile, Long> {

    // Internal secure lookup
    Optional<DoctorProfile> findByUser(Login user);

    // Frontend: GET /doctors/specialty/:specialty
    List<DoctorProfile> findBySpecialtyIgnoreCase(String specialty);

    Optional<DoctorProfile> findByUser_UserId(Long userId);
}