package com.securehealth.backend.repository;

import com.securehealth.backend.model.ArchivedUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface ArchivedUserRepository extends JpaRepository<ArchivedUser, Long> {

    List<ArchivedUser> findAllByOrderByArchivedAtDesc();

    Optional<ArchivedUser> findByOriginalUserId(Long originalUserId);

    Optional<ArchivedUser> findByEmail(String email);
}
