package com.securehealth.backend.repository;

import com.securehealth.backend.model.Login;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.List;

/**
 * Data Access Object (DAO) for the Login entity.
 * <p>
 * This interface extends JpaRepository to provide standard CRUD operations
 * (Create, Read, Update, Delete) without writing SQL.
 * </p>
 * * @author Manas
 * 
 * @version 1.0
 */
@Repository
public interface LoginRepository extends JpaRepository<Login, Long> {

    /**
     * Finds a user by their email address.
     * <p>
     * Used during authentication to retrieve the password hash and role.
     * </p>
     *
     * @param email The unique email address to search for.
     * @return An Optional containing the Login entity if found, or empty if not.
     */
    Optional<Login> findByEmail(String email);

    /**
     * Checks if a user exists with the given email.
     * <p>
     * Used during registration to prevent duplicate accounts.
     * </p>
     *
     * @param email The email address to check.
     * @return true if the email is already registered, false otherwise.
     */
    boolean existsByEmail(String email);

    /**
     * Counts the total number of users assigned to a specific role.
     * <p>
     * Used for administrative metrics and dashboard reporting.
     * </p>
     * @param role The string representation of the user role (e.g., "PATIENT", "DOCTOR").
     * @return The total count of users with the specified role.
     */
    long countByRole(String role);

    /**
     * Retrieves a list of users who do not have the specified role.
     * <p>
     * Typically used to fetch all staff members (Admins, Doctors, Nurses) by excluding "PATIENT".
     * </p>
     * @param role The role to exclude from the results.
     * @return A list of Login entities that do not match the given role.
     */
    List<Login> findByRoleNot(String role);
}