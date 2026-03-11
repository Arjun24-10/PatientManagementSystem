package com.securehealth.backend.dto;

import com.securehealth.backend.model.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.LocalDate;

/**
 * Data Transfer Object for user registration requests.
 * <p>
 * Contains the necessary information to create a new user account, 
 * including email, password, role, and optional profile details like 
 * full name, date of birth, and address.
 * </p>
 */
@Data
@NoArgsConstructor  // Fixes Test Error
@AllArgsConstructor // Fixes Test Error
public class RegistrationRequest {

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    private String email;

    @NotBlank(message = "Password is required")
    @Size(min = 12, message = "Password must be at least 12 characters long")
    private String password;

    @NotNull(message = "Role is required")
    private Role role;

    @JsonProperty("full_name")
    private String fullName;

    @JsonProperty("date_of_birth")
    private LocalDate dateOfBirth;

    private String address;
}