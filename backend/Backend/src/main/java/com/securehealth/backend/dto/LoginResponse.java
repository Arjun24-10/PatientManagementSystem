package com.securehealth.backend.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * Data Transfer Object for login responses.
 * <p>
 * Contains authentication tokens (access and refresh), the user's role, 
 * authentication status, and the unique user ID upon successful login or 
 * partial authentication (e.g., when OTP is required).
 * </p>
 */
@Data
@AllArgsConstructor
public class LoginResponse {
    private String accessToken;
    private String refreshToken; 
    private String role;
    private String status;
    private Long userId;
}