package com.securehealth.backend.controller;

import com.securehealth.backend.dto.LoginRequest;
import com.securehealth.backend.dto.LoginResponse;
import com.securehealth.backend.dto.RegistrationRequest;
import com.securehealth.backend.model.Login;
import com.securehealth.backend.service.AuthService;
import jakarta.servlet.http.Cookie;            
import jakarta.servlet.http.HttpServletRequest;  
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * REST Controller for Authentication endpoints.
 * <p>
 * Exposes APIs for user registration and login.
 * This layer handles HTTP concerns (Status codes, JSON formatting)
 * and delegates business logic to the {@link AuthService}.
 * </p>
 *
 * @author Manas
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    /**
     * Register a new user.
     * <p>
     * Endpoint: POST /api/auth/register
     * </p>
     *
     * @param request The validated DTO containing email, password, and role.
     * @return 201 Created if successful, or 400 Bad Request if validation fails.
     */
    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> registerUser(@Valid @RequestBody RegistrationRequest request) {
        try {
            authService.registerUser(
                    request.getEmail(),
                    request.getPassword(),
                    request.getRole());
            Map<String, String> resp = new HashMap<>();
            resp.put("message", "User registered successfully");
            return ResponseEntity.status(HttpStatus.CREATED).body(resp);

        } catch (RuntimeException e) {
            // In a real app, use a Global Exception Handler instead of try-catch here
            Map<String, String> resp = new HashMap<>();
            resp.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(resp);
        }

    }

    /**
     * Authenticates user and sets Secure HttpOnly Cookie.
     * Endpoint: POST /api/auth/login
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request,
                                   HttpServletResponse response,
                                   HttpServletRequest httpRequest) {
        try {
            // 1. Call Service (Now returns LoginResponse DTO, not User entity)
            LoginResponse loginData = authService.login(
                request.getEmail(), 
                request.getPassword(),
                httpRequest.getRemoteAddr(),       // Get User's IP
                httpRequest.getHeader("User-Agent") // Get Browser info
            );

            // 2. [NEW] Create the Secure Cookie
            // This is how we hide the refresh token from JavaScript
            Cookie refreshCookie = new Cookie("refreshToken", loginData.getRefreshToken());
            refreshCookie.setHttpOnly(true);  // Critical: JS cannot read this
            refreshCookie.setSecure(false);   // False for Localhost, True for Production
            refreshCookie.setPath("/api/auth"); // Cookie only sent to Auth endpoints
            refreshCookie.setMaxAge(7 * 24 * 60 * 60); // 7 Days in seconds

            // 3. Add Cookie to Response
            response.addCookie(refreshCookie);

            // 4. Sanitize Response Body
            // We set refreshToken to null here so it is NOT sent in the JSON body
            loginData.setRefreshToken(null); 

            // 5. Return Access Token & Role
            return ResponseEntity.ok(loginData);

        } catch (RuntimeException e) {
            Map<String, Object> resp = new HashMap<>();
            resp.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(resp);
        }
    }
    
    // --- LOGOUT (NEW - TASK #12515) ---
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@CookieValue(name = "refreshToken", required = false) String refreshToken,
                                    HttpServletResponse response) {
        
        // 1. Invalidate in DB
        if(refreshToken != null) authService.logout(refreshToken);

        // 2. Kill the Cookie
        Cookie cookie = new Cookie("refreshToken", null);
        cookie.setHttpOnly(true);
        cookie.setSecure(false);
        cookie.setPath("/api/auth");
        cookie.setMaxAge(0); // Expires immediately
        
        response.addCookie(cookie);
        
        return ResponseEntity.ok("Logged out successfully");
    }
}