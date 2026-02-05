package com.securehealth.backend.service;

import com.securehealth.backend.model.Login;
import com.securehealth.backend.model.Role;
import com.securehealth.backend.model.Session; // [FIXED] Added Import
import com.securehealth.backend.repository.LoginRepository;
import com.securehealth.backend.repository.SessionRepository; // [FIXED] Added Import
import com.securehealth.backend.dto.LoginResponse; // [FIXED] Added Import
import com.securehealth.backend.util.JwtUtil;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional; // [FIXED] Added Import

import java.time.LocalDateTime;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Optional;

@Service
public class AuthService {

    @Autowired
    private LoginRepository loginRepository;

    @Autowired
    private SessionRepository sessionRepository; // Now this will work!

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * Registers a new user.
     */
    @Transactional // Now this will work!
    public Login registerUser(String email, String rawPassword, Role role) {
        if (loginRepository.existsByEmail(email)) {
            throw new RuntimeException("Email already taken");
        }

        String hash = passwordEncoder.encode(rawPassword);

        Login newUser = new Login();
        newUser.setEmail(email);
        newUser.setPasswordHash(hash);
        newUser.setRole(role);
        
        return loginRepository.save(newUser);
    }

    /**
     * Authenticates user and generates tokens.
     */
    @Transactional
    public LoginResponse login(String email, String rawPassword, String ipAddress, String userAgent) {
        // 1. Verify User
        Login user = loginRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Invalid credentials"));

        if (user.isLocked()) throw new RuntimeException("Account locked");

        if (!passwordEncoder.matches(rawPassword, user.getPasswordHash())) {
            throw new RuntimeException("Invalid credentials");
        }

        // 2. Generate Tokens
        String accessToken = jwtUtil.generateAccessToken(user.getEmail(), user.getRole().name(), user.getUserId());
        String refreshToken = jwtUtil.generateRefreshToken();

        // 3. Hash Refresh Token
        String refreshTokenHash = hashToken(refreshToken);

        // 4. Create Session in DB
        Session session = new Session();
        session.setUser(user);
        session.setRefreshTokenHash(refreshTokenHash);
        session.setIpAddress(ipAddress);
        session.setUserAgent(userAgent);
        session.setExpiresAt(LocalDateTime.now().plusDays(7)); 
        sessionRepository.save(session);

        return new LoginResponse(accessToken, refreshToken, user.getRole().name());
    }

    /**
     * Revokes a session (Logout).
     */
    @Transactional
    public void logout(String refreshToken) {
        if (refreshToken == null) return;
        
        String hash = hashToken(refreshToken);
        
        sessionRepository.findByRefreshTokenHash(hash)
            .ifPresent(session -> {
                session.setRevoked(true);
                sessionRepository.save(session);
            });
    }

    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes());
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Error hashing token");
        }
    }
}