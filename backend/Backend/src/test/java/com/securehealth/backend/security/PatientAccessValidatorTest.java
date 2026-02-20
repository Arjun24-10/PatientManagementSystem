package com.securehealth.backend.security;

import com.securehealth.backend.model.Login;
import com.securehealth.backend.model.PatientProfile;
import com.securehealth.backend.repository.PatientProfileRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class PatientAccessValidatorTest {

    @Mock
    private PatientProfileRepository patientProfileRepository;

    @Mock
    private Authentication authentication;

    @InjectMocks
    private PatientAccessValidator validator;

    private PatientProfile mockProfile;

    @BeforeEach
    void setUp() {
        Login mockLogin = new Login();
        mockLogin.setEmail("patientA@mail.com");

        mockProfile = new PatientProfile();
        mockProfile.setProfileId(1L);
        mockProfile.setUser(mockLogin);
    }

    @Test
    void validateAccess_DoctorBypassesCheck() {
        // Arrange
        GrantedAuthority authority = new SimpleGrantedAuthority("DOCTOR");
        doReturn(Collections.singletonList(authority)).when(authentication).getAuthorities();

        // Act & Assert
        assertDoesNotThrow(() -> validator.validateAccess(1L, authentication));
        
        // Verify repository was never called because Doctors bypass the check
        verify(patientProfileRepository, never()).findById(anyLong());
    }

    @Test
    void validateAccess_PatientAccessingOwnData_Succeeds() {
        // Arrange
        GrantedAuthority authority = new SimpleGrantedAuthority("PATIENT");
        doReturn(Collections.singletonList(authority)).when(authentication).getAuthorities();
        when(authentication.getName()).thenReturn("patientA@mail.com");
        when(patientProfileRepository.findById(1L)).thenReturn(Optional.of(mockProfile));

        // Act & Assert
        assertDoesNotThrow(() -> validator.validateAccess(1L, authentication));
    }

    @Test
    void validateAccess_PatientAccessingOtherData_ThrowsException() {
        // Arrange
        GrantedAuthority authority = new SimpleGrantedAuthority("PATIENT");
        doReturn(Collections.singletonList(authority)).when(authentication).getAuthorities();
        when(authentication.getName()).thenReturn("hacker@mail.com"); // Different email!
        when(patientProfileRepository.findById(1L)).thenReturn(Optional.of(mockProfile));

        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class, 
            () -> validator.validateAccess(1L, authentication));
        
        assertTrue(exception.getMessage().contains("403 Forbidden"));
    }
}