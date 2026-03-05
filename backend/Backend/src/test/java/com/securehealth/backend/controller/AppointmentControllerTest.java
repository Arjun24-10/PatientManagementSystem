package com.securehealth.backend.controller;

import com.securehealth.backend.model.Appointment;
import com.securehealth.backend.repository.AppointmentRepository;
import com.securehealth.backend.repository.AuditLogRepository;
import com.securehealth.backend.security.PatientAccessValidator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import com.securehealth.backend.util.JwtUtil;
import com.securehealth.backend.service.TokenBlacklistService;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.time.LocalDateTime;
import java.util.Arrays;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AppointmentController.class)
@AutoConfigureMockMvc(addFilters = false)
public class AppointmentControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AppointmentRepository appointmentRepository;

    @MockBean
    private PatientAccessValidator accessValidator;

    @MockBean
    private JwtUtil jwtUtil;

    @MockBean
    private UserDetailsService userDetailsService;

    @MockBean
    private TokenBlacklistService tokenBlacklistService;

    // FIX: AuditLogRepository must be mocked so the RequestLoggingFilter
    // (which Spring wires even in WebMvcTest) can be satisfied during context load.
    @MockBean
    private AuditLogRepository auditLogRepository;

    @Test
    @WithMockUser(username = "patient@mail.com", authorities = {"PATIENT"})
    void getAppointmentsByPatient_ReturnsList() throws Exception {
        // Arrange
        Long patientId = 1L;
        Appointment apt = new Appointment();
        apt.setAppointmentId(100L);
        apt.setStatus("SCHEDULED");
        apt.setAppointmentDate(LocalDateTime.now().plusDays(1));

        doNothing().when(accessValidator).validateAccess(eq(patientId), any());
        when(appointmentRepository.findByPatient_ProfileIdOrderByAppointmentDateDesc(patientId))
                .thenReturn(Arrays.asList(apt));

        // Act & Assert
        mockMvc.perform(get("/api/appointments/patient/" + patientId)
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].appointmentId").value(100))
                .andExpect(jsonPath("$[0].status").value("SCHEDULED"));
    }
}
