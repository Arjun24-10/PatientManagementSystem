package com.securehealth.backend.controller;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import java.util.List;
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
import com.securehealth.backend.service.AppointmentService;
import com.securehealth.backend.service.TokenBlacklistService;
import org.springframework.security.core.userdetails.UserDetailsService;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.ArgumentMatchers.anyLong;

import java.time.LocalDateTime;
import java.util.Arrays;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AppointmentController.class)
@AutoConfigureMockMvc(addFilters = false)
public class AppointmentControllerTest {

    @Autowired
    private MockMvc mockMvc;

    // --- CONTROLLER DEPENDENCIES ---
    @MockBean
    private AppointmentRepository appointmentRepository;

    @MockBean
    private PatientAccessValidator accessValidator;

    @MockBean
    private AppointmentService appointmentService;

    // --- SECURITY DEPENDENCIES (Needed to satisfy the ApplicationContext) ---
    @MockBean
    private com.securehealth.backend.util.JwtUtil jwtUtil;

    @MockBean
    private org.springframework.security.core.userdetails.UserDetailsService userDetailsService;

    @MockBean
    private com.securehealth.backend.service.TokenBlacklistService tokenBlacklistService;

    // FIX: AuditLogRepository must be mocked so the RequestLoggingFilter
    // (which Spring wires even in WebMvcTest) can be satisfied during context load.
    @MockBean
    private AuditLogRepository auditLogRepository;

    @Test
    @WithMockUser(username = "patient@mail.com", authorities = {"PATIENT"})
    void getAppointmentsByPatient_ReturnsList() throws Exception {
        //Arrange
        com.securehealth.backend.dto.AppointmentDTO mockDto = new com.securehealth.backend.dto.AppointmentDTO();
        mockDto.setAppointmentId(10L);
        mockDto.setDoctorName("dr.house@mail.com");
        mockDto.setPatientName("John Doe");
        mockDto.setStatus("SCHEDULED");
        mockDto.setReasonForVisit("Routine Checkup");

        when(appointmentService.getAppointmentsByPatient(1L))
                .thenReturn(List.of(mockDto));

        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                "patient@mail.com", null, List.of(new SimpleGrantedAuthority("PATIENT")));
                
        mockMvc.perform(get("/api/appointments/patient/1")
                .principal(auth)
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].appointmentId").value(10))           // Matches the DTO
                .andExpect(jsonPath("$[0].doctorName").value("dr.house@mail.com")) // Matches the DTO
                .andExpect(jsonPath("$[0].status").value("SCHEDULED"));        // Matches the DTO
    }
    @Test
    void approveAppointment_AsAdmin_Returns200() throws Exception {
        // Arrange
        Appointment approved = new Appointment();
        approved.setStatus("SCHEDULED");
        when(appointmentService.approveAppointment(10L)).thenReturn(approved);

        // Manually create the Authentication object
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                "admin@mail.com", null, List.of(new SimpleGrantedAuthority("ADMIN")));

        // Act & Assert
        mockMvc.perform(put("/api/appointments/10/approve")
                .principal(auth) // <-- THIS INJECTS THE AUTHENTICATION
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("SCHEDULED"));
    }

    @Test
    void approveAppointment_AsPatient_Returns403() throws Exception {
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                "patient@mail.com", null, List.of(new SimpleGrantedAuthority("PATIENT")));

        mockMvc.perform(put("/api/appointments/10/approve")
                .principal(auth)
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isForbidden())
                .andExpect(content().string("Forbidden: Only administrative staff can approve appointments."));
        
        verify(appointmentService, never()).approveAppointment(anyLong());
    }

    @Test
    void rejectAppointment_AsAdmin_Returns200() throws Exception {
        Appointment rejected = new Appointment();
        rejected.setStatus("REJECTED");
        when(appointmentService.rejectAppointment(eq(10L), any())).thenReturn(rejected);

        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                "admin@mail.com", null, List.of(new SimpleGrantedAuthority("ADMIN")));

        mockMvc.perform(put("/api/appointments/10/reject")
                .principal(auth)
                .contentType(MediaType.APPLICATION_JSON)
                .content("Not in network"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("REJECTED"));
    }
}
