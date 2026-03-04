package com.securehealth.backend.repository;

import com.securehealth.backend.model.Appointment;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import com.securehealth.backend.model.PatientProfile;

import java.util.List;
import java.time.LocalDateTime;

@Repository
public interface AppointmentRepository extends JpaRepository<Appointment, Long> {

    // Frontend: GET /appointments/patient/:patientId
    List<Appointment> findByPatient_ProfileIdOrderByAppointmentDateDesc(Long patientId);

    // Frontend: GET /appointments/doctor/:doctorId
    // Finds all appointments for a doctor between the start and end of a specific
    // day
    List<Appointment> findByDoctor_UserIdAndAppointmentDateBetween(
            Long doctorId,
            java.time.LocalDateTime startOfDay,
            java.time.LocalDateTime endOfDay);

    // Checks if the doctor already has a non-cancelled appointment at this exact
    // time
    boolean existsByDoctor_UserIdAndAppointmentDateAndStatusNotIn(
            Long doctorId,
            java.time.LocalDateTime appointmentDate,
            java.util.List<String> statuses);

    List<Appointment> findByDoctor_UserIdOrderByAppointmentDateAsc(Long doctorId);

    @Query("SELECT DISTINCT a.patient FROM Appointment a " +
           "WHERE a.doctor.userId = :doctorId " +
           "AND a.status IN ('SCHEDULED', 'COMPLETED')")
    List<PatientProfile> findDistinctPatientsByDoctorId(@Param("doctorId") Long doctorId);

    List<Appointment> findByPatient_ProfileId(Long patientId);

    // Counts appointments by their exact status
    long countByStatus(String status);

    List<Appointment> findByStatus(String status);

    // Counts scheduled appointments for a specific time range (today)
    @Query("SELECT COUNT(a) FROM Appointment a WHERE a.appointmentDate >= :startOfDay " +
           "AND a.appointmentDate < :endOfDay AND a.status = 'SCHEDULED'")
    long countTodaysAppointments(@Param("startOfDay") LocalDateTime startOfDay, 
                                 @Param("endOfDay") LocalDateTime endOfDay);
}