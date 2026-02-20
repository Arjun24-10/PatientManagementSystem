package com.securehealth.backend.repository;

import com.securehealth.backend.model.Appointment;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AppointmentRepository extends JpaRepository<Appointment, Long> {

    // Frontend: GET /appointments/patient/:patientId
    List<Appointment> findByPatient_ProfileIdOrderByAppointmentDateDesc(Long patientId);

    // Frontend: GET /appointments/doctor/:doctorId
    // Note: Doctor is linked via the Login entity, whose ID is 'userId'
    List<Appointment> findByDoctor_UserIdOrderByAppointmentDateAsc(Long doctorId);
}