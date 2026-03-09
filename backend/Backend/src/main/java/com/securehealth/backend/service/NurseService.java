package com.securehealth.backend.service;

import com.securehealth.backend.model.HandoverNote;
import com.securehealth.backend.model.Login;
import com.securehealth.backend.model.NurseTask;
import com.securehealth.backend.model.PatientProfile;
import com.securehealth.backend.repository.HandoverNoteRepository;
import com.securehealth.backend.repository.LoginRepository;
import com.securehealth.backend.repository.NurseTaskRepository;
import com.securehealth.backend.repository.PatientProfileRepository;
import com.securehealth.backend.repository.VitalSignRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
@Transactional
public class NurseService {

    @Autowired private LoginRepository loginRepository;
    @Autowired private PatientProfileRepository patientProfileRepository;
    @Autowired private NurseTaskRepository nurseTaskRepository;
    @Autowired private HandoverNoteRepository handoverNoteRepository;
    @Autowired private VitalSignRepository vitalSignRepository;

    private Login getAuthUser(String email) {
        return loginRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Nurse not found with email: " + email));
    }

    public Map<String, Object> getDashboardOverview(String nurseEmail) {
        Login nurse = getAuthUser(nurseEmail);
        Long nurseId = nurse.getUserId();

        // 1. Assigned Patients
        long assignedPatientsCount = patientProfileRepository.findByAssignedNurse(nurse).size();

        // 2. Pending Tasks
        long pendingTasks = nurseTaskRepository.countByAssignedNurse_UserIdAndCompletedFalse(nurseId);
        long overdueTasks = nurseTaskRepository.countByAssignedNurse_UserIdAndCompletedFalseAndDueTimeBefore(nurseId, LocalDateTime.now());
        long highPriorityTasks = nurseTaskRepository.countByAssignedNurse_UserIdAndCompletedFalseAndPriority(nurseId, "high");
        // 3. Vitals (Tracked as NurseTasks with category "vitals")
        long pendingVitals = nurseTaskRepository.countByAssignedNurse_UserIdAndCompletedFalseAndCategoryIgnoreCase(nurseId, "vitals");
        long overdueVitals = nurseTaskRepository.countByAssignedNurse_UserIdAndCompletedFalseAndCategoryIgnoreCaseAndDueTimeBefore(nurseId, "vitals", LocalDateTime.now());

        // 4. Medications (Tracked as NurseTasks with category "medication")
        long medicationsDue = nurseTaskRepository.countByAssignedNurse_UserIdAndCompletedFalseAndCategoryIgnoreCase(nurseId, "medication");
        long overdueMedications = nurseTaskRepository.countByAssignedNurse_UserIdAndCompletedFalseAndCategoryIgnoreCaseAndDueTimeBefore(nurseId, "medication", LocalDateTime.now());
        
        Optional<NurseTask> nextMed = nurseTaskRepository.findFirstByAssignedNurse_UserIdAndCompletedFalseAndCategoryIgnoreCaseOrderByDueTimeAsc(nurseId, "medication");
        long nextMedicationIn = -1; // -1 indicates no pending medications
        if (nextMed.isPresent() && nextMed.get().getDueTime().isAfter(LocalDateTime.now())) {
            nextMedicationIn = java.time.Duration.between(LocalDateTime.now(), nextMed.get().getDueTime()).toMinutes();
        } else if (nextMed.isPresent() && nextMed.get().getDueTime().isBefore(LocalDateTime.now())) {
            nextMedicationIn = 0; // It's overdue/due right now
        }

        Map<String, Object> stats = new HashMap<>();
        stats.put("assignedPatients", assignedPatientsCount);
        stats.put("pendingVitals", pendingVitals);
        stats.put("overdueVitals", overdueVitals);
        stats.put("medicationsDue", medicationsDue);
        stats.put("overdueMedications", overdueMedications);
        stats.put("nextMedicationIn", nextMedicationIn);
        stats.put("pendingTasks", pendingTasks);
        stats.put("overdueTasks", overdueTasks);
        stats.put("highPriorityTasks", highPriorityTasks);

        return stats;
    }

    public List<PatientProfile> getAssignedPatients(String nurseEmail) {
        Login nurse = getAuthUser(nurseEmail);
        return patientProfileRepository.findByAssignedNurse(nurse);
    }

    public List<NurseTask> getTasks(String nurseEmail) {
        Login nurse = getAuthUser(nurseEmail);
        return nurseTaskRepository.findByAssignedNurse_UserIdOrderByDueTimeAsc(nurse.getUserId());
    }

    public Map<String, Object> toggleTaskStatus(Long taskId, String nurseEmail) {
        Login nurse = getAuthUser(nurseEmail);
        NurseTask task = nurseTaskRepository.findById(taskId)
                .orElseThrow(() -> new RuntimeException("Task not found: " + taskId));

        if (!task.getAssignedNurse().getUserId().equals(nurse.getUserId())) {
            throw new RuntimeException("Not authorized to modify this task.");
        }

        task.setCompleted(!task.isCompleted());
        if (task.isCompleted()) {
            task.setPreviousStatus(task.getStatus());
            task.setStatus("completed");
        } else {
            task.setStatus(task.getPreviousStatus() != null ? task.getPreviousStatus() : "upcoming");
        }

        nurseTaskRepository.save(task);
        return Map.of("message", "Task toggled successfully.", "task", task);
    }

    public Map<String, Object> getHandoverNotes(String nurseEmail) {
        Login nurse = getAuthUser(nurseEmail);
        
        List<HandoverNote> fromPrevious = handoverNoteRepository.findByShiftDirectionOrderByTimestampDesc("FROM_PREVIOUS");
        List<HandoverNote> forNext = handoverNoteRepository.findByShiftDirectionOrderByTimestampDesc("FOR_NEXT");

        return Map.of(
                "fromPreviousShift", fromPrevious,
                "forNextShift", forNext
        );
    }

    public HandoverNote saveHandoverNote(Map<String, Object> payload, String nurseEmail) {
        Login nurse = getAuthUser(nurseEmail);
        
        HandoverNote note = new HandoverNote();
        note.setAuthor(nurse);
        note.setContent(payload.getOrDefault("content", "").toString());
        note.setType(payload.getOrDefault("type", "general").toString());
        note.setPriority(payload.getOrDefault("priority", "normal").toString());
        note.setShiftDirection(payload.getOrDefault("direction", "FOR_NEXT").toString());

        // Assuming patient ID is optionally passed
        if (payload.containsKey("patientId")) {
            Long patientId = Long.valueOf(payload.get("patientId").toString());
            PatientProfile patient = patientProfileRepository.findById(patientId).orElse(null);
            note.setPatient(patient);
        }

        return handoverNoteRepository.save(note);
    }
}
