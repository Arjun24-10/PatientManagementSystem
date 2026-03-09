# Nurse Integration Issues - Backend Only
**Last Updated**: March 9, 2026  
**Severity Level**: 🔴 CRITICAL - Vital Signs Cannot Be Recorded

---

## Executive Summary

The Nurse role has **critical backend gaps** preventing vital signs from being submitted and stored. Frontend pages exist but lack corresponding backend endpoints. **BLOCKER FOR PRODUCTION**.

---

## 🔴 CRITICAL ISSUES

### ISSUE #NB1: No Endpoint to Submit Vital Signs
**Severity**: CRITICAL (Core Function Missing)  
**Status**: NOT YET FIXED  
**Impact**: Nurses cannot record patient vital signs; data cannot persist

#### Frontend Requirement
**nurse/Vitals.jsx** (Lines 250-300):
```javascript
const handleVitalsSubmit = () => {
    // Form data exists: systolic, diastolic, heartRate, temperature, etc.
    // BUT no API call to submit
    // Only displays in local state
    setVitalsForm(...);
};
```

#### Backend Missing
NurseController has NO endpoint like:
```java
// ❌ MISSING: No way to submit vital signs
@PostMapping("/vitals")
public ResponseEntity<?> submitVitalSigns(
    @RequestBody VitalSignRequest request,
    Authentication authentication) {
    // Not implemented
}
```

#### What Backend Needs
```java
@RestController
@RequestMapping("/api/nurse")
@PreAuthorize("hasAuthority('NURSE')")
@CrossOrigin(origins = "http://localhost:3000")
public class NurseController {
    
    // ✅ ADD THIS ENDPOINT
    @PostMapping("/vitals")
    public ResponseEntity<?> recordVitalSigns(
        @RequestBody @Valid VitalSignRequest request,
        Authentication authentication) {
        try {
            // Extract nurse ID from authentication
            Long nurseId = getCurrentUserId(authentication);
            
            // Validate patient assigned to this nurse
            if (!isPatientAssigned(request.getPatientId(), nurseId)) {
                return ResponseEntity.status(403).body("Patient not assigned");
            }
            
            // Save vital signs
            VitalSign saved = vitalSignService.create(request);
            
            // Log audit trail
            auditLogService.log(
                nurseId,
                "VITALS_RECORDED",
                "Recorded vitals for patient",
                request.getPatientId(),
                AuditLogLevel.INFO
            );
            
            return ResponseEntity.status(201).body(saved);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}
```

#### Frontend Will Call
```javascript
// After this endpoint is created, add to api.js:
nurse: {
    recordVitals: async (vitalData) => {
        return apiCall('/nurse/vitals', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(vitalData),
        });
    },
}
```

---

### ISSUE #NB2: No Endpoint to Fetch Patient Vital Signs History
**Severity**: CRITICAL  
**Status**: NOT YET FIXED  
**Impact**: Nurse cannot view patient's vital signs trends

#### Frontend Requirement
**nurse/Vitals.jsx** needs to load historical vital signs:
```javascript
useEffect(() => {
    // ❌ No endpoint to fetch vitals for a patient
    fetchVitalSigns(patientId);
}, [patientId]);
```

#### Backend Missing
```java
// ❌ MISSING: NurseController should have:
@GetMapping("/vitals/patient/{patientId}")
public ResponseEntity<?> getPatientVitals(
    @PathVariable Long patientId,
    Authentication authentication) {
    // Get last N vital signs for patient
    // Verify patient is assigned to this nurse
}

// ❌ MISSING: Get latest vital signs only
@GetMapping("/vitals/patient/{patientId}/latest")
public ResponseEntity<?> getLatestVitals(@PathVariable Long patientId) {
    // Return most recent vital sign entry
}
```

#### Implementation Pattern
```java
@GetMapping("/vitals/patient/{patientId}")
public ResponseEntity<?> getPatientVitals(
    @PathVariable Long patientId,
    @RequestParam(defaultValue = "24") int hours,
    Authentication authentication) {
    try {
        Long nurseId = getCurrentUserId(authentication);
        
        // Verify access
        if (!isPatientAssigned(patientId, nurseId)) {
            return ResponseEntity.status(403).body("Access denied");
        }
        
        // Fetch vitals from last N hours, sorted DESC
        List<VitalSignDTO> vitals = vitalSignService.getByPatientLastHours(patientId, hours);
        return ResponseEntity.ok(vitals);
    } catch (Exception e) {
        return ResponseEntity.badRequest().body(e.getMessage());
    }
}
```

---

### ISSUE #NB3: No Endpoint to Record Medication Administration
**Severity**: CRITICAL  
**Status**: NOT YET FIXED  
**Impact**: Nurses cannot document medication given to patients

#### Frontend Requirement
**nurse/MedicationAdministration.jsx** (Line 35):
```javascript
const confirmAdministration = () => {
    // ❌ No API call; only updates local state
    setMedications(prev => prev.map(m =>
        m.id === selectedMed.id
            ? { ...m, status: 'administered', administeredTime: timestamp }
            : m
    ));
};
```

#### Backend Missing
```java
// ❌ COMPLETELY MISSING: No medication administration tracking endpoint
@PostMapping("/medications/{medicationId}/administer")
public ResponseEntity<?> administeredMedication(
    @PathVariable Long medicationId,
    @RequestBody MedicationAdministrationRequest request,
    Authentication authentication) {
    // Record that medication was given to patient
    // Time, dose, route, nurse signature (authentication)
}
```

#### What Backend Needs
1. Fetch medications prescribed for patient:
```java
@GetMapping("/medications/patient/{patientId}")
public ResponseEntity<?> getPatientMedications(@PathVariable Long patientId) {
    // Return: medications prescribed, dosage, schedule, status
}
```

2. Record medication administration:
```java
@PostMapping("/medications/{medicationId}/administer")
public ResponseEntity<?> recordAdministration(
    @PathVariable Long medicationId,
    @RequestBody MedicationAdministrationRequest request,
    Authentication authentication) {
    // Record: timestamp, nurse (from auth), actually given yes/no, reason if not given
}
```

3. Get medication administration history:
```java
@GetMapping("/medications/patient/{patientId}/history")
public ResponseEntity<?> getMedicationHistory(@PathVariable Long patientId) {
    // All medications given, not given, with timestamps and nurse names
}
```

---

### ISSUE #NB4: Missing @CrossOrigin on NurseController
**Severity**: CRITICAL (API Blocker)  
**Status**: NOT YET FIXED  
**Impact**: All nurse API calls from frontend will be blocked by CORS

#### Evidence
**NurseController.java** (Line 10):
```java
@RestController
@RequestMapping("/api/nurse")
@PreAuthorize("hasAuthority('NURSE')")
// ❌ NO @CrossOrigin ANNOTATION
public class NurseController {
```

#### Fix Required
```java
@CrossOrigin(origins = "http://localhost:3000",
            allowedMethods = {"GET", "POST", "PUT", "DELETE", "OPTIONS"},
            allowCredentials = "true",
            maxAge = 3600)
@RestController
@RequestMapping("/api/nurse")
@PreAuthorize("hasAuthority('NURSE')")
public class NurseController {
    // existing code
}
```

---

## 🟠 MAJOR ISSUES

### ISSUE #NB5: No Endpoint to Get Assigned Patients with Details
**Severity**: MAJOR  
**Status**: NOT YET FIXED  
**Impact**: Nurse dashboard shows empty list

#### Current Backend
```java
@GetMapping("/assigned-patients")
public ResponseEntity<?> getAssignedPatients(Authentication authentication) {
    // Returns what? Likely mock data or incomplete info
}
```

#### Frontend Requirement
**nurse/Patients.jsx** needs to load full patient list with:
- Patient name, age, gender
- Room and bed number
- Current diagnosis
- Vital signs status (done/due/overdue)
- Last vitals timestamp
- Patient status (stable/monitor/critical)

#### What Backend Returns Now
Unknown - likely incomplete. Should return:
```json
{
  "id": 1,
  "firstName": "John",
  "lastName": "Doe",
  "age": 45,
  "gender": "M",
  "room": "201",
  "bed": "A",
  "diagnosis": "Type 2 Diabetes",
  "vitalsDue": "12:00",
  "vitalsStatus": "overdue",
  "lastVitalsTime": "2026-03-09T10:00:00",
  "acuity": "stable",
  "medications": [
    {"name": "Metformin", "dosage": "500mg", "due": true, "dueTime": "14:00"}
  ]
}
```

#### Fix Required
Implement comprehensive endpoint:
```java
@GetMapping("/assigned-patients")
public ResponseEntity<?> getAssignedPatients(
    @RequestParam(required = false, defaultValue = "all") String filter,
    Authentication authentication) {
    
    Long nurseId = getCurrentUserId(authentication);
    List<NursePatientDTO> patients = nurseService.getAssignedPatients(
        nurseId, 
        filter  // all, critical, needs-attention, stable
    );
    return ResponseEntity.ok(patients);
}
```

---

## 🟡 MODERATE ISSUES

### ISSUE #NB6: No Medication Administration History/Status Tracking
**Severity**: MODERATE  
**Status**: NOT YET FIXED  
**Impact**: Cannot verify if medications were actually given

#### Missing Models
Need database table:
```sql
CREATE TABLE medication_administration_log (
    id BIGSERIAL PRIMARY KEY,
    prescription_id BIGINT NOT NULL,
    patient_id BIGINT NOT NULL,
    nurse_id BIGINT NOT NULL,
    medication_name VARCHAR(255),
    dosage VARCHAR(50),
    route VARCHAR(50),
    scheduled_time TIMESTAMP,
    actual_time TIMESTAMP,
    given BOOLEAN,
    not_given_reason VARCHAR(500),
    signature_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    notes TEXT,
    FOREIGN KEY (prescription_id) REFERENCES prescriptions(id),
    FOREIGN KEY (patient_id) REFERENCES patient_profile(id),
    FOREIGN KEY (nurse_id) REFERENCES login(user_id)
);
```

#### Missing DTO
```java
@Data
public class MedicationAdministrationDTO {
    private Long id;
    private String medicationName;
    private String dosage;
    private String route;
    private LocalDateTime scheduledTime;
    private LocalDateTime actualTime;
    private Boolean given;
    private String notGivenReason;
    private String nurseName;
}
```

---

### ISSUE #NB7: Tasks Endpoint Returns Nothing/Not Implemented
**Severity**: MODERATE  
**Status**: NOT YET FIXED  
**Impact**: Nurse task list is empty

#### Backend
```java
@GetMapping("/tasks")
public ResponseEntity<?> getTasks(Authentication authentication) {
    try {
        return ResponseEntity.ok(nurseService.getTasks(authentication.getName()));
    } catch (RuntimeException e) {
        return ResponseEntity.badRequest().body(e.getMessage());
    }
}
```

But NurseService implementation likely returns mock or empty.

#### Tasks Should Include
- Vital signs due for patients
- Medication administration due
- Wound assessments due
- Patient care tasks (bed change, etc.)
- Shift-specific assignments

---

### ISSUE #NB8: No Validation on Vital Signs Data
**Severity**: MODERATE  
**Status**: NOT YET FIXED  
**Impact**: Invalid vital signs can be recorded

#### VitalSignRequest Missing Validation
```java
@Data
public class VitalSignRequest {
    // ❌ No validation annotations
    private Long patientId;
    private String bloodPressure;
    private Integer heartRate;
    private Double temperature;
    private Integer respiratoryRate;
    private Integer oxygenSaturation;
}
```

#### Should Have
```java
@Data
public class VitalSignRequest {
    @NotNull(message = "Patient ID is required")
    private Long patientId;
    
    @NotBlank(message = "Blood pressure is required")
    @Pattern(regexp = "\\d{2,3}/\\d{2,3}", message = "BP format: XXX/YY")
    private String bloodPressure;  // "120/80"
    
    @NotNull(message = "Heart rate is required")
    @Min(value = 20, message = "Heart rate must be >= 20")
    @Max(value = 200, message = "Heart rate must be <= 200")
    private Integer heartRate;
    
    @NotNull(message = "Temperature is required")
    @DecimalMin(value = "95.0", message = "Temperature too low")
    @DecimalMax(value = "105.0", message = "Temperature too high")
    private Double temperature;
    
    @NotNull(message = "Respiratory rate is required")
    @Min(value = 8, message = "RR must be >= 8")
    @Max(value = 40, message = "RR must be <= 40")
    private Integer respiratoryRate;
    
    @NotNull(message = "Oxygen saturation is required")
    @Min(value = 70, message = "O2 sat must be >= 70")
    @Max(value = 100, message = "O2 sat must be <= 100")
    private Integer oxygenSaturation;
}
```

---

## 📋 Recommended Fix Priority

### Phase 1 (Blockers)
1. ✅ Add @CrossOrigin to NurseController (NB4)
2. ✅ Implement POST /nurse/vitals endpoint (NB1)
3. ✅ Implement GET /nurse/vitals/patient/{patientId} endpoints (NB2)

### Phase 2 (Core Features)
4. ✅ Implement medication recording endpoints (NB3)
5. ✅ Implement comprehensive patient list endpoint (NB5)
6. ✅ Implement /nurse/tasks endpoint (NB7)

### Phase 3 (Quality)
7. ✅ Add validation to VitalSignRequest (NB8)
8. ✅ Implement medication administration tracking (NB6)

---

## Summary Statistics

| Type | Count |
|------|-------|
| Critical Issues | 4 |
| Major Issues | 2 |
| Moderate Issues | 2 |
| Total Issues | 8 |
| Missing Endpoints | 7+ |
| Missing Tables | 1 |
| Missing DTOs | 2 |

**Status**: 🔴 **PRODUCTION NOT READY** - Vital signs workflow completely non-functional; critical backend endpoints missing.
