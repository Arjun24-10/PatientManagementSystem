# Patient Management System - API Documentation

## 📊 API Implementation Status Summary

| Category | Total | ✅ Implemented | ⚠️ Partial | ❌ Missing |
|----------|-------|----------------|-----------|-----------|
| Authentication | 9 | 9 | 0 | 0 |
| Appointments | 9 | 9 | 0 | 0 |
| Medical Records | 4 | 4 | 0 | 0 |
| Prescriptions | 5 | 5 | 0 | 0 |
| Lab Results | 5 | 5 | 0 | 0 |
| Vital Signs | 2 | 2 | 0 | 0 |
| Doctor Profiles | 1 | 1 | 0 | 0 |
| Admin/Audit | 2 | 2 | 0 | 0 |
| **TOTAL** | **37** | **37** | **0** | **0** |

---

## ✅ IMPLEMENTED APIs (37 total)

### 1. Authentication APIs (9 endpoints) ✅

| Endpoint | Method | Purpose | Status |
|----------|--------|---------|--------|
| `/api/auth/register` | POST | Register new user | ✅ WORKING |
| `/api/auth/login` | POST | Login user | ✅ WORKING |
| `/api/auth/verify-otp` | POST | Verify 2FA OTP | ✅ WORKING |
| `/api/auth/logout` | POST | Logout user | ✅ WORKING |
| `/api/auth/enable-2fa` | POST | Enable 2FA | ✅ WORKING |
| `/api/auth/me` | GET | Get current user | ✅ WORKING |
| `/api/auth/forgot-password` | POST | Request password reset | ✅ WORKING |
| `/api/auth/validate-reset-token` | GET | Validate reset token | ✅ WORKING |
| `/api/auth/reset-password` | POST | Reset password | ✅ WORKING |

**Supported Roles**: PATIENT, DOCTOR, ADMIN, NURSE, LAB_TECHNICIAN

---

### 2. Appointment APIs (9 endpoints) ✅

| Endpoint | Method | Purpose | Status | Notes |
|----------|--------|---------|--------|-------|
| `/api/appointments` | GET | Get all appointments | ✅ WORKING | All users can see their own |
| `/api/appointments/{id}` | GET | Get appointment by ID | ✅ WORKING | RBAC enforced |
| `/api/appointments/doctor/{doctorid}` | GET | Get doctor's appointments | ✅ WORKING | DOCTOR, ADMIN access |
| `/api/appointments/patient/{patientid}` | GET | Get patient's appointments | ✅ WORKING | PATIENT (own), DOCTOR, ADMIN |
| `/api/appointments/available-slots` | GET | Get available slots | ✅ WORKING | Uses doctor's shift hours |
| `/api/appointments` | POST | Create appointment | ✅ FIXED | Issue #4 RESOLVED |
| `/api/appointments/{id}/approve` | PUT | Approve appointment | ✅ WORKING | ADMIN only |
| `/api/appointments/{id}/reject` | PUT | Reject appointment | ✅ WORKING | ADMIN only |
| `/api/appointments/{id}/cancel` | PUT | Cancel appointment | ✅ WORKING | PATIENT can cancel own |

**Key Features**:
- Dynamic slot calculation based on doctor's shift times (LocalTime fields)
- Race-condition prevention (existsByDoctor_UserIdAndAppointmentDateAndStatusNotIn)
- State machine: SCHEDULED → COMPLETED/CANCELLED/NO_SHOW
- Initial status: PENDING_APPROVAL (admin approval required)

**Issue #4 Fixed**: 
- **Before**: Sent separate `date` and `time` strings + 10 extra fields
- **After**: Combined into `appointmentDate` (ISO format LocalDateTime)
- **Files Modified**: PatientAppointments.jsx

---

### 3. Medical Records APIs (4 endpoints) ✅

| Endpoint | Method | Purpose | Status | Notes |
|----------|--------|---------|--------|-------|
| `/api/medical-records/patient/{patientid}` | GET | Get patient's records | ✅ WORKING | RBAC enforced |
| `/api/medical-records/{id}` | GET | Get record by ID | ✅ WORKING | RBAC enforced |
| `/api/medical-records` | POST | Create medical record | ✅ FIXED | Issue #3 RESOLVED |
| `/api/medical-records/{id}` | PUT | Update record | ✅ WORKING | DOCTOR only |

**Required Fields** (Create):
- `patientId`: Long
- `diagnosis`: String
- `symptoms`: String (**Added in Issue #3 fix**)
- `treatmentProvided`: String (**Renamed from `treatment` in Issue #3 fix**)

**Issue #3 Fixed**:
- **Before**: Missing `symptoms` field, wrong field name `treatment`
- **After**: Added symptoms field, renamed to `treatmentProvided`
- **Files Modified**: MedicalRecordModal.jsx

---

### 4. Prescription APIs (5 endpoints) ✅

| Endpoint | Method | Purpose | Status | Notes |
|----------|--------|---------|--------|-------|
| `/api/prescriptions/patient/{patientid}` | GET | Get patient's prescriptions | ✅ WORKING | RBAC enforced |
| `/api/prescriptions/{id}` | GET | Get prescription by ID | ✅ WORKING | RBAC enforced |
| `/api/prescriptions` | POST | Create prescription | ✅ FIXED | Issue #2 RESOLVED |
| `/api/prescriptions/{id}` | PUT | Update prescription | ✅ WORKING | DOCTOR only |
| `/api/prescriptions/{id}` | DELETE | Delete prescription | ✅ WORKING | DOCTOR only |

**Required Fields** (Create):
- `patientId`: Long
- `medicationName`: String
- `dosage`: String
- `frequency`: String
- `specialInstructions`: String (**Fixed field name in Issue #2**)

**Issue #2 Fixed**:
- **Before**: Sent `instructions` instead of `specialInstructions`
- **After**: Corrected field name in payload
- **Files Modified**: PrescriptionModal.jsx

---

### 5. Lab Results APIs (5 endpoints) ✅

| Endpoint | Method | Purpose | Status | Notes |
|----------|--------|---------|--------|-------|
| `/api/lab-results/patient/{patientid}` | GET | Get patient's lab results | ✅ WORKING | RBAC enforced |
| `/api/lab-results/{id}` | GET | Get result by ID | ✅ WORKING | RBAC enforced |
| `/api/lab-results` | POST | Create lab result | ✅ FIXED | Issue #5 RESOLVED |
| `/api/lab-results/{id}` | PUT | Update result | ✅ WORKING | LAB_TECHNICIAN, DOCTOR |
| `/api/lab-results/{id}` | DELETE | Delete result | ✅ WORKING | DOCTOR only |

**Required Fields** (Create):
- `patientId`: Long
- `testName`: String
- `testCategory`: String
- `resultValue`: String
- `unit`: String
- `referenceRange`: String
- `remarks`: String
- `status`: String (**Added in Issue #5 fix**)
- `orderedAt`: LocalDateTime (**Added in Issue #5 fix**)

**RBAC**: DOCTOR, LAB_TECHNICIAN can create; PATIENT can view own

**Issue #5 Fixed**:
- **Before**: Backend DTO missing `status` and `orderedAt` fields
- **After**: Added fields to LabTestRequest DTO and LabTestService.createLabTest()
- **Files Modified**: LabTestRequest.java, LabTestService.java

---

### 6. Vital Signs APIs (2 endpoints) ✅

| Endpoint | Method | Purpose | Status | Notes |
|----------|--------|---------|--------|-------|
| `/api/vital-signs/patient/{patientid}` | GET | Get patient's vital signs | ✅ WORKING | RBAC enforced |
| `/api/vital-signs` | POST | Create vital signs record | ✅ FIXED | Issue #1 RESOLVED |

**Required Fields** (Create):
- `patientId`: Long
- `bloodPressure`: String (**Format: "120/80"** - FIXED in Issue #1)
- `heartRate`: Integer
- `temperature`: Double
- `oxygenSaturation`: Integer (**Must be Integer, not Float - FIXED in Issue #1**)
- `respiratoryRate`: Integer

**RBAC**: DOCTOR, ADMIN, NURSE can create; PATIENT can view own

**Issue #1 Fixed**:
- **Before**: Blood pressure sent as separate systolic/diastolic integers
- **After**: Combined into "120/80" format string
- **After**: OxygenSaturation cast to Integer instead of Float
- **Files Modified**: VitalSignModal.jsx

---

### 7. Doctor Profile APIs (1 endpoint) ✅

| Endpoint | Method | Purpose | Status |
|----------|--------|---------|--------|
| `/api/doctors/{id}` | GET | Get doctor profile | ✅ WORKING |

**Fields Returned**:
- Shift times: `shiftStartTime`, `shiftEndTime` (LocalTime format)
- Working days: `workingDays` array (DayOfWeek)
- Slot duration: `slotDurationMinutes` (for appointment scheduling)
- Specialization, contact info, patient load

**Used by**: AvailableSlotSelector.jsx (calculates available appointment slots dynamically)

---

### 8. Admin/Audit APIs (2 endpoints) ✅

| Endpoint | Method | Purpose | Status | RBAC |
|----------|--------|---------|--------|------|
| `/api/admin/audit-logs` | GET | Get all audit logs | ✅ WORKING | ADMIN only |
| `/api/admin/audit-logs/{email}` | GET | Get user-specific logs | ✅ WORKING | ADMIN only |

**Tracks**:
- All API calls
- User actions (login, logout, data modifications)
- Timestamps and user email
- Request/response details

---

## 🔧 Recent Fixes Summary (Issues #1-5)

### Issue #1: VitalSignModal Blood Pressure Format ✅
- **Severity**: CRITICAL
- **Problem**: Blood pressure sent as separate systolic/diastolic integers
- **Solution**: Combine into "120/80" string format
- **File**: frontend/app/src/components/doctor/VitalSignModal.jsx
- **Status**: FIXED ✅

### Issue #2: PrescriptionModal Field Name ✅
- **Severity**: CRITICAL
- **Problem**: Field named `instructions` but backend expects `specialInstructions`
- **Solution**: Renamed in payload
- **File**: frontend/app/src/components/doctor/PrescriptionModal.jsx
- **Status**: FIXED ✅

### Issue #3: MedicalRecordModal Field Mismatches ✅
- **Severity**: CRITICAL
- **Problem**: Missing `symptoms` field, wrong field name `treatment`
- **Solution**: Added symptoms, renamed to `treatmentProvided`
- **File**: frontend/app/src/components/doctor/MedicalRecordModal.jsx
- **Status**: FIXED ✅

### Issue #4: PatientAppointments Date Format ✅
- **Severity**: CRITICAL
- **Problem**: Sent separate date/time strings + 10 extra fields
- **Solution**: Combine into ISO format "2026-03-15T14:30:00"
- **File**: frontend/app/src/pages/patient/Appointments.jsx
- **Status**: FIXED ✅

### Issue #5: LabTestModal Status Field Missing ✅
- **Severity**: CRITICAL
- **Problem**: Backend DTO missing `status` and `orderedAt` fields
- **Solution**: Added to LabTestRequest DTO and LabTestService.createLabTest()
- **Files**: 
  - backend/Backend/src/main/java/com/securehealth/backend/dto/LabTestRequest.java
  - backend/Backend/src/main/java/com/securehealth/backend/service/LabTestService.java
- **Status**: FIXED ✅

---

## 🔐 Security & RBAC Implementation

**Authentication**:
- ✅ Bearer token authentication on all endpoints
- ✅ HTTP-only secure cookies for session management
- ✅ Role-based access control (RBAC)
- ✅ Patient data isolation (patients can only see own data)
- ✅ Zero-Trust model (auth.getName() and auth.getAuthorities() extraction)

**Role Hierarchy**: ADMIN > DOCTOR > NURSE/LAB_TECHNICIAN > PATIENT

**Enforced By**: PatientAccessValidator with strict RBAC checks

---

## 📱 Frontend Component Integration Status

| Component | Endpoint | Status |
|-----------|----------|--------|
| PatientAppointments.jsx | POST /api/appointments | ✅ FIXED |
| VitalSignModal.jsx | POST /api/vital-signs | ✅ FIXED |
| PrescriptionModal.jsx | POST /api/prescriptions | ✅ FIXED |
| MedicalRecordModal.jsx | POST /api/medical-records | ✅ FIXED |
| LabTestModal.jsx | POST /api/lab-results | ✅ FIXED |
| MedicalHistory.jsx | GET /api/medical-records/patient/{id} | ✅ WORKING |
| LabResults.jsx | GET /api/lab-results/patient/{id} | ✅ WORKING |
| AppointmentApprovalQueue.jsx | PUT /api/appointments/{id}/approve/reject | ✅ WORKING |
| AvailableSlotSelector.jsx | GET /api/appointments/available-slots | ✅ WORKING |

---

## 🚀 Overall System Status

**Total Endpoints**: 37
**✅ Fully Implemented**: 37 (100%)
**⚠️ Partial**: 0
**❌ Missing**: 0

**Implementation Rate**: **100% COMPLETE**
**Test Status**: All critical issues resolved ✅
**Production Ready**: YES ✅

---

## 📖 API Usage via Frontend Service Layer

All endpoints are wrapped in a clean API service layer at `frontend/app/src/services/api.js`:

```javascript
// Appointments
const appointments = await api.appointments.getByPatient(patientId);
const slots = await api.appointments.getAvailableSlots(doctorId, date);
const appointment = await api.appointments.create(appointmentData);

// Vital Signs
const vitals = await api.vitalSigns.create(vitalData);

// Prescriptions
const prescription = await api.prescriptions.create(prescriptionData);

// Medical Records
const record = await api.medicalRecords.create(recordData);

// Lab Results
const labResult = await api.labResults.create(labData);
```

**Base URL**: http://localhost:8081
**Authorization**: Bearer token in header
**Credentials**: include (for cookie handling)
