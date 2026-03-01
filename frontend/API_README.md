## Base URL
http://localhost:8081/api

## Register
fetch("http://localhost:8081/api/auth/register", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ email, password, role }),
});

## Login
fetch("http://localhost:8081/api/auth/login", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  credentials: "include",
  body: JSON.stringify({ email, password }),
});

## Verify OTP
fetch("http://localhost:8081/api/auth/verify-otp", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  credentials: "include",
  body: JSON.stringify({ email, otp }),
});

## Resend OTP
fetch("http://localhost:8081/api/auth/resend-otp", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ email }),
});

## Logout
fetch("http://localhost:8081/api/auth/logout", {
  method: "POST",
  credentials: "include",
});

## Authentication (`/auth`)
| Method | Endpoint | Description | Payload (JSON) |
|---|---|---|---|
| POST | `/auth/register` | Register a new user | `{ email, password, role, ...userData }` |
| POST | `/auth/login` | Login user | `{ email, password }` |
| POST | `/auth/logout` | Logout user | - |
| GET | `/auth/me` | Get current user profile | - |
| POST | `/auth/verify-otp` | Verify 2FA OTP | `{ email, otp }` |
| POST | `/auth/resend-otp` | Resend 2FA OTP | `{ email }` |
| POST | `/auth/forgot-password` | Request password reset | `{ email }` |
| GET | `/auth/validate-reset-token` | Validate reset token | Query param: `?token=...` |
| POST | `/auth/reset-password` | Reset password | `{ token, newPassword, confirmPassword }` |

## Patients (`/patients`)
| Method | Endpoint | Description | Payload |
|---|---|---|---|
| GET | `/patients` | Get all patients | - |
| GET | `/patients/:id` | Get patient by ID | - |
| POST | `/patients` | Create new patient | `{ ...patientData }` |
| PUT | `/patients/:id` | Update patient | `{ ...patientData }` |
| DELETE | `/patients/:id` | Delete patient | - |

## Appointments (`/appointments`)
| Method | Endpoint | Description | Payload |
|---|---|---|---|
| GET | `/appointments` | Get all appointments | - |
| GET | `/appointments/:id` | Get appointment by ID | - |
| GET | `/appointments/patient/:patientId` | Get by Patient ID | - |
| GET | `/appointments/doctor/:doctorId` | Get by Doctor ID | - |
| POST | `/appointments` | Create appointment | `{ ...appointmentData }` |
| PUT | `/appointments/:id` | Update appointment | `{ ...appointmentData }` |
| PUT | `/appointments/:id/cancel` | Cancel appointment | - |
| DELETE | `/appointments/:id` | Delete appointment | - |

## Medical Records (`/medical-records`)
| Method | Endpoint | Description | Payload |
|---|---|---|---|
| GET | `/medical-records` | Get all medical records | - |
| GET | `/medical-records/patient/:patientId` | Get all by Patient | - |
| GET | `/medical-records/:id` | Get record by ID | - |
| POST | `/medical-records` | Create record | `{ ...recordData }` |
| PUT | `/medical-records/:id` | Update record | `{ ...recordData }` |
| DELETE | `/medical-records/:id` | Delete record | - |

## Prescriptions (`/prescriptions`)
| Method | Endpoint | Description | Payload |
|---|---|---|---|
| GET | `/prescriptions` | Get all prescriptions | - |
| GET | `/prescriptions/patient/:patientId` | Get all by Patient | - |
| GET | `/prescriptions/:id` | Get prescription by ID | - |
| POST | `/prescriptions` | Create prescription | `{ ...prescriptionData }` |
| PUT | `/prescriptions/:id` | Update prescription | `{ ...prescriptionData }` |
| DELETE | `/prescriptions/:id` | Delete prescription | - |

## Lab Results (`/lab-results`)
| Method | Endpoint | Description | Payload |
|---|---|---|---|
| GET | `/lab-results` | Get all lab results | - |
| GET | `/lab-results/patient/:patientId` | Get all by Patient | - |
| GET | `/lab-results/:id` | Get result by ID | - |
| POST | `/lab-results` | Create result | `{ ...labResultData }` |
| PUT | `/lab-results/:id` | Update result | `{ ...labResultData }` |
| DELETE | `/lab-results/:id` | Delete result | - |

## Doctors (`/doctors`)
| Method | Endpoint | Description | Payload |
|---|---|---|---|
| GET | `/doctors` | Get all doctors | - |
| GET | `/doctors/:id` | Get doctor by ID | - |
| GET | `/doctors/specialty/:specialty` | Get by specialty | - |
| PUT | `/doctors/:id` | Update doctor profile | `{ ...doctorData }` |

## Vital Signs (`/vital-signs`)
| Method | Endpoint | Description | Payload |
|---|---|---|---|
| GET | `/vital-signs/patient/:patientId` | Get history by Patient | - |
| GET | `/vital-signs/patient/:patientId/latest` | Get latest by Patient | - |
| POST | `/vital-signs` | Record new vitals | `{ ...vitalSignsData }` |
| PUT | `/vital-signs/:id` | Update vitals entry | `{ ...vitalSignsData }` |
