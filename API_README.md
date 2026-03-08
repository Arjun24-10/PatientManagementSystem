## for registration
const registerUser = async (email, password, role) => {
  const response = await fetch("http://localhost:8081/api/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password, role }),
  });

  if (!response.ok) {
    throw new Error("Registration failed");
  }
  return await response.json(); // Returns User object
};

## for login
const loginUser = async (email, password) => {
  const response = await fetch("http://localhost:8081/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include", // CRITICAL: Allows browser to save the secure cookie
    body: JSON.stringify({ email, password }),
  });

  const data = await response.json();

  if (data.status === "OTP_REQUIRED") {
    console.log("OTP Required! Redirect to OTP screen.");
    return { status: "OTP_REQUIRED", email: email };
  } 
  
  if (data.accessToken) {
    console.log("Login Success! Token:", data.accessToken);
    // TODO: Save accessToken to React Context or State
    return { status: "SUCCESS", token: data.accessToken, role: data.role };
  }

  throw new Error("Login failed");
};

## for otp
const verifyOtp = async (email, otpCode) => {
  const response = await fetch("http://localhost:8081/api/auth/verify-otp", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include", // CRITICAL: Sets the session cookie after OTP check
    body: JSON.stringify({ email, otp: otpCode }),
  });

  if (!response.ok) {
    throw new Error("Invalid OTP");
  }

  const data = await response.json();
  console.log("OTP Verified! Access Token:", data.accessToken);
  // TODO: Save accessToken to React Context or State
  return data;
};

## for logout
const logoutUser = async () => {
  await fetch("http://localhost:8081/api/auth/logout", {
    method: "POST",
    credentials: "include", // CRITICAL: Sends the cookie so server can delete it
  });

  console.log("Logged out successfully");
  // TODO: Clear accessToken from React State
};

## for enabling 2fa
const enableTwoFactorAuth = async (email) => {
  const response = await fetch("http://localhost:8081/api/auth/enable-2fa", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });

  if (!response.ok) {
    throw new Error("Failed to enable 2FA");
  }
  return await response.json();
};

GET /api/appointments/patient/{patientId} (Fetch a patient's appointments)

GET /api/appointments/doctor/{doctorId} (Fetch a doctor's schedule)

GET /api/appointments/doctor/{doctorId}/available-slots?date=YYYY-MM-DD (Get available time slots)

POST /api/appointments (Book a new appointment)

PUT /api/appointments/{id}/approve (Admin: Approve appointment)

PUT /api/appointments/{id}/reject (Admin: Reject appointment)

Module 2: Appointment Scheduling
Fetch Schedules & Available Slots
JavaScript

// Fetch all appointments for a patient (Roles: PATIENT, DOCTOR, ADMIN)
export const getPatientAppointments = async (patientId, token) => {
  const response = await fetch(`http://localhost:8081/api/appointments/patient/${patientId}`, {
    headers: { "Authorization": `Bearer ${token}` }
  });
  return await response.json();
};

// Fetch a doctor's schedule (Roles: DOCTOR, ADMIN)
export const getDoctorSchedule = async (doctorId, token) => {
  const response = await fetch(`http://localhost:8081/api/appointments/doctor/${doctorId}`, {
    headers: { "Authorization": `Bearer ${token}` }
  });
  return await response.json();
};

// Generate available calendar slots (e.g., "09:00:00")
export const getAvailableSlots = async (doctorId, dateString, token) => {
  const response = await fetch(`http://localhost:8081/api/appointments/doctor/${doctorId}/available-slots?date=${dateString}`, {
    headers: { "Authorization": `Bearer ${token}` }
  });
  return await response.json();
};

Booking & Approvals
JavaScript

// Book an open slot -> PENDING_APPROVAL (Roles: PATIENT)
export const bookAppointment = async (appointmentData, token) => {
  const response = await fetch("http://localhost:8081/api/appointments", {
    method: "POST",
    headers: { 
      "Content-Type": "application/json",
      "Authorization": `Bearer ${token}` 
    },
    body: JSON.stringify(appointmentData), // { doctorId, appointmentDate, reasonForVisit }
  });
  if (response.status === 409) throw new Error("Time slot already taken!");
  if (!response.ok) throw new Error("Failed to book appointment");
  return await response.json();
};

// Admin approves an appointment -> SCHEDULED (Roles: ADMIN)
export const approveAppointment = async (appointmentId, token) => {
  const response = await fetch(`http://localhost:8081/api/appointments/${appointmentId}/approve`, {
    method: "PUT",
    headers: { "Authorization": `Bearer ${token}` }
  });
  return await response.json();
};

// Admin rejects an appointment -> REJECTED (Roles: ADMIN)
export const rejectAppointment = async (appointmentId, reason, token) => {
  const response = await fetch(`http://localhost:8081/api/appointments/${appointmentId}/reject`, {
    method: "PUT",
    headers: { 
      "Content-Type": "text/plain",
      "Authorization": `Bearer ${token}` 
    },
    body: reason // Optional string
  });
  return await response.json();
};

Get Doctor's Unique Patients

Retrieves a distinct list of all patients assigned to a doctor.

    GET /doctors/{doctorId}/patients

    Allowed Roles: DOCTOR (Self), ADMIN

JavaScript

export const getPatientsByDoctor = async (doctorId, token) => {
  const response = await fetch(`http://localhost:8081/api/doctors/${doctorId}/patients`, {
    headers: { "Authorization": `Bearer ${token}` }
  });
  return await response.json();
};

Log Vital Signs & Lab Tests (Pre-Consultation)

    Allowed Roles: DOCTOR, ADMIN (or NURSE)

JavaScript

// Payload: { patientId, bloodPressure, heartRate, temperature, respiratoryRate, oxygenSaturation, weight, height }
export const addVitalSigns = async (vitalsData, token) => {
  const response = await fetch("http://localhost:8081/api/vital-signs", {
    method: "POST",
    headers: { 
      "Content-Type": "application/json",
      "Authorization": `Bearer ${token}` 
    },
    body: JSON.stringify(vitalsData),
  });
  return await response.json();
};

// Payload: { patientId, testName, testCategory, resultValue, unit, referenceRange, remarks }
export const addLabTest = async (labData, token) => {
  const response = await fetch("http://localhost:8081/api/lab-results", {
    method: "POST",
    headers: { 
      "Content-Type": "application/json",
      "Authorization": `Bearer ${token}` 
    },
    body: JSON.stringify(labData),
  });
  return await response.json();
};

Write Medical Records & Prescriptions (Consultation)

    Allowed Roles: DOCTOR (Only)

JavaScript

// Payload: { patientId, diagnosis, symptoms, treatmentProvided }
export const addMedicalRecord = async (recordData, token) => {
  const response = await fetch("http://localhost:8081/api/medical-records", {
    method: "POST",
    headers: { 
      "Content-Type": "application/json",
      "Authorization": `Bearer ${token}` 
    },
    body: JSON.stringify(recordData),
  });
  return await response.json();
};

// Payload: { patientId, medicationName, dosage, frequency, duration, specialInstructions }
export const addPrescription = async (prescriptionData, token) => {
  const response = await fetch("http://localhost:8081/api/prescriptions", {
    method: "POST",
    headers: { 
      "Content-Type": "application/json",
      "Authorization": `Bearer ${token}` 
    },
    body: JSON.stringify(prescriptionData),
  });
  return await response.json();
};