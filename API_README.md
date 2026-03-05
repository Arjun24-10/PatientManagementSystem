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

# Missing APIs: 
## for getting current user (MISSING - NEEDS BACKEND IMPLEMENTATION)
const getCurrentUser = async () => {
  const response = await fetch("http://localhost:8081/api/auth/me", {
    method: "GET",
    headers: { 
      "Content-Type": "application/json",
      "Authorization": `Bearer ${localStorage.getItem('accessToken')}`
    },
    credentials: "include",
  });

  if (!response.ok) {
    throw new Error("Failed to get current user");
  }
  return await response.json();
};

## for forgot password
const forgotPassword = async (email) => {
  const response = await fetch("http://localhost:8081/api/auth/forgot-password", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });

  if (!response.ok) {
    throw new Error("Failed to send password reset email");
  }
  return await response.json();
};

## for validating reset token
const validateResetToken = async (token) => {
  const response = await fetch(`http://localhost:8081/api/auth/validate-reset-token?token=${token}`, {
    method: "GET",
    headers: { "Content-Type": "application/json" },
  });

  if (!response.ok) {
    throw new Error("Invalid or expired token");
  }
  return await response.json();
};

## for resetting password
const resetPassword = async (token, newPassword, confirmPassword) => {
  const response = await fetch("http://localhost:8081/api/auth/reset-password", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token, newPassword, confirmPassword }),
  });

  if (!response.ok) {
    throw new Error("Failed to reset password");
  }
  return await response.json();
};

## for refresh token
const refreshToken = async () => {
  const response = await fetch("http://localhost:8081/api/auth/refresh-token", {
    method: "POST",
    credentials: "include",
  });

  if (!response.ok) {
    throw new Error("Failed to refresh token");
  }
  return await response.json();
};

// ============================================
// APPOINTMENT APIs (MISSING - NEEDS BACKEND IMPLEMENTATION)
// ============================================

## for getting all appointments
const getAllAppointments = async () => {
  const response = await fetch("http://localhost:8081/api/appointments", {
    method: "GET",
    headers: { 
      "Content-Type": "application/json",
      "Authorization": `Bearer ${localStorage.getItem('accessToken')}`
    },
    credentials: "include",
  });

  if (!response.ok) {
    throw new Error("Failed to fetch appointments");
  }
  return await response.json();
};

## for getting appointment by ID
const getAppointmentById = async (id) => {
  const response = await fetch(`http://localhost:8081/api/appointments/${id}`, {
    method: "GET",
    headers: { 
      "Content-Type": "application/json",
      "Authorization": `Bearer ${localStorage.getItem('accessToken')}`
    },
    credentials: "include",
  });

  if (!response.ok) {
    throw new Error("Failed to fetch appointment");
  }
  return await response.json();
};

## for getting appointments by doctor
const getAppointmentsByDoctor = async (doctorId) => {
  const response = await fetch(`http://localhost:8081/api/appointments/doctor/${doctorId}`, {
    method: "GET",
    headers: { 
      "Content-Type": "application/json",
      "Authorization": `Bearer ${localStorage.getItem('accessToken')}`
    },
    credentials: "include",
  });

  if (!response.ok) {
    throw new Error("Failed to fetch doctor appointments");
  }
  return await response.json();
};

## for creating appointment
const createAppointment = async (appointmentData) => {
  const response = await fetch("http://localhost:8081/api/appointments", {
    method: "POST",
    headers: { 
      "Content-Type": "application/json",
      "Authorization": `Bearer ${localStorage.getItem('accessToken')}`
    },
    credentials: "include",
    body: JSON.stringify(appointmentData),
  });

  if (!response.ok) {
    throw new Error("Failed to create appointment");
  }
  return await response.json();
};

## for updating appointment
const updateAppointment = async (id, appointmentData) => {
  const response = await fetch(`http://localhost:8081/api/appointments/${id}`, {
    method: "PUT",
    headers: { 
      "Content-Type": "application/json",
      "Authorization": `Bearer ${localStorage.getItem('accessToken')}`
    },
    credentials: "include",
    body: JSON.stringify(appointmentData),
  });

  if (!response.ok) {
    throw new Error("Failed to update appointment");
  }
  return await response.json();
};

## for canceling appointment
const cancelAppointment = async (id) => {
  const response = await fetch(`http://localhost:8081/api/appointments/${id}/cancel`, {
    method: "PUT",
    headers: { 
      "Content-Type": "application/json",
      "Authorization": `Bearer ${localStorage.getItem('accessToken')}`
    },
    credentials: "include",
  });

  if (!response.ok) {
    throw new Error("Failed to cancel appointment");
  }
  return await response.json();
};

## for deleting appointment
const deleteAppointment = async (id) => {
  const response = await fetch(`http://localhost:8081/api/appointments/${id}`, {
    method: "DELETE",
    headers: { 
      "Content-Type": "application/json",
      "Authorization": `Bearer ${localStorage.getItem('accessToken')}`
    },
    credentials: "include",
  });

  if (!response.ok) {
    throw new Error("Failed to delete appointment");
  }
  return await response.json();
};

// ============================================
// MEDICAL RECORDS APIs (MISSING - NEEDS BACKEND IMPLEMENTATION)
// ============================================

## for getting all medical records
const getAllMedicalRecords = async () => {
  const response = await fetch("http://localhost:8081/api/medical-records", {
    method: "GET",
    headers: { 
      "Content-Type": "application/json",
      "Authorization": `Bearer ${localStorage.getItem('accessToken')}`
    },
    credentials: "include",
  });

  if (!response.ok) {
    throw new Error("Failed to fetch medical records");
  }
  return await response.json();
};

## for getting medical record by ID
const getMedicalRecordById = async (id) => {
  const response = await fetch(`http://localhost:8081/api/medical-records/${id}`, {
    method: "GET",
    headers: { 
      "Content-Type": "application/json",
      "Authorization": `Bearer ${localStorage.getItem('accessToken')}`
    },
    credentials: "include",
  });

  if (!response.ok) {
    throw new Error("Failed to fetch medical record");
  }
  return await response.json();
};

## for updating medical record
const updateMedicalRecord = async (id, recordData) => {
  const response = await fetch(`http://localhost:8081/api/medical-records/${id}`, {
    method: "PUT",
    headers: { 
      "Content-Type": "application/json",
      "Authorization": `Bearer ${localStorage.getItem('accessToken')}`
    },
    credentials: "include",
    body: JSON.stringify(recordData),
  });

  if (!response.ok) {
    throw new Error("Failed to update medical record");
  }
  return await response.json();
};

## for soft deleting medical record (compliance-safe)
const softDeleteMedicalRecord = async (id) => {
  const response = await fetch(`http://localhost:8081/api/medical-records/${id}`, {
    method: "DELETE",
    headers: { 
      "Content-Type": "application/json",
      "Authorization": `Bearer ${localStorage.getItem('accessToken')}`
    },
    credentials: "include",
  });

  if (!response.ok) {
    throw new Error("Failed to archive medical record");
  }
  return await response.json();
};

// ============================================
// PRESCRIPTION APIs (MISSING - NEEDS BACKEND IMPLEMENTATION)
// ============================================

## for getting all prescriptions
const getAllPrescriptions = async () => {
  const response = await fetch("http://localhost:8081/api/prescriptions", {
    method: "GET",
    headers: { 
      "Content-Type": "application/json",
      "Authorization": `Bearer ${localStorage.getItem('accessToken')}`
    },
    credentials: "include",
  });

  if (!response.ok) {
    throw new Error("Failed to fetch prescriptions");
  }
  return await response.json();
};

## for getting prescription by ID
const getPrescriptionById = async (id) => {
  const response = await fetch(`http://localhost:8081/api/prescriptions/${id}`, {
    method: "GET",
    headers: { 
      "Content-Type": "application/json",
      "Authorization": `Bearer ${localStorage.getItem('accessToken')}`
    },
    credentials: "include",
  });

  if (!response.ok) {
    throw new Error("Failed to fetch prescription");
  }
  return await response.json();
};

## for updating prescription
const updatePrescription = async (id, prescriptionData) => {
  const response = await fetch(`http://localhost:8081/api/prescriptions/${id}`, {
    method: "PUT",
    headers: { 
      "Content-Type": "application/json",
      "Authorization": `Bearer ${localStorage.getItem('accessToken')}`
    },
    credentials: "include",
    body: JSON.stringify(prescriptionData),
  });

  if (!response.ok) {
    throw new Error("Failed to update prescription");
  }
  return await response.json();
};

## for deleting prescription
const deletePrescription = async (id) => {
  const response = await fetch(`http://localhost:8081/api/prescriptions/${id}`, {
    method: "DELETE",
    headers: { 
      "Content-Type": "application/json",
      "Authorization": `Bearer ${localStorage.getItem('accessToken')}`
    },
    credentials: "include",
  });

  if (!response.ok) {
    throw new Error("Failed to delete prescription");
  }
  return await response.json();
};

// ============================================
// LAB RESULTS APIs (MISSING - NEEDS BACKEND IMPLEMENTATION)
// ============================================

## for getting all lab results
const getAllLabResults = async () => {
  const response = await fetch("http://localhost:8081/api/lab-results", {
    method: "GET",
    headers: { 
      "Content-Type": "application/json",
      "Authorization": `Bearer ${localStorage.getItem('accessToken')}`
    },
    credentials: "include",
  });

  if (!response.ok) {
    throw new Error("Failed to fetch lab results");
  }
  return await response.json();
};

## for getting lab result by ID
const getLabResultById = async (id) => {
  const response = await fetch(`http://localhost:8081/api/lab-results/${id}`, {
    method: "GET",
    headers: { 
      "Content-Type": "application/json",
      "Authorization": `Bearer ${localStorage.getItem('accessToken')}`
    },
    credentials: "include",
  });

  if (!response.ok) {
    throw new Error("Failed to fetch lab result");
  }
  return await response.json();
};

## for updating lab result
const updateLabResult = async (id, labResultData) => {
  const response = await fetch(`http://localhost:8081/api/lab-results/${id}`, {
    method: "PUT",
    headers: { 
      "Content-Type": "application/json",
      "Authorization": `Bearer ${localStorage.getItem('accessToken')}`
    },
    credentials: "include",
    body: JSON.stringify(labResultData),
  });

  if (!response.ok) {
    throw new Error("Failed to update lab result");
  }
  return await response.json();
};

## for deleting lab result
const deleteLabResult = async (id) => {
  const response = await fetch(`http://localhost:8081/api/lab-results/${id}`, {
    method: "DELETE",
    headers: { 
      "Content-Type": "application/json",
      "Authorization": `Bearer ${localStorage.getItem('accessToken')}`
    },
    credentials: "include",
  });

  if (!response.ok) {
    throw new Error("Failed to delete lab result");
  }
  return await response.json();
};

// ============================================
// VITAL SIGNS APIs (MISSING - NEEDS BACKEND IMPLEMENTATION)
// ============================================

## for getting latest vital signs
const getLatestVitalSigns = async (patientId) => {
  const response = await fetch(`http://localhost:8081/api/vital-signs/patient/${patientId}/latest`, {
    method: "GET",
    headers: { 
      "Content-Type": "application/json",
      "Authorization": `Bearer ${localStorage.getItem('accessToken')}`
    },
    credentials: "include",
  });

  if (!response.ok) {
    throw new Error("Failed to fetch latest vital signs");
  }
  return await response.json();
};

## for updating vital signs
const updateVitalSigns = async (id, vitalSignsData) => {
  const response = await fetch(`http://localhost:8081/api/vital-signs/${id}`, {
    method: "PUT",
    headers: { 
      "Content-Type": "application/json",
      "Authorization": `Bearer ${localStorage.getItem('accessToken')}`
    },
    credentials: "include",
    body: JSON.stringify(vitalSignsData),
  });

  if (!response.ok) {
    throw new Error("Failed to update vital signs");
  }
  return await response.json();
};

// ============================================
// DOCTOR APIs (MISSING - NEEDS BACKEND IMPLEMENTATION)
// ============================================

## for updating doctor profile
const updateDoctorProfile = async (id, doctorData) => {
  const response = await fetch(`http://localhost:8081/api/doctors/${id}`, {
    method: "PUT",
    headers: { 
      "Content-Type": "application/json",
      "Authorization": `Bearer ${localStorage.getItem('accessToken')}`
    },
    credentials: "include",
    body: JSON.stringify(doctorData),
  });

  if (!response.ok) {
    throw new Error("Failed to update doctor profile");
  }
  return await response.json();
};

// ============================================
// ADMIN AUDIT APIs (EXISTING - DOCUMENTED FOR FRONTEND USE)
// ============================================

## for getting all audit logs (ADMIN ONLY)
const getAllAuditLogs = async () => {
  const response = await fetch("http://localhost:8081/api/admin/audit-logs", {
    method: "GET",
    headers: { 
      "Content-Type": "application/json",
      "Authorization": `Bearer ${localStorage.getItem('accessToken')}`
    },
    credentials: "include",
  });

  if (!response.ok) {
    throw new Error("Failed to fetch audit logs");
  }
  return await response.json();
};

## for getting user-specific audit logs (ADMIN ONLY)
const getUserAuditLogs = async (email) => {
  const response = await fetch(`http://localhost:8081/api/admin/audit-logs/${email}`, {
    method: "GET",
    headers: { 
      "Content-Type": "application/json",
      "Authorization": `Bearer ${localStorage.getItem('accessToken')}`
    },
    credentials: "include",
  });

  if (!response.ok) {
    throw new Error("Failed to fetch user audit logs");
  }
  return await response.json();
};