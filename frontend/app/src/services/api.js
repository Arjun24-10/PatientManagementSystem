// API Service - Centralized API calls for the Patient Management System
const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8081/api';

// Helper function for API calls
const apiCall = async (endpoint, options = {}) => {
   // Retrieve access token from secure_health_user in localStorage
   const userDataStr = localStorage.getItem('secure_health_user');
   let accessToken = null;
   if (userDataStr) {
      try {
         const userSession = JSON.parse(userDataStr);
         accessToken = userSession.accessToken;
      } catch (e) {
         console.error('Failed to parse secure_health_user from localStorage', e);
      }
   }

   const headers = {
      'Content-Type': 'application/json',
      ...options.headers,
   };

   // Inject Authorization header if we have an accessToken
   if (accessToken) {
      headers['Authorization'] = `Bearer ${accessToken}`;
   }

   const config = {
      headers,
      credentials: 'include', // Include cookies for authentication
      ...options,
   };

   try {
      const response = await fetch(`${API_BASE_URL}${endpoint}`, config);

      if (response.status === 401 || response.status === 403) {
         if (endpoint !== '/auth/login' && endpoint !== '/auth/register') {
            console.warn('API returned 401/403. Checking if this is an expected error for doctor role.');

            // Get current user to check role
            const userDataStr = localStorage.getItem('secure_health_user');
            let userRole = null;
            if (userDataStr) {
               try {
                  const userSession = JSON.parse(userDataStr);
                  userRole = userSession?.role;
               } catch (e) { }
            }

            // Don't auto-logout for doctors accessing patient/appointment endpoints
            // These might not be properly implemented for doctor role yet
            const isDoctorEndpoint = (
               endpoint.includes('/patients') ||
               endpoint.includes('/appointments') ||
               endpoint.includes('/medical-records') ||
               endpoint.includes('/prescriptions') ||
               endpoint.includes('/lab-results') ||
               endpoint.includes('/vital-signs')
            );

            if (userRole === 'DOCTOR' && isDoctorEndpoint) {
               console.warn(`Doctor role accessing ${endpoint} - treating as not implemented rather than auth failure`);
               // Don't redirect to login, just throw an error that can be caught
               throw new Error(`This feature is not yet available for doctors. Please contact support.`);
            }

            // For other cases, proceed with logout
            console.warn('Genuine auth failure - redirecting to login');
            localStorage.removeItem('secure_health_user');
            window.location.href = '/login';
            throw new Error('Session expired. Please log in again.');
         }
      }

      // Handle missing endpoints gracefully (BACKEND NOT IMPLEMENTED YET)
      if (response.status === 404) {
         console.warn(`Endpoint ${endpoint} not yet implemented in backend`);

         // Return mock data for missing endpoints to prevent frontend crashes
         if (endpoint === '/auth/me') {
            return { id: 'P001', email: 'user@example.com', role: 'PATIENT' };
         }
         if (endpoint.includes('/appointments') && options.method === 'GET') {
            return [];
         }
         if (endpoint.includes('/medical-records') && options.method === 'GET') {
            return [];
         }
         if (endpoint.includes('/prescriptions') && options.method === 'GET') {
            return [];
         }
         if (endpoint.includes('/lab-results') && options.method === 'GET') {
            return [];
         }
         if (endpoint.includes('/vital-signs') && options.method === 'GET') {
            return [];
         }

         if (options.method === 'POST' || options.method === 'PUT' || options.method === 'DELETE') {
            throw new Error('This feature is not yet implemented. Please contact support.');
         }
      }

      if (!response.ok) {
         const error = await response.json().catch(() => ({ message: 'Request failed' }));
         throw new Error(error.message || `HTTP error! status: ${response.status}`);
      }

      return await response.json();
   } catch (error) {
      if (!error?.message?.includes('not yet available')) {
         console.error(`API Error [${endpoint}]:`, error);
      }
      throw error;
   }
};

// Helper: Many components fallback to 'P001' due to missing profile ID. Resolve it seamlessly.
let resolvedProfileIdCache = {};
const resolvePatientId = async (id) => {
   if (id !== 'P001' && id !== null && id !== undefined && !isNaN(id)) return id;

   // Check cache to avoid duplicate /patients/me calls
   const userDataStr = localStorage.getItem('secure_health_user');
   let userEmail = 'unknown';
   if (userDataStr) {
      try {
         const userSession = JSON.parse(userDataStr);
         if (userSession?.user?.email) userEmail = userSession.user.email;
      } catch (e) { }
   }

   if (resolvedProfileIdCache[userEmail]) {
      return resolvedProfileIdCache[userEmail];
   }

   try {
      const pData = await apiCall('/patients/me', { method: 'GET' });
      if (pData && pData.id) {
         resolvedProfileIdCache[userEmail] = pData.id;
         return pData.id;
      }
   } catch (e) {
      console.warn("Could not dynamically resolve patient profile ID.", e);
   }
   return id;
};

// ============================================
// AUTHENTICATION APIs
// ============================================

export const authAPI = {
   // Register a new user
   register: async (email, password, role = 'PATIENT') => {
      return apiCall('/auth/register', {
         method: 'POST',
         body: JSON.stringify({ email, password, role }),
      });
   },

   // Login user
   login: async (email, password) => {
      return apiCall('/auth/login', {
         method: 'POST',
         body: JSON.stringify({ email, password }),
      });
   },

   // Verify OTP for 2FA
   verifyOtp: async (email, otp) => {
      return apiCall('/auth/verify-otp', {
         method: 'POST',
         body: JSON.stringify({ email, otp }),
      });
   },

   // Forgot password
   forgotPassword: async (email) => {
      return apiCall('/auth/forgot-password', {
         method: 'POST',
         body: JSON.stringify({ email }),
      });
   },

   // Validate reset token
   validateResetToken: async (token) => {
      return apiCall(`/auth/validate-reset-token?token=${encodeURIComponent(token)}`, {
         method: 'GET',
      });
   },

   // Reset password
   resetPassword: async (token, newPassword, confirmPassword) => {
      return apiCall('/auth/reset-password', {
         method: 'POST',
         body: JSON.stringify({ token, newPassword, confirmPassword }),
      });
   },

   // Refresh token
   refreshToken: async () => {
      return apiCall('/auth/refresh-token', {
         method: 'POST',
      });
   },

   // Logout user
   logout: async () => {
      return apiCall('/auth/logout', {
         method: 'POST',
      });
   },

   // Get current user (BACKEND NOT IMPLEMENTED - RETURNS MOCK DATA)
   getCurrentUser: async () => {
      try {
         return apiCall('/auth/me', {
            method: 'GET',
         });
      } catch (error) {
         // Fallback to localStorage user data if endpoint doesn't exist
         const userDataStr = localStorage.getItem('secure_health_user');
         if (userDataStr) {
            try {
               const userSession = JSON.parse(userDataStr);
               return userSession.user || { id: 'unknown', email: 'unknown', role: 'PATIENT' };
            } catch (e) {
               console.error('Failed to parse user data from localStorage', e);
            }
         }
         throw error;
      }
   },

   // Enable 2FA
   enableTwoFactor: async (email) => {
      return apiCall('/auth/enable-2fa', {
         method: 'POST',
         body: JSON.stringify({ email }),
      });
   },
};

// ============================================
// PATIENT APIs
// ============================================

export const patientAPI = {
   // Get current patient profile
   getMe: async () => {
      const data = await apiCall('/patients/me', {
         method: 'GET',
      });
      if (data) {
         return {
            ...data,
            name: `${data.firstName || ''} ${data.lastName || ''}`.trim() || data.name,
         };
      }
      return data;
   },

   // Get all patients
   getAll: async () => {
      const data = await apiCall('/patients', {
         method: 'GET',
      });
      if (Array.isArray(data)) {
         return data.map(p => ({
            ...p,
            name: `${p.firstName || ''} ${p.lastName || ''}`.trim() || p.name || 'Unknown',
            id: p.id != null ? String(p.id) : '',
         }));
      }
      return data;
   },

   // Get patient by ID
   getById: async (id) => {
      return apiCall(`/patients/${id}`, {
         method: 'GET',
      });
   },

   // Create new patient
   create: async (patientData) => {
      return apiCall('/patients', {
         method: 'POST',
         body: JSON.stringify(patientData),
      });
   },

   // Update patient
   update: async (id, patientData) => {
      return apiCall(`/patients/${id}`, {
         method: 'PUT',
         body: JSON.stringify(patientData),
      });
   },

   // REMOVE DELETE FUNCTIONALITY FOR HEALTHCARE COMPLIANCE
   // Patient data should not be permanently deleted for legal and regulatory compliance
   // Instead, implement soft delete or data archival in backend if needed
   // delete: async (id) => {
   //    throw new Error('Patient data deletion is not permitted for healthcare compliance reasons.');
   // },
};

// ============================================
// APPOINTMENT APIs
// ============================================

export const appointmentAPI = {
   // Get available slots for a doctor on a specific date
   getAvailableSlots: async (doctorId, date) => {
      return apiCall(`/appointments/doctor/${doctorId}/available-slots?date=${date}`, {
         method: 'GET',
      });
   },

   // Get all appointments (DOCTOR and ADMIN only)
   getAll: async () => {
      const data = await apiCall('/appointments', {
         method: 'GET',
      });
      if (Array.isArray(data)) {
         return data.map(appt => ({
            ...appt,
            id: appt.appointmentId || appt.id,
            date: appt.appointmentDate ? appt.appointmentDate.split('T')[0] : appt.date,
            time: appt.appointmentDate ? appt.appointmentDate.split('T')[1]?.substring(0, 5) : appt.time,
            doctorName: appt.doctor?.email || appt.doctorName || 'Assigned Doctor',
            patientName: appt.patient
               ? `${appt.patient.firstName || ''} ${appt.patient.lastName || ''}`.trim()
               : appt.patientName || 'Patient',
            type: appt.reasonForVisit || appt.type,
            status: appt.status || 'PENDING',
         }));
      }
      return data;
   },

   // Get appointment by ID (NOT IN BACKEND)
   getById: async (id) => {
      console.warn('Get appointment by ID not implemented in backend');
      throw new Error('Appointment details view is not yet available. Please contact support.');
   },

   // Get appointments by patient ID
   getByPatient: async (patientId) => {
      try {
         const realId = await resolvePatientId(patientId);
         const data = await apiCall(`/appointments/patient/${realId}`, {
            method: 'GET',
         });
         if (Array.isArray(data)) {
            return data.map(appt => ({
               ...appt,
               id: appt.appointmentId || appt.id,
               date: appt.appointmentDate ? appt.appointmentDate.split('T')[0] : appt.date,
               time: appt.appointmentDate ? appt.appointmentDate.split('T')[1].substring(0, 5) : appt.time,
               doctorName: appt.doctor?.email || appt.doctorName || 'Assigned Doctor',
               type: appt.reasonForVisit || appt.type,
               status: appt.status || 'PENDING',
            }));
         }
         return data;
      } catch (error) {
         if (error.message.includes('not yet implemented')) {
            console.warn('Patient appointments API not yet implemented, returning empty array');
            return [];
         }
         throw error;
      }
   },

   // Get appointments by doctor ID
   getByDoctor: async (doctorId) => {
      const data = await apiCall(`/appointments/doctor/${doctorId}`, {
         method: 'GET',
      });
      if (Array.isArray(data)) {
         return data.map(appt => ({
            ...appt,
            id: appt.appointmentId || appt.id,
            date: appt.appointmentDate ? appt.appointmentDate.split('T')[0] : appt.date,
            time: appt.appointmentDate ? appt.appointmentDate.split('T')[1]?.substring(0, 5) : appt.time,
            patientName: appt.patient
               ? `${appt.patient.firstName || ''} ${appt.patient.lastName || ''}`.trim()
               : appt.patientName || 'Patient',
            type: appt.reasonForVisit || appt.type,
            status: appt.status || 'PENDING',
         }));
      }
      return data;
   },

   // Get appointments by date (NOT IN BACKEND - will return empty)
   getByDate: async (date) => {
      console.warn('Date-based appointments API not implemented in backend');
      return [];
   },

   // Get appointments by status (NOT IN BACKEND - will return empty)
   getByStatus: async (status) => {
      console.warn('Status-based appointments API not implemented in backend');
      return [];
   },

   // Get upcoming appointments (NOT IN BACKEND - use getByPatient with client-side filtering)
   getUpcoming: async (patientId) => {
      console.warn('Upcoming appointments API not in backend, using getByPatient instead');
      const appts = await appointmentAPI.getByPatient(patientId);
      const now = new Date();
      return appts.filter(a => new Date(a.date + ' ' + a.time) > now);
   },

   // Get appointment statistics (NOT IN BACKEND - return empty stats)
   getStats: async () => {
      console.warn('Appointment statistics API not implemented in backend');
      return {
         total: 0,
         pending: 0,
         approved: 0,
         completed: 0,
         cancelled: 0
      };
   },

   // Create new appointment
   create: async (appointmentData) => {
      return apiCall('/appointments', {
         method: 'POST',
         body: JSON.stringify(appointmentData),
      });
   },

   // Update appointment (DOCTOR only)
   update: async (id, appointmentData) => {
      return apiCall(`/appointments/${id}`, {
         method: 'PUT',
         body: JSON.stringify(appointmentData),
      });
   },

   // Approve appointment (BACKEND IMPLEMENTED)
   approve: async (id) => {
      return apiCall(`/appointments/${id}/approve`, {
         method: 'PUT',
      });
   },

   // Reject appointment (BACKEND IMPLEMENTED)
   reject: async (id, reason) => {
      return apiCall(`/appointments/${id}/reject`, {
         method: 'PUT',
         body: JSON.stringify({ reason }),
      });
   },

   // Cancel appointment (NOT IN BACKEND - use update with CANCELLED status)
   cancel: async (id, cancelReason) => {
      console.warn('Cancel endpoint not in backend, using update instead');
      return appointmentAPI.update(id, { status: 'CANCELLED', cancellationReason: cancelReason });
   },

   // Complete appointment (DOCTOR only)
   complete: async (id, notes) => {
      return apiCall(`/appointments/${id}/complete`, {
         method: 'PUT',
         body: JSON.stringify({ notes }),
      });
   },

   // Reschedule appointment (NOT IN BACKEND - use update)
   reschedule: async (id, newDate, newTime) => {
      console.warn('Reschedule endpoint not in backend, using update instead');
      return appointmentAPI.update(id, { appointmentDate: `${newDate}T${newTime}` });
   },

   // Check appointment conflicts (NOT IN BACKEND - return no conflict)
   checkConflicts: async (doctorId, date, time) => {
      console.warn('Appointment conflict checking not implemented in backend');
      return { hasConflict: false };
   },

   // REMOVE DELETE FUNCTIONALITY FOR COMPLIANCE
   // Healthcare data should not be permanently deleted
   // delete: async (id) => {
   //    throw new Error('Appointment deletion is not permitted for compliance reasons. Use cancel instead.');
   // },
};

// ============================================
// MEDICAL RECORD APIs
// ============================================

export const medicalRecordAPI = {
   // Get all medical records for a patient
   getByPatient: async (patientId) => {
      const realId = await resolvePatientId(patientId);
      const data = await apiCall(`/medical-records/patient/${realId}`, {
         method: 'GET',
      });
      if (Array.isArray(data)) {
         return data.map(record => ({
            ...record,
            id: record.recordId || record.id,
            name: record.diagnosis || record.name,
            date: record.createdAt ? record.createdAt.split('T')[0] : record.date,
            doctor: record.doctor?.email || record.doctor || 'Assigned Doctor',
            severity: 'Moderate', // Default severity since backend doesn't have it
         }));
      }
      return data;
   },

   // Get all medical records (NOT IN BACKEND)
   getAll: async () => {
      console.warn('getAll medical records not implemented in backend');
      return [];
   },

   // Get medical record by ID (NOT IN BACKEND)
   getById: async (id) => {
      console.warn('Get medical record by ID not implemented in backend');
      throw new Error('Medical record details not available.');
   },

   // Create new medical record
   create: async (recordData) => {
      return apiCall('/medical-records', {
         method: 'POST',
         body: JSON.stringify(recordData),
      });
   },

   // Update medical record (NOT IN BACKEND)
   update: async (id, recordData) => {
      console.warn('Update medical record not implemented in backend');
      throw new Error('Medical record updates not yet supported. Please contact support.');
   },

   // Delete medical record (NOT IN BACKEND)
   delete: async (id) => {
      console.warn('Delete medical record not implemented in backend');
      throw new Error('Medical record deletion not permitted for compliance reasons.');
   },
};

// ============================================
// PRESCRIPTION APIs
// ============================================

export const prescriptionAPI = {
   // Get all prescriptions for a patient
   getByPatient: async (patientId) => {
      const realId = await resolvePatientId(patientId);
      const data = await apiCall(`/prescriptions/patient/${realId}`, {
         method: 'GET',
      });
      if (Array.isArray(data)) {
         return data.map(rx => ({
            ...rx,
            id: rx.prescriptionId || rx.id,
            name: rx.medicationName || rx.name,
            active: rx.status === 'ACTIVE' || rx.active,
            date: rx.issuedAt ? rx.issuedAt.split('T')[0] : rx.date,
            doctorName: rx.doctor?.email || rx.doctorName || 'Assigned Doctor',
         }));
      }
      return data;
   },

   // Get all prescriptions (NOT IN BACKEND)
   getAll: async () => {
      console.warn('getAll prescriptions not implemented in backend');
      return [];
   },

   // Get prescription by ID (NOT IN BACKEND)
   getById: async (id) => {
      console.warn('Get prescription by ID not implemented in backend');
      throw new Error('Prescription details not available.');
   },

   // Create new prescription
   create: async (prescriptionData) => {
      return apiCall('/prescriptions', {
         method: 'POST',
         body: JSON.stringify(prescriptionData),
      });
   },

   // Update prescription (NOT IN BACKEND)
   update: async (id, prescriptionData) => {
      console.warn('Update prescription not implemented in backend');
      throw new Error('Prescription updates not yet supported. Please contact support.');
   },

   // Delete prescription (NOT IN BACKEND)
   delete: async (id) => {
      console.warn('Delete prescription not implemented in backend');
      throw new Error('Prescription deletion not permitted for compliance reasons.');
   },
};

// ============================================
// LAB RESULT APIs
// ============================================

export const labResultAPI = {
   // Get all lab results for a patient
   getByPatient: async (patientId) => {
      const realId = await resolvePatientId(patientId);
      const data = await apiCall(`/lab-results/patient/${realId}`, {
         method: 'GET',
      });
      if (Array.isArray(data)) {
         return data.map(lab => ({
            ...lab,
            id: lab.testId || lab.id,
            name: lab.testName || lab.name,
            type: lab.testName || lab.type,
            result: lab.resultData || lab.result,
            date: lab.orderedAt ? lab.orderedAt.split('T')[0] : lab.date,
         }));
      }
      return data;
   },

   // Get all lab results (NOT IN BACKEND)
   getAll: async () => {
      console.warn('getAll lab results not implemented in backend');
      return [];
   },

   // Get lab result by ID (NOT IN BACKEND)
   getById: async (id) => {
      console.warn('Get lab result by ID not implemented in backend');
      throw new Error('Lab result details not available.');
   },

   // Create new lab result
   create: async (labResultData) => {
      return apiCall('/lab-results', {
         method: 'POST',
         body: JSON.stringify(labResultData),
      });
   },

   // Update lab result (NOT IN BACKEND)
   update: async (id, labResultData) => {
      console.warn('Update lab result not implemented in backend');
      throw new Error('Lab result updates not yet supported. Please contact support.');
   },

   // Delete lab result (NOT IN BACKEND)
   delete: async (id) => {
      console.warn('Delete lab result not implemented in backend');
      throw new Error('Lab result deletion not permitted for compliance reasons.');
   },
};

// ============================================
// DOCTOR APIs
// ============================================

export const doctorAPI = {
   // Get patients associated with a doctor
   getPatientsByDoctor: async (doctorId) => {
      return apiCall(`/doctors/${doctorId}/patients`, {
         method: 'GET',
      });
   },

   // Get all doctors
   getAll: async () => {
      return apiCall('/doctors', {
         method: 'GET',
      });
   },

   // Get doctor by ID
   getById: async (id) => {
      return apiCall(`/doctors/${id}`, {
         method: 'GET',
      });
   },

   // Get doctor by specialty
   getBySpecialty: async (specialty) => {
      return apiCall(`/doctors/specialty/${specialty}`, {
         method: 'GET',
      });
   },

   // Update doctor profile
   update: async (id, doctorData) => {
      return apiCall(`/doctors/${id}`, {
         method: 'PUT',
         body: JSON.stringify(doctorData),
      });
   },
};

// ============================================
// VITAL SIGNS APIs
// ============================================

export const vitalSignsAPI = {
   // Get all vital signs for a patient
   getByPatient: async (patientId) => {
      const realId = await resolvePatientId(patientId);
      return apiCall(`/vital-signs/patient/${realId}`, {
         method: 'GET',
      });
   },

   // Get latest vital signs for a patient (NOT IN BACKEND)
   getLatest: async (patientId) => {
      const realId = await resolvePatientId(patientId);
      const allVitals = await apiCall(`/vital-signs/patient/${realId}`, {
         method: 'GET',
      });
      if (Array.isArray(allVitals) && allVitals.length > 0) {
         return allVitals[0]; // Assuming backend returns in descending order
      }
      return null;
   },

   // Create new vital signs record
   create: async (vitalSignsData) => {
      return apiCall('/vital-signs', {
         method: 'POST',
         body: JSON.stringify(vitalSignsData),
      });
   },

   // Update vital signs
   update: async (id, vitalSignsData) => {
      return apiCall(`/vital-signs/${id}`, {
         method: 'PUT',
         body: JSON.stringify(vitalSignsData),
      });
   },
};

// ============================================
// ADMIN AUDIT APIs
// ============================================

export const adminAuditAPI = {
   // Get all audit logs (admin only)
   getAllAuditLogs: async (params = {}) => {
      const query = new URLSearchParams(params).toString();
      return apiCall(`/admin/audit-logs${query ? `?${query}` : ''}`, {
         method: 'GET',
      });
   },

   // Get audit logs by user email
   getAuditLogsByUser: async (email, params = {}) => {
      const query = new URLSearchParams(params).toString();
      return apiCall(`/admin/audit-logs/${encodeURIComponent(email)}${query ? `?${query}` : ''}`, {
         method: 'GET',
      });
   },

   // Get system metrics
   getSystemMetrics: async () => {
      return apiCall('/admin/metrics', {
         method: 'GET',
      });
   },

   // Get user activity summary
   getUserActivity: async (timeframe = '24h') => {
      return apiCall(`/admin/user-activity?timeframe=${timeframe}`, {
         method: 'GET',
      });
   },

   // Get security events
   getSecurityEvents: async (params = {}) => {
      const query = new URLSearchParams(params).toString();
      return apiCall(`/admin/security-events${query ? `?${query}` : ''}`, {
         method: 'GET',
      });
   },

   // Generate audit report
   generateReport: async (params = {}) => {
      return apiCall('/admin/audit-report', {
         method: 'POST',
         body: JSON.stringify(params),
      });
   },
};

const api = {
   auth: authAPI,
   patients: patientAPI,
   appointments: appointmentAPI,
   medicalRecords: medicalRecordAPI,
   prescriptions: prescriptionAPI,
   labResults: labResultAPI,
   doctors: doctorAPI,
   vitalSigns: vitalSignsAPI,
   admin: adminAuditAPI,
};

export default api;
