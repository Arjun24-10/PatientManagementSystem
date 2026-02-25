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

      if (!response.ok) {
         const error = await response.json().catch(() => ({ message: 'Request failed' }));
         throw new Error(error.message || `HTTP error! status: ${response.status}`);
      }

      return await response.json();
   } catch (error) {
      console.error(`API Error [${endpoint}]:`, error);
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

   // Logout user
   logout: async () => {
      return apiCall('/auth/logout', {
         method: 'POST',
      });
   },

   // Get current user
   getCurrentUser: async () => {
      return apiCall('/auth/me', {
         method: 'GET',
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
      return apiCall('/patients', {
         method: 'GET',
      });
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

   // Delete patient
   delete: async (id) => {
      return apiCall(`/patients/${id}`, {
         method: 'DELETE',
      });
   },
};

// ============================================
// APPOINTMENT APIs
// ============================================

export const appointmentAPI = {
   // Get all appointments
   getAll: async () => {
      return apiCall('/appointments', {
         method: 'GET',
      });
   },

   // Get appointment by ID
   getById: async (id) => {
      return apiCall(`/appointments/${id}`, {
         method: 'GET',
      });
   },

   // Get appointments by patient ID
   getByPatient: async (patientId) => {
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
         }));
      }
      return data;
   },

   // Get appointments by doctor ID
   getByDoctor: async (doctorId) => {
      return apiCall(`/appointments/doctor/${doctorId}`, {
         method: 'GET',
      });
   },

   // Create new appointment
   create: async (appointmentData) => {
      return apiCall('/appointments', {
         method: 'POST',
         body: JSON.stringify(appointmentData),
      });
   },

   // Update appointment
   update: async (id, appointmentData) => {
      return apiCall(`/appointments/${id}`, {
         method: 'PUT',
         body: JSON.stringify(appointmentData),
      });
   },

   // Cancel appointment
   cancel: async (id) => {
      return apiCall(`/appointments/${id}/cancel`, {
         method: 'PUT',
      });
   },

   // Delete appointment
   delete: async (id) => {
      return apiCall(`/appointments/${id}`, {
         method: 'DELETE',
      });
   },
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

   // Get medical record by ID
   getById: async (id) => {
      return apiCall(`/medical-records/${id}`, {
         method: 'GET',
      });
   },

   // Create new medical record
   create: async (recordData) => {
      return apiCall('/medical-records', {
         method: 'POST',
         body: JSON.stringify(recordData),
      });
   },

   // Update medical record
   update: async (id, recordData) => {
      return apiCall(`/medical-records/${id}`, {
         method: 'PUT',
         body: JSON.stringify(recordData),
      });
   },

   // Delete medical record
   delete: async (id) => {
      return apiCall(`/medical-records/${id}`, {
         method: 'DELETE',
      });
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

   // Get prescription by ID
   getById: async (id) => {
      return apiCall(`/prescriptions/${id}`, {
         method: 'GET',
      });
   },

   // Create new prescription
   create: async (prescriptionData) => {
      return apiCall('/prescriptions', {
         method: 'POST',
         body: JSON.stringify(prescriptionData),
      });
   },

   // Update prescription
   update: async (id, prescriptionData) => {
      return apiCall(`/prescriptions/${id}`, {
         method: 'PUT',
         body: JSON.stringify(prescriptionData),
      });
   },

   // Delete prescription
   delete: async (id) => {
      return apiCall(`/prescriptions/${id}`, {
         method: 'DELETE',
      });
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

   // Get lab result by ID
   getById: async (id) => {
      return apiCall(`/lab-results/${id}`, {
         method: 'GET',
      });
   },

   // Create new lab result
   create: async (labResultData) => {
      return apiCall('/lab-results', {
         method: 'POST',
         body: JSON.stringify(labResultData),
      });
   },

   // Update lab result
   update: async (id, labResultData) => {
      return apiCall(`/lab-results/${id}`, {
         method: 'PUT',
         body: JSON.stringify(labResultData),
      });
   },

   // Delete lab result
   delete: async (id) => {
      return apiCall(`/lab-results/${id}`, {
         method: 'DELETE',
      });
   },
};

// ============================================
// DOCTOR APIs
// ============================================

export const doctorAPI = {
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

   // Get latest vital signs for a patient
   getLatest: async (patientId) => {
      const realId = await resolvePatientId(patientId);
      return apiCall(`/vital-signs/patient/${realId}/latest`, {
         method: 'GET',
      });
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

const api = {
   auth: authAPI,
   patients: patientAPI,
   appointments: appointmentAPI,
   medicalRecords: medicalRecordAPI,
   prescriptions: prescriptionAPI,
   labResults: labResultAPI,
   doctors: doctorAPI,
   vitalSigns: vitalSignsAPI,
};

export default api;
