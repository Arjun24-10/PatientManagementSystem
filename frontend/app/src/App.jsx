import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';

import { AuthProvider } from './contexts/AuthContext';
import Login from './pages/login.jsx';
import CreateAccount from './pages/createAccount.jsx';

import DashboardLayout from './layouts/DashboardLayout.jsx';
import DoctorDashboard from './pages/doctor/Dashboard.jsx';
import PatientDetail from './pages/doctor/PatientDetail.jsx';
import Patients from './pages/doctor/Patients.jsx';
import Appointments from './pages/doctor/Appointments.jsx';
import LabResults from './pages/doctor/LabResults.jsx';
import Prescriptions from './pages/doctor/Prescriptions.jsx';
import Reports from './pages/doctor/Reports.jsx';
import Messages from './pages/doctor/Messages.jsx';
import Profile from './pages/doctor/Profile.jsx';
import NurseDashboard from './pages/nurse/Dashboard.jsx';
import LabDashboard from './pages/lab/Dashboard.jsx';
import AdminDashboard from './pages/admin/Dashboard.jsx';
import PatientDashboard from './pages/patient/Dashboard.jsx';
import PatientAppointments from './pages/patient/Appointments.jsx';
import PatientMedicalHistory from './pages/patient/MedicalHistory.jsx';
import PatientLabResults from './pages/patient/LabResults.jsx';
import PatientMedications from './pages/patient/Medications.jsx';

function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/" element={<Navigate to="/login" replace />} />
          <Route path="/login" element={<Login />} />
          <Route path="/create" element={<CreateAccount />} />

          {/* Dashboards */}
          <Route path="/dashboard/doctor/*" element={<DashboardLayout role="doctor" userName="Dr. Smith" />}>
            <Route path="" element={<DoctorDashboard />} />
            <Route path="patients" element={<Patients />} />
            <Route path="patient/:id" element={<PatientDetail />} />
            <Route path="appointments" element={<Appointments />} />
            <Route path="labs" element={<LabResults />} />
            <Route path="prescriptions" element={<Prescriptions />} />
            <Route path="reports" element={<Reports />} />
            <Route path="messages" element={<Messages />} />
            <Route path="profile" element={<Profile />} />
          </Route>

          <Route path="/dashboard/patient/*" element={<DashboardLayout role="patient" userName="John Doe" />}>
            <Route path="" element={<PatientDashboard />} />
            <Route path="appointments" element={<PatientAppointments />} />
            <Route path="history" element={<PatientMedicalHistory />} />
            <Route path="labs" element={<PatientLabResults />} />
            <Route path="prescriptions" element={<PatientMedications />} />
          </Route>

          <Route path="/dashboard/nurse/*" element={<DashboardLayout role="nurse" userName="Nurse Joy" />}>
            <Route path="" element={<NurseDashboard />} />
          </Route>

          <Route path="/dashboard/lab/*" element={<DashboardLayout role="lab" userName="Tech Mike" />}>
            <Route path="" element={<LabDashboard />} />
          </Route>

          <Route path="/dashboard/admin/*" element={<DashboardLayout role="admin" userName="Admin User" />}>
            <Route path="" element={<AdminDashboard />} />
          </Route>
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}

export default App;