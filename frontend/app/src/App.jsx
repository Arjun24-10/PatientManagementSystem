import { Routes, Route } from 'react-router-dom';

import Login from './pages/login.jsx';
import CreateAccount from './pages/createAccount.jsx';
import TwoFactorAuth from './pages/TwoFactorAuth.jsx';
import ForgotPassword from './pages/ForgotPassword.jsx';
import ResetPassword from './pages/ResetPassword.jsx';

import DashboardLayout from './layouts/DashboardLayout.jsx';
import DoctorDashboard from './pages/doctor/Dashboard.jsx';
import PatientDetail from './pages/doctor/PatientDetail.jsx';
import Patients from './pages/doctor/Patients.jsx';
import DoctorAppointments from './pages/doctor/Appointments.jsx';
import DoctorProfile from './pages/doctor/Profile.jsx';
import PatientProfile from './pages/patient/Profile.jsx';
import NurseProfile from './pages/nurse/Profile.jsx';
import LabProfile from './pages/lab/Profile.jsx';
import AdminProfile from './pages/admin/Profile.jsx';

import DoctorMessages from './pages/doctor/Messages.jsx';
import DoctorLabResults from './pages/doctor/LabResults.jsx';
import DoctorPrescriptions from './pages/doctor/Prescriptions.jsx';
import DoctorReports from './pages/doctor/Reports.jsx';
import PatientDashboard from './pages/patient/Dashboard.jsx';
import PatientAppointments from './pages/patient/Appointments.jsx';
import PatientLabResults from './pages/patient/LabResults.jsx';
import PatientMedicalHistory from './pages/patient/MedicalHistory.jsx';
import PatientMedications from './pages/patient/Medications.jsx';
import PatientPrescriptions from './pages/patient/Prescriptions.jsx';
import ConsentManagement from './pages/patient/ConsentManagement.jsx';
import NurseDashboard from './pages/nurse/Dashboard.jsx';
import NurseVitals from './pages/nurse/Vitals.jsx';
import LabDashboard from './pages/lab/Dashboard.jsx';
import LabOrders from './pages/lab/Orders.jsx';
import LabOrderDetail from './pages/lab/OrderDetail.jsx';
import UploadResults from './pages/lab/UploadResults.jsx';
import LabHistory from './pages/lab/History.jsx';
// New Nurse Pages
import NursePatients from './pages/nurse/Patients.jsx';
import NursePatientDetail from './pages/nurse/PatientDetail.jsx';
import NurseVitalsEntry from './pages/nurse/VitalsEntry.jsx';
import NurseMedication from './pages/nurse/MedicationAdministration.jsx';
import NurseTasks from './pages/nurse/Tasks.jsx';
import NurseShiftHandover from './pages/nurse/ShiftHandover.jsx';
import AdminDashboard from './pages/admin/Dashboard.jsx';

function App() {
  return (
    <Routes>
      <Route path="/" element={<Login />} />
      <Route path="/login" element={<Login />} />
      <Route path="/create" element={<CreateAccount />} />
      <Route path="/verify-2fa" element={<TwoFactorAuth />} />
      <Route path="/forgot-password" element={<ForgotPassword />} />
      <Route path="/reset-password" element={<ResetPassword />} />

      {/* Doctor Dashboard */}
      <Route path="/dashboard/doctor/*" element={<DashboardLayout role="doctor" userName="Dr. Smith" />}>

        <Route path="" element={<DoctorDashboard />} />
        <Route path="patients" element={<Patients />} />
        <Route path="patient/:id" element={<PatientDetail />} />
        <Route path="appointments" element={<DoctorAppointments />} />
        <Route path="profile" element={<DoctorProfile />} />
        <Route path="messages" element={<DoctorMessages />} />
        <Route path="labs" element={<DoctorLabResults />} />
        <Route path="prescriptions" element={<DoctorPrescriptions />} />
        <Route path="reports" element={<DoctorReports />} />
      </Route>

      {/* Patient Dashboard */}
      <Route path="/dashboard/patient/*" element={<DashboardLayout role="patient" userName="John Doe" />}>
        <Route path="" element={<PatientDashboard />} />
        <Route path="appointments" element={<PatientAppointments />} />
        <Route path="profile" element={<PatientProfile />} />
        <Route path="labs" element={<PatientLabResults />} />
        <Route path="history" element={<PatientMedicalHistory />} />
        <Route path="medications" element={<PatientMedications />} />
        <Route path="prescriptions" element={<PatientPrescriptions />} />
        <Route path="consents" element={<ConsentManagement />} />
      </Route>

      {/* Nurse Dashboard */}
      <Route path="/dashboard/nurse/*" element={<DashboardLayout role="nurse" userName="Nurse Joy" />}>
        <Route path="" element={<NurseDashboard />} />
        <Route path="patients" element={<NursePatients />} />
        <Route path="patient/:id" element={<NursePatientDetail />} />
        <Route path="patient/:id/vitals" element={<NurseVitalsEntry />} />
        <Route path="patient/:id/medication" element={<NurseMedication />} />
        <Route path="vitals" element={<NurseVitals />} />
        <Route path="tasks" element={<NurseTasks />} />
        <Route path="shift-notes" element={<NurseShiftHandover />} />
        <Route path="profile" element={<NurseProfile />} />
      </Route>

      {/* Lab Dashboard */}
      <Route path="/dashboard/lab/*" element={<DashboardLayout role="lab" userName="Tech Mike" />}>
        <Route path="" element={<LabDashboard />} />
        <Route path="orders" element={<LabOrders />} />
        <Route path="orders/:id" element={<LabOrderDetail />} />
        <Route path="upload" element={<UploadResults />} />
        <Route path="history" element={<LabHistory />} />
        <Route path="profile" element={<LabProfile />} />
      </Route>

      {/* Admin Dashboard */}
      <Route path="/dashboard/admin/*" element={<DashboardLayout role="admin" userName="Admin User" />}>
        <Route path="" element={<AdminDashboard />} />
        <Route path="profile" element={<AdminProfile />} />
      </Route>
    </Routes>
  );
}

export default App;