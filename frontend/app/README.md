# Secure Healthcare Platform - Frontend (Phase 1)

This project contains the UI implementation for the secure healthcare platform, featuring role-based dashboards for Doctors and Patients (Parents).

## 🚀 Getting Started

### Prerequisites
- Node.js (v18+)
- npm

### Installation
1. Navigate to the app directory:
   ```bash
   cd app
   ```
2. Install dependencies:
   ```bash
   npm install
   npm install lucide-react
   ```
3. Start the development server:
   ```bash
   npm start
   ```

## 🖥️ Dashboard Access

Since authentication is currently a placeholder, you can directly access the dashboards via these URLs:

| Role | URL Route | Features Implemented |
|------|-----------|----------------------|
| **Doctor** | `/dashboard/doctor` | Patient Search, Patient Detail View, Prescriptions, Treatment Mgmt, Notifications |
| **Parent** | `/dashboard/parent` | Child Profiles, Medical History, Appointments, Consent Mgmt |
| **Nurse** | `/dashboard/nurse` | *Placeholder* |
| **Lab** | `/dashboard/lab` | *Placeholder* |
| **Admin** | `/dashboard/admin` | *Placeholder* |

## 📂 Project Structure

```
src/
├── components/
│   └── common/         # Shared UI (Button, Card, Modal, Alert, Badge)
├── layouts/            # DashboardLayout (Sidebar, Header)
├── mocks/              # Mock Data (Patients, Appointments, Records)
├── pages/
│   ├── doctor/         # Doctor Dashboard Views
│   │   ├── components/ # Doctor-specific components (PatientSearch, Notifications)
│   │   ├── Dashboard.jsx
│   │   └── PatientDetail.jsx
│   ├── parent/         # Parent Dashboard Views
│   │   ├── components/ # Parent-specific components (ConsentManager)
│   │   └── Dashboard.jsx
│   └── ...
└── App.jsx             # Routing Configuration
```

## 🛠️ Key Features (Phase 1)

### Doctor Dashboard
- **Patients Directory**: Searchable list of all patients on `/dashboard/doctor/patients`.
- **Appointments**: Manage schedule (Upcoming/History) on `/dashboard/doctor/appointments`.
- **Patient Search**: Quick lookup on the dashboard home.
- **Patient Detail**: Comprehensive view including Vitals, History, and Prescriptions.
- **Prescription Management**: UI for adding/deleting prescriptions (local state).
- **Notifications**: Alert panel for urgent updates.
- **Profile**: Doctor settings and availability toggle on `/dashboard/doctor/profile`.

### Patient/Parent Dashboard
- **Family Portal**: Managing multiple child profiles.
- **Consent Manager**: Toggle data sharing permissions.
- **Appointments**: View upcoming schedule.
- **Medical History**: Access and "download" past records.

## 🧪 Mock Data
The application uses local mock data located in `src/mocks/`. You can edit these files to test different data scenarios without a backend.

## 📡 API Reference

The following APIs are defined in the frontend services (`src/services/api.js`).

### Authentication
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/auth/register` | Register a new user |
| `POST` | `/api/auth/login` | Login user |
| `POST` | `/api/auth/logout` | Logout user |
| `GET` | `/api/auth/me` | Get current user |

### Patients
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/patients` | Get all patients |
| `GET` | `/api/patients/:id` | Get patient by ID |
| `POST` | `/api/patients` | Create new patient |
| `PUT` | `/api/patients/:id` | Update patient |
| `DELETE` | `/api/patients/:id` | Delete patient |

### Appointments
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/appointments` | Get all appointments |
| `GET` | `/api/appointments/:id` | Get appointment by ID |
| `GET` | `/api/appointments/patient/:patientId` | Get appointments by patient |
| `GET` | `/api/appointments/doctor/:doctorId` | Get appointments by doctor |
| `POST` | `/api/appointments` | Create new appointment |
| `PUT` | `/api/appointments/:id` | Update appointment |
| `PUT` | `/api/appointments/:id/cancel` | Cancel appointment |
| `DELETE` | `/api/appointments/:id` | Delete appointment |

### Medical Records
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/medical-records/:id` | Get medical record by ID |
| `GET` | `/api/medical-records/patient/:patientId` | Get records by patient |
| `POST` | `/api/medical-records` | Create new record |
| `PUT` | `/api/medical-records/:id` | Update record |
| `DELETE` | `/api/medical-records/:id` | Delete record |

### Prescriptions
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/prescriptions/:id` | Get prescription by ID |
| `GET` | `/api/prescriptions/patient/:patientId` | Get prescriptions by patient |
| `POST` | `/api/prescriptions` | Create new prescription |
| `PUT` | `/api/prescriptions/:id` | Update prescription |
| `DELETE` | `/api/prescriptions/:id` | Delete prescription |

### Lab Results
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/lab-results/:id` | Get lab result by ID |
| `GET` | `/api/lab-results/patient/:patientId` | Get results by patient |
| `POST` | `/api/lab-results` | Create new lab result |
| `PUT` | `/api/lab-results/:id` | Update lab result |
| `DELETE` | `/api/lab-results/:id` | Delete lab result |

### Doctors
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/doctors` | Get all doctors |
| `GET` | `/api/doctors/:id` | Get doctor by ID |
| `GET` | `/api/doctors/specialty/:specialty` | Get doctors by specialty |
| `PUT` | `/api/doctors/:id` | Update doctor profile |

### Vital Signs
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/vital-signs/patient/:patientId` | Get all vital signs for patient |
| `GET` | `/api/vital-signs/patient/:patientId/latest` | Get latest vital signs |
| `POST` | `/api/vital-signs` | Create vital signs record |
| `PUT` | `/api/vital-signs/:id` | Update vital signs |
