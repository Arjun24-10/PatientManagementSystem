# Secure Healthcare Platform - Frontend

This project contains the UI for the secure healthcare platform with role-based dashboards and authentication flows.

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

## 🖥️ Routes

Authentication routes:

| Route | Purpose |
|------|---------|
| `/login` | Login |
| `/create` | Create account |
| `/verify-2fa` | OTP verification |
| `/forgot-password` | Request password reset |
| `/reset-password` | Reset password |

Dashboard routes:

| Role | Base Route |
|------|------------|
| Doctor | `/dashboard/doctor` |
| Patient | `/dashboard/patient` |
| Nurse | `/dashboard/nurse` |
| Lab | `/dashboard/lab` |
| Admin | `/dashboard/admin` |

## 📂 Project Structure

```
src/
├── components/
│   ├── common/
│   └── doctor/
├── contexts/
├── layouts/
├── mocks/
├── pages/
│   ├── admin/
│   ├── doctor/
│   ├── lab/
│   ├── nurse/
│   ├── patient/
│   ├── ForgotPassword.jsx
│   ├── ResetPassword.jsx
│   ├── TwoFactorAuth.jsx
│   ├── createAccount.jsx
│   └── login.jsx
├── services/
│   ├── api.js
│   └── supabaseAuth.js
└── App.jsx
```

## 🛠️ Key Features

### Doctor Dashboard
- Patients directory, patient details, appointments, messages, labs, prescriptions, and reports.

### Patient Dashboard
- Appointments, labs, medical history, medications, and prescriptions.

### Nurse Dashboard
- Vitals overview and vitals log.

### Lab Dashboard
- Orders, upload results, and history.

### Admin Dashboard
- High-level administrative overview.

## 📡 API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/auth/register` | Register a new user |
| `POST` | `/api/auth/login` | Login user |
| `POST` | `/api/auth/verify-otp` | Verify OTP |
| `POST` | `/api/auth/resend-otp` | Resend OTP |
| `POST` | `/api/auth/forgot-password` | Request password reset |
| `GET` | `/api/auth/validate-reset-token` | Validate reset token |
| `POST` | `/api/auth/reset-password` | Reset password |
| `POST` | `/api/auth/logout` | Logout user |
