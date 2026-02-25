# Patient Dashboard & Frontend Features

This document outlines all the frontend features available to a Patient user within the Patient Management System. These features correspond to the views and components found in the `frontend/app/src/pages/patient` directory.

## 1. Patient Dashboard (`Dashboard.jsx`)
The main landing page for patients, providing an overview of their healthcare status and quick actions.
*   **Welcome Header:** Displays a personalized greeting with the patient's name and quick links to "My Appointments" and "View Records".
*   **Action Required Alerts:** High-visibility alerts for pending tasks, such as "Pending Lab Results" waiting for review.
*   **Upcoming Appointments Widget:** Compact, chronological view of the next three upcoming appointments, showing date, doctor's name, time, and visit type, with a quick action to reschedule.
*   **Recent Diagnoses Widget:** A compact list displaying recent medical diagnoses alongside severity badges (e.g., High, Moderate, Low).
*   **Active Medications Widget:** A sidebar view showing current active medications, dosage, frequency, refill warnings, and quick "Request Refill" buttons.
*   **Patient Support / Quick Help:** A dedicated section for 24/7 support providing "Contact Doctor" and "Symptom Checker" action buttons.

## 2. Appointments Management (`Appointments.jsx`)
*   **View Appointments:** A complete list of all past, upcoming, and cancelled healthcare appointments.
*   **Schedule & Reschedule:** Interface for patients to book new appointments with doctors or reschedule existing ones.

## 3. Medical History (`MedicalHistory.jsx`)
*   **Comprehensive Health Record:** A detailed view of the patient's medical events over time.
*   **Diagnoses & Treatments:** Detailed logs of past illnesses, diagnoses, treatments, and procedures provided.
*   **Critical Alerts:** Prominent "Critical Allergies Alert" section displaying any life-threatening or severe allergies the patient has.

## 4. Medications & Prescriptions (`Medications.jsx` & `Prescriptions.jsx`)
*   **My Medications Repository:** An exhaustive list of the patient's pharmacological history and current drug regimen.
*   **Refill Management:** Ability for the patient to manually "Request Refill" for running low or expiring medications.
*   **Safety Warnings:** "Potential Drug Interaction" alerts notifying the patient of overlapping medication side effects or contraindications.

## 5. Lab Results (`LabResults.jsx`)
*   **Result Tracking:** Allows patients to view the outcome of their completed lab tests and diagnostics.
*   **Trend Analysis:** Visual or comparative analysis for specific recurring lab metrics to track health progress over time.

## 6. Privacy & Consent Management (`ConsentManagement.jsx` & `GrantModifyConsent.jsx`)
*   **HIPAA Rights Overview:** Educational section detailing the patient's healthcare privacy rights under HIPAA.
*   **Consent Tracking Categories:** Categorized lists showing "Active Consents", "Pending Review", and "Withdrawn" consents.
*   **Grant & Modify Consent Flow:** A comprehensive step-by-step form for patients to configure their data-sharing preferences:
    *   *What would you like to consent to?* (Defining the scope of shared data).
    *   *When should this consent take effect?* (Start dates).
    *   *How long should this consent remain active?* (Expiration/duration).
    *   *Review of Privacy & Security Information.*
    *   *Digital Signature* for legal validation.
    *   Alerts for "Consent Successfully Submitted" or "Consent Successfully Withdrawn".

## 7. Patient Profile (`Profile.jsx`)
*   **Personal Information:** View and edit personal particulars, contact information, and demographic details.
*   **Account Settings:** Manage patient-specific preferences and display settings within the application.

tients (patient1@securehealth.com through patient10@securehealth.com):

Email: patient1@securehealth.com
Email: patient2@securehealth.com
... up to patient9@securehealth.com
Password (for all): Password123xyz!
Doctors:

Email: dr.smith@securehealth.com (Dr. Alice Smith)
Email: dr.jones@securehealth.com (Dr. Bob Jones)
Email: dr.davis@securehealth.com (Dr. Carol Davis)
Password (for all): Password123xyz!
Nurses:

Email: nurse.joy@securehealth.com (Nurse Joy)
Email: nurse.jack@securehealth.com (Nurse Jack)
Password (for all): Password123xyz!
Admins:

Email: admin.max@securehealth.com (Admin Max)
Password: Password123xyz!