/**
 * Mock data for Grant/Modify Consent Interface
 * HIPAA-compliant consent form data structures
 */

// Research Consent Form Data
export const researchConsentForm = {
   consentId: "consent-research",
   category: "research",
   title: "Medical Research & Clinical Studies",
   icon: "FlaskConical",
   description: "Help advance medical knowledge by participating in research studies. Your participation is completely voluntary and will not affect your medical care.",
   whyNeeded: "Medical research leads to breakthrough treatments and cures. By consenting, you help doctors and scientists develop new ways to prevent, diagnose, and treat diseases that affect millions of people.",
   learnMore: [
      "Research using patient data has led to major advances in cancer treatment, heart disease prevention, and infectious disease control.",
      "All research studies are reviewed by an Institutional Review Board (IRB) to ensure patient safety and ethical standards.",
      "Your identity is protected through de-identification procedures that remove personal information from research datasets.",
      "You can withdraw your consent at any time without any impact on your healthcare."
   ],
   
   availableOptions: [
      {
         id: "research-data",
         title: "Share de-identified health records for medical research",
         description: "Allow anonymized data to be used in studies that improve healthcare. Your name and identifying information will be removed.",
         required: false,
         recommended: true,
         category: "data-sharing",
         expandedInfo: {
            whoReceives: "Approved medical researchers and institutions",
            howUsed: "Statistical analysis, treatment outcome studies, disease research",
            howToRevoke: "You can withdraw at any time through your consent dashboard"
         }
      },
      {
         id: "clinical-trials",
         title: "Contact me about clinical trial opportunities",
         description: "Receive information about clinical trials you may qualify for based on your health conditions.",
         required: false,
         recommended: false,
         category: "communication",
         expandedInfo: {
            whoReceives: "Clinical trial coordinators at this facility",
            howUsed: "Match your health profile with appropriate studies",
            howToRevoke: "Uncheck this option or contact research department"
         }
      },
      {
         id: "quality-improvement",
         title: "Include my data in quality improvement studies",
         description: "Help improve patient care quality and safety through internal quality reviews.",
         required: false,
         recommended: true,
         category: "data-sharing",
         expandedInfo: {
            whoReceives: "Hospital quality improvement team",
            howUsed: "Analyze care patterns, identify best practices, improve safety",
            howToRevoke: "Withdraw consent through your dashboard"
         }
      },
      {
         id: "genetic-research",
         title: "Share genomic/genetic data for research",
         description: "Allow genetic information to be used in research studies (fully anonymized).",
         required: false,
         recommended: false,
         category: "data-sharing",
         conditionalWarning: "This option requires genetic testing to be part of your care.",
         expandedInfo: {
            whoReceives: "Genetics researchers, biobanks",
            howUsed: "Study genetic factors in disease, develop new treatments",
            howToRevoke: "Withdraw consent - note that anonymized data cannot be retrieved"
         }
      },
      {
         id: "education",
         title: "Use my case for medical education",
         description: "Allow de-identified case information for teaching medical students and residents.",
         required: false,
         recommended: false,
         category: "education",
         expandedInfo: {
            whoReceives: "Medical students, residents, teaching faculty",
            howUsed: "Case presentations, educational conferences (fully de-identified)",
            howToRevoke: "Withdraw consent at any time"
         }
      }
   ]
};

// Health Information Exchange Consent Form Data
export const hieConsentForm = {
   consentId: "consent-hie",
   category: "hie",
   title: "Health Information Exchange (HIE)",
   icon: "Network",
   description: "Allow your health information to be shared securely with other healthcare providers through electronic health networks for better coordinated care.",
   whyNeeded: "When your healthcare providers can access your complete medical history, they can make better decisions, avoid duplicate tests, prevent medication errors, and provide faster care in emergencies.",
   learnMore: [
      "HIE uses secure, encrypted connections to share your health information between authorized providers.",
      "Only healthcare providers who are treating you can access your information through the HIE.",
      "Emergency rooms can access critical information even if you're unconscious, potentially saving your life.",
      "You control what information is shared and can opt out at any time."
   ],
   
   availableOptions: [
      {
         id: "hie-history",
         title: "Share medical history and diagnoses",
         description: "Essential for coordinated care across providers. Includes conditions, procedures, and allergies.",
         required: true,
         recommended: true,
         category: "core",
         expandedInfo: {
            whoReceives: "Healthcare providers treating you through networked facilities",
            howUsed: "Ensure continuity of care, prevent medical errors",
            howToRevoke: "This is required for HIE participation. Opt out of HIE entirely to prevent sharing."
         }
      },
      {
         id: "hie-medications",
         title: "Share medication lists and allergies",
         description: "Prevents dangerous drug interactions and allergic reactions by keeping all providers informed.",
         required: false,
         recommended: true,
         category: "safety",
         expandedInfo: {
            whoReceives: "All treating providers and pharmacies in the network",
            howUsed: "Medication reconciliation, allergy checks, interaction warnings",
            howToRevoke: "Uncheck this option in your consent settings"
         }
      },
      {
         id: "hie-labs",
         title: "Share lab and test results",
         description: "Reduces duplicate testing and helps providers see your complete health picture.",
         required: false,
         recommended: true,
         category: "data-sharing",
         expandedInfo: {
            whoReceives: "Treating providers requesting your lab history",
            howUsed: "Track trends, avoid unnecessary repeat tests, inform diagnoses",
            howToRevoke: "Uncheck this option in your consent settings"
         }
      },
      {
         id: "hie-imaging",
         title: "Share imaging results (X-rays, MRIs, etc.)",
         description: "Provides complete picture to specialists without requiring new scans.",
         required: false,
         recommended: true,
         category: "data-sharing",
         expandedInfo: {
            whoReceives: "Radiologists, specialists, and treating providers",
            howUsed: "Compare previous imaging, track changes, avoid radiation exposure from repeat scans",
            howToRevoke: "Uncheck this option in your consent settings"
         }
      },
      {
         id: "hie-immunizations",
         title: "Share immunization records",
         description: "Ensures up-to-date vaccination status across all your healthcare providers.",
         required: false,
         recommended: true,
         category: "data-sharing",
         expandedInfo: {
            whoReceives: "All treating providers, pharmacies, public health agencies",
            howUsed: "Track vaccination status, prevent duplicate vaccines, public health reporting",
            howToRevoke: "Uncheck this option in your consent settings"
         }
      },
      {
         id: "hie-mental-health",
         title: "Share mental health records",
         description: "Include behavioral health information in exchanges. Special protections apply.",
         required: false,
         recommended: false,
         category: "sensitive",
         conditionalWarning: "Mental health records have additional privacy protections under federal law. Consider carefully before enabling.",
         expandedInfo: {
            whoReceives: "Only providers you specifically authorize, with additional consent",
            howUsed: "Coordinate behavioral and physical health care",
            howToRevoke: "Uncheck this option - protections are immediate"
         }
      },
      {
         id: "hie-substance-abuse",
         title: "Share substance abuse treatment records",
         description: "Include addiction treatment information. 42 CFR Part 2 protections apply.",
         required: false,
         recommended: false,
         category: "sensitive",
         conditionalWarning: "Substance abuse records are protected under 42 CFR Part 2 and require specific consent.",
         expandedInfo: {
            whoReceives: "Only providers you specifically authorize in writing",
            howUsed: "Coordinate addiction treatment with other medical care",
            howToRevoke: "Revoke at any time - requires separate written revocation"
         }
      }
   ]
};

// Communications Consent Form Data
export const communicationsConsentForm = {
   consentId: "consent-communications",
   category: "communications",
   title: "Communication Preferences",
   icon: "Bell",
   description: "Choose how you'd like to receive health-related communications from our healthcare system.",
   whyNeeded: "Timely communication helps you stay on top of your health. We want to reach you in the way that's most convenient and effective for you.",
   learnMore: [
      "All communications are sent securely and follow HIPAA privacy guidelines.",
      "We never share your contact information with third parties for marketing purposes.",
      "You can update your preferences at any time.",
      "Some communications (like appointment confirmations) are essential and cannot be disabled."
   ],
   
   availableOptions: [
      {
         id: "comm-email-appointments",
         title: "Appointment reminders via email",
         description: "Receive email reminders about upcoming appointments.",
         required: false,
         recommended: true,
         category: "appointments",
         contactField: {
            type: "email",
            label: "Email address",
            value: "john.smith@email.com",
            editable: true
         },
         expandedInfo: {
            whoReceives: "Only you at the email address provided",
            howUsed: "Appointment reminders 24-48 hours before scheduled visits",
            howToRevoke: "Uncheck this option or update email preferences"
         }
      },
      {
         id: "comm-sms-appointments",
         title: "Appointment reminders via SMS/text",
         description: "Receive text message reminders about upcoming appointments.",
         required: false,
         recommended: true,
         category: "appointments",
         contactField: {
            type: "phone",
            label: "Mobile phone",
            value: "(555) 123-4567",
            editable: true
         },
         expandedInfo: {
            whoReceives: "Only you at the phone number provided",
            howUsed: "Brief text reminders 24-48 hours before appointments",
            howToRevoke: "Reply STOP to any message or uncheck this option"
         }
      },
      {
         id: "comm-test-results",
         title: "Test results notifications",
         description: "Notify when lab or imaging results are available in your portal.",
         required: false,
         recommended: true,
         category: "results",
         expandedInfo: {
            whoReceives: "You via email and/or portal notification",
            howUsed: "Alert when new results are ready for viewing",
            howToRevoke: "Uncheck this option"
         }
      },
      {
         id: "comm-refill-reminders",
         title: "Prescription refill reminders",
         description: "Alerts when medications need refilling based on fill dates.",
         required: false,
         recommended: true,
         category: "medications",
         expandedInfo: {
            whoReceives: "You via preferred contact method",
            howUsed: "Remind you when it's time to refill prescriptions",
            howToRevoke: "Uncheck this option"
         }
      },
      {
         id: "comm-preventive",
         title: "Preventive care reminders",
         description: "Annual checkup, screenings, and vaccination reminders based on your age and health history.",
         required: false,
         recommended: true,
         category: "preventive",
         expandedInfo: {
            whoReceives: "You via preferred contact method",
            howUsed: "Remind you of recommended screenings and preventive visits",
            howToRevoke: "Uncheck this option"
         }
      },
      {
         id: "comm-health-tips",
         title: "Health tips and wellness information",
         description: "Educational content about health topics relevant to you.",
         required: false,
         recommended: false,
         category: "education",
         expandedInfo: {
            whoReceives: "You via email",
            howUsed: "Share articles, tips, and resources for healthy living",
            howToRevoke: "Uncheck this option or unsubscribe from emails"
         }
      },
      {
         id: "comm-portal",
         title: "Portal notifications",
         description: "Receive notifications in your patient portal for messages and updates.",
         required: false,
         recommended: true,
         category: "portal",
         expandedInfo: {
            whoReceives: "Only visible when you log into the portal",
            howUsed: "Secure in-app notifications for all portal activity",
            howToRevoke: "Uncheck this option in notification settings"
         }
      },
      {
         id: "comm-phone",
         title: "Phone call reminders",
         description: "Receive phone call reminders for important appointments.",
         required: false,
         recommended: false,
         category: "appointments",
         contactField: {
            type: "phone",
            label: "Phone number",
            value: "(555) 123-4567",
            editable: true
         },
         expandedInfo: {
            whoReceives: "Only you at the phone number provided",
            howUsed: "Automated reminder calls for appointments",
            howToRevoke: "Uncheck this option"
         }
      }
   ]
};

// Family/Friends Sharing Consent Form Data
export const familySharingConsentForm = {
   consentId: "consent-family",
   category: "family-sharing",
   title: "Family & Authorized Access",
   icon: "Users",
   description: "Authorize family members or friends to access specific aspects of your health information or make decisions on your behalf.",
   whyNeeded: "Having trusted individuals who can access your health information or make healthcare decisions helps ensure you receive the care you need, especially during emergencies or when you're unable to communicate.",
   learnMore: [
      "You maintain full control over who can access your information and what they can see.",
      "Authorized persons must verify their identity before accessing any information.",
      "You can revoke access for any individual at any time.",
      "Different individuals can have different levels of access based on your preferences."
   ],
   
   authorizedPersons: [
      {
         id: "person-1",
         name: "Jane Smith",
         relationship: "Spouse",
         phone: "(555) 234-5678",
         email: "jane.smith@email.com",
         canEdit: true
      },
      {
         id: "person-2",
         name: "Robert Smith",
         relationship: "Son",
         phone: "(555) 345-6789",
         email: "robert.smith@email.com",
         canEdit: true
      }
   ],
   
   availablePermissions: [
      {
         id: "perm-health-status",
         title: "General health status updates",
         description: "Share general information about your health condition.",
         category: "information"
      },
      {
         id: "perm-diagnosis",
         title: "Diagnosis information",
         description: "Share specific diagnoses and medical conditions.",
         category: "information"
      },
      {
         id: "perm-treatment",
         title: "Treatment plans",
         description: "Share information about your treatment plans and medications.",
         category: "information"
      },
      {
         id: "perm-appointments",
         title: "Appointment scheduling",
         description: "Allow scheduling, rescheduling, or canceling appointments on your behalf.",
         category: "actions"
      },
      {
         id: "perm-billing",
         title: "Billing and insurance",
         description: "Access billing statements and communicate with insurance.",
         category: "financial"
      },
      {
         id: "perm-results",
         title: "Test results",
         description: "View lab and imaging results.",
         category: "information"
      },
      {
         id: "perm-emergency",
         title: "Emergency contact only",
         description: "Be contacted only in case of medical emergency.",
         category: "emergency"
      }
   ],
   
   // Default permissions for each authorized person
   personPermissions: {
      "person-1": ["perm-health-status", "perm-diagnosis", "perm-treatment", "perm-appointments", "perm-billing", "perm-results"],
      "person-2": ["perm-health-status", "perm-appointments", "perm-emergency"]
   }
};

// Privacy notices shared across all consent forms
export const privacyNotices = {
   rights: [
      "You can revoke this consent at any time without affecting your medical care",
      "Revoking consent doesn't affect information already shared under this authorization",
      "You have the right to request an accounting of all disclosures",
      "You can file a complaint with the hospital Privacy Officer or HHS if you believe your privacy rights were violated"
   ],
   protections: [
      "All data encrypted in transit and at rest using industry-standard AES-256 encryption",
      "Access limited to authorized personnel only based on role-based access controls",
      "All access to your information is logged in tamper-proof audit trails",
      "Strict security policies and regular training for all staff handling patient data",
      "Regular security audits and compliance monitoring"
   ],
   nextSteps: [
      "Your consent will be reviewed and processed within 24-48 hours",
      "You'll receive email confirmation once processed",
      "Changes may take time to propagate to all connected systems",
      "You can download a PDF copy of your signed consent anytime",
      "Consent becomes part of your permanent medical record"
   ]
};

// Required acknowledgments for all consent forms
export const requiredAcknowledgments = [
   {
      id: "understanding",
      text: "I have read and understand what I am consenting to",
      required: true
   },
   {
      id: "revocable",
      text: "I understand I can revoke this consent at any time",
      required: true
   },
   {
      id: "voluntary",
      text: "I am making this decision voluntarily without coercion",
      required: true
   },
   {
      id: "email-copy",
      text: "Send me a copy of this consent via email",
      required: false,
      defaultChecked: true
   },
   {
      id: "privacy-officer",
      text: "I would like to speak with a privacy officer before submitting",
      required: false,
      showsContact: true
   }
];

// Expiration options
export const expirationOptions = [
   { value: "none", label: "No expiration (until revoked)" },
   { value: "6-months", label: "6 months from effective date" },
   { value: "1-year", label: "1 year from effective date" },
   { value: "2-years", label: "2 years from effective date" },
   { value: "5-years", label: "5 years from effective date" },
   { value: "custom", label: "Custom date" }
];

// Consent history for the research consent
export const consentHistory = [
   {
      id: "history-1",
      consentId: "consent-research",
      timestamp: "2024-02-09T14:45:00",
      action: "modified",
      changedBy: {
         type: "patient",
         name: "John Smith"
      },
      changes: {
         added: ["genetic-research", "education"],
         removed: [],
         modified: []
      },
      reason: "Interested in contributing to genetic research",
      metadata: {
         ipAddress: "192.168.1.100",
         device: "Chrome 121 on Windows 10",
         consentVersion: "v2.1"
      },
      before: {
         selectedOptions: ["research-data", "clinical-trials", "quality-improvement"],
         effectiveDate: "2024-01-15"
      },
      after: {
         selectedOptions: ["research-data", "clinical-trials", "quality-improvement", "genetic-research", "education"],
         effectiveDate: "2024-02-09"
      }
   },
   {
      id: "history-2",
      consentId: "consent-research",
      timestamp: "2024-01-20T10:30:00",
      action: "modified",
      changedBy: {
         type: "patient",
         name: "John Smith"
      },
      changes: {
         added: ["quality-improvement"],
         removed: [],
         modified: []
      },
      reason: null,
      metadata: {
         ipAddress: "192.168.1.50",
         device: "Safari on iPhone",
         consentVersion: "v2.0"
      },
      before: {
         selectedOptions: ["research-data", "clinical-trials"],
         effectiveDate: "2024-01-15"
      },
      after: {
         selectedOptions: ["research-data", "clinical-trials", "quality-improvement"],
         effectiveDate: "2024-01-20"
      }
   },
   {
      id: "history-3",
      consentId: "consent-research",
      timestamp: "2024-01-15T09:00:00",
      action: "granted",
      changedBy: {
         type: "patient",
         name: "John Smith"
      },
      changes: {
         added: ["research-data", "clinical-trials"],
         removed: [],
         modified: []
      },
      reason: "Initial consent during registration",
      metadata: {
         ipAddress: "192.168.1.25",
         device: "Chrome 120 on Windows 10",
         consentVersion: "v1.0"
      },
      before: null,
      after: {
         selectedOptions: ["research-data", "clinical-trials"],
         effectiveDate: "2024-01-15"
      }
   }
];

// Helper function to get consent form by category
export const getConsentFormByCategory = (category) => {
   switch (category) {
      case 'research':
         return researchConsentForm;
      case 'hie':
         return hieConsentForm;
      case 'communications':
         return communicationsConsentForm;
      case 'family-sharing':
         return familySharingConsentForm;
      default:
         return null;
   }
};

// Helper function to get consent history by consent ID
export const getConsentHistoryById = (consentId) => {
   return consentHistory.filter(h => h.consentId === consentId);
};

// Generate a new consent ID
export const generateConsentId = () => {
   const year = new Date().getFullYear();
   const random = Math.floor(Math.random() * 1000000).toString().padStart(6, '0');
   return `CONSENT-${year}-${random}`;
};

// Patient info for the consent form
export const patientInfo = {
   id: "patient-123",
   name: "John Smith",
   mrn: "123456",
   email: "john.smith@email.com",
   phone: "(555) 123-4567",
   dob: "1985-06-15"
};
