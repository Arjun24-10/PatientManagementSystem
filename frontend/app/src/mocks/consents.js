/**
 * HIPAA-Compliant Consent Management Mock Data
 * This data structure supports the Consent Management Center for patient privacy settings
 */

export const consentData = {
  patient: {
    id: "P-001",
    name: "John Smith",
    mrn: "MRN-123456"
  },
  
  summary: {
    activeConsents: 5,
    pendingReview: 1,
    withdrawn: 2,
    lastReviewed: "2024-02-09T14:30:00"
  },
  
  consents: [
    {
      id: "consent-1",
      category: "tpo",
      title: "Treatment, Payment & Healthcare Operations",
      icon: "Stethoscope",
      type: "required",
      status: "active",
      canWithdraw: false,
      description: "This allows us to provide your medical care, process insurance claims, and run our healthcare facility. This consent is required to receive care and cannot be withdrawn.",
      includes: [
        "Sharing information with your care team (doctors, nurses, specialists)",
        "Billing insurance companies",
        "Quality improvement activities",
        "Hospital administrative operations"
      ],
      grantedDate: "2024-01-15T09:00:00",
      effectiveDate: "2024-01-15T09:00:00",
      lastModified: "2024-01-15T09:00:00"
    },
    {
      id: "consent-2",
      category: "research",
      title: "Medical Research & Clinical Studies",
      icon: "FlaskConical",
      type: "optional",
      status: "granted",
      canWithdraw: true,
      description: "Allow your de-identified health information to be used for medical research and clinical studies that may improve healthcare.",
      includes: [
        "Use of anonymized data for research studies",
        "Participation in clinical research databases",
        "Medical education purposes (de-identified)"
      ],
      privacyNotes: [
        "Your identity will be protected and removed from research data",
        "You may withdraw consent at any time without affecting your care",
        "Withdrawing does not affect data already used in research"
      ],
      grantedDate: "2024-01-15T09:00:00",
      lastModified: "2024-01-15T09:00:00",
      effectiveDate: "2024-01-15T09:00:00"
    },
    {
      id: "consent-3",
      category: "family-sharing",
      title: "Sharing Information with Family/Friends",
      icon: "Users",
      type: "optional",
      status: "granted",
      canWithdraw: true,
      description: "Allow healthcare providers to discuss your medical information with specified family members or friends.",
      authorizedPersons: [
        {
          id: "ap-1",
          name: "Jane Smith",
          relationship: "Spouse",
          phone: "(555) 123-4567",
          canReceive: ["general-status", "diagnosis", "treatment", "appointments"]
        },
        {
          id: "ap-2",
          name: "Robert Smith",
          relationship: "Son",
          phone: "(555) 987-6543",
          canReceive: ["general-status", "appointments"]
        }
      ],
      informationTypes: [
        { id: "general-status", label: "General health status" },
        { id: "diagnosis", label: "Diagnosis information" },
        { id: "treatment", label: "Treatment plans" },
        { id: "appointments", label: "Appointment information" },
        { id: "billing", label: "Billing information" }
      ],
      grantedDate: "2024-01-15T09:00:00",
      lastModified: "2024-01-20T14:30:00",
      effectiveDate: "2024-01-15T09:00:00"
    },
    {
      id: "consent-4",
      category: "hie",
      title: "Health Information Exchange (HIE)",
      icon: "Network",
      type: "optional",
      status: "granted",
      canWithdraw: true,
      description: "Allow your health records to be shared electronically with other healthcare providers and hospitals through secure health information networks.",
      benefits: [
        "Better coordination of care across providers",
        "Faster access to medical history in emergencies",
        "Reduced duplicate tests"
      ],
      whatIsShared: [
        "Medical history and diagnoses",
        "Medications and allergies",
        "Lab and imaging results",
        "Immunization records"
      ],
      whoCanAccess: [
        "Other healthcare providers involved in your care",
        "Emergency departments",
        "Specialists you are referred to"
      ],
      grantedDate: "2024-01-15T09:00:00",
      lastModified: "2024-01-15T09:00:00",
      effectiveDate: "2024-01-15T09:00:00"
    },
    {
      id: "consent-5",
      category: "communications",
      title: "Appointment Reminders & Communications",
      icon: "Bell",
      type: "optional",
      status: "granted",
      canWithdraw: true,
      description: "Receive appointment reminders, test results notifications, and general health information.",
      preferences: {
        email: { address: "john.smith@email.com", enabled: true },
        sms: { phone: "(555) 123-4567", enabled: true },
        phone: { phone: "(555) 123-4567", enabled: false },
        portal: { enabled: true }
      },
      communicationTypes: [
        { id: "appointments", label: "Appointment reminders", enabled: true },
        { id: "lab-results", label: "Lab/test results available", enabled: true },
        { id: "refills", label: "Prescription refill reminders", enabled: true },
        { id: "preventive", label: "Preventive care reminders", enabled: true },
        { id: "health-tips", label: "General health tips", enabled: false }
      ],
      grantedDate: "2024-01-15T09:00:00",
      lastModified: "2024-01-25T11:20:00",
      effectiveDate: "2024-01-15T09:00:00"
    },
    {
      id: "consent-6",
      category: "marketing",
      title: "Marketing & Fundraising",
      icon: "Megaphone",
      type: "optional",
      status: "withdrawn",
      canWithdraw: true,
      description: "Receive information about hospital services, health programs, and fundraising activities.",
      includes: [
        "Information about new services",
        "Health and wellness programs",
        "Community health events",
        "Fundraising requests"
      ],
      importantNote: "This does not include your medical information, only general communications about our services.",
      grantedDate: "2024-01-15T09:00:00",
      withdrawnDate: "2024-02-01T16:45:00",
      lastModified: "2024-02-01T16:45:00",
      effectiveDate: "2024-01-15T09:00:00"
    },
    {
      id: "consent-7",
      category: "directory",
      title: "Hospital Directory Listing",
      icon: "BookOpen",
      type: "optional",
      status: "pending",
      canWithdraw: true,
      description: "Include your basic information in the hospital directory so visitors and callers can find you during your stay.",
      informationIncluded: [
        "Your name",
        "Your location in the facility",
        "Your general condition (e.g., 'stable', 'fair')",
        "Your religious affiliation (optional)"
      ],
      whoCanAccess: [
        "People who ask for you by name",
        "Clergy members (if religious affiliation included)"
      ],
      requestDate: "2024-02-09T08:00:00",
      requiresAction: true
    },
    {
      id: "consent-8",
      category: "sensitive-restrictions",
      title: "Sensitive Information Restrictions",
      icon: "Lock",
      type: "special",
      status: "active",
      canWithdraw: true,
      description: "Request additional privacy protection for particularly sensitive health information under HIPAA.",
      activeRestrictions: [
        {
          id: "restriction-1",
          category: "mental-health",
          label: "Mental Health Records",
          restriction: "Do not share with family members",
          effectiveDate: "2024-01-20T10:00:00"
        }
      ],
      availableCategories: [
        { id: "mental-health", label: "Mental health records" },
        { id: "substance-abuse", label: "Substance abuse treatment" },
        { id: "hiv-aids", label: "HIV/AIDS status" },
        { id: "genetic", label: "Genetic testing results" },
        { id: "reproductive", label: "Sexual/reproductive health" }
      ],
      importantNote: "These restrictions may be overridden in emergencies or when required by law.",
      grantedDate: "2024-01-20T10:00:00",
      lastModified: "2024-01-20T10:00:00",
      effectiveDate: "2024-01-20T10:00:00"
    }
  ],
  
  history: [
    {
      id: "history-1",
      timestamp: "2024-02-01T16:45:00",
      category: "marketing",
      categoryTitle: "Marketing & Fundraising",
      action: "withdrawn",
      changedBy: "patient",
      changedByName: "You",
      details: "Marketing & Fundraising consent withdrawn",
      previousStatus: "granted",
      newStatus: "withdrawn"
    },
    {
      id: "history-2",
      timestamp: "2024-01-25T11:20:00",
      category: "communications",
      categoryTitle: "Appointment Reminders & Communications",
      action: "modified",
      changedBy: "patient",
      changedByName: "You",
      details: "Communication preferences updated - disabled phone calls",
      previousStatus: "granted",
      newStatus: "granted"
    },
    {
      id: "history-3",
      timestamp: "2024-01-20T14:30:00",
      category: "family-sharing",
      categoryTitle: "Sharing Information with Family/Friends",
      action: "modified",
      changedBy: "patient",
      changedByName: "You",
      details: "Added Robert Smith to authorized persons list",
      previousStatus: "granted",
      newStatus: "granted"
    },
    {
      id: "history-4",
      timestamp: "2024-01-20T10:00:00",
      category: "sensitive-restrictions",
      categoryTitle: "Sensitive Information Restrictions",
      action: "granted",
      changedBy: "patient",
      changedByName: "You",
      details: "Added restriction on mental health records",
      previousStatus: null,
      newStatus: "active"
    },
    {
      id: "history-5",
      timestamp: "2024-01-15T09:00:00",
      category: "multiple",
      categoryTitle: "Initial Consent Package",
      action: "granted",
      changedBy: "patient",
      changedByName: "You",
      details: "Initial consent package completed during registration",
      previousStatus: null,
      newStatus: "granted"
    }
  ],

  faq: [
    {
      id: "faq-1",
      question: "Will withdrawing consent affect my care?",
      answer: "Withdrawing optional consents will not affect the quality of your medical care. Required consents (Treatment, Payment & Healthcare Operations) cannot be withdrawn as they are necessary for providing your care."
    },
    {
      id: "faq-2",
      question: "How long does it take for changes to take effect?",
      answer: "Most consent changes take effect within 24-48 hours. Some changes, particularly those involving third parties or external systems, may take up to 5 business days."
    },
    {
      id: "faq-3",
      question: "Can I change my mind later?",
      answer: "Yes, you can grant or withdraw optional consents at any time. However, please note that withdrawing consent does not affect information that was already used or shared while the consent was active."
    },
    {
      id: "faq-4",
      question: "Who can I contact with privacy questions?",
      answer: "You can contact our Privacy Officer at privacy@securehealth.com or call (555) 123-4567. Our office is open Monday through Friday, 9 AM to 5 PM."
    }
  ],

  privacyOfficer: {
    email: "privacy@securehealth.com",
    phone: "(555) 123-4567",
    hours: "Monday - Friday, 9 AM - 5 PM"
  },

  legalLinks: {
    privacyNotice: "/docs/privacy-notice.pdf",
    privacyRights: "/docs/privacy-rights.pdf",
    fileComplaint: "/privacy/complaint"
  },

  lastPrivacyNoticeUpdate: "2024-01-01"
};

// Helper function to get consent by ID
export const getConsentById = (consentId) => {
  return consentData.consents.find(c => c.id === consentId);
};

// Helper function to get consents by status
export const getConsentsByStatus = (status) => {
  return consentData.consents.filter(c => c.status === status);
};

// Helper function to get consent history filtered by time range
export const getConsentHistory = (days = null) => {
  if (!days) return consentData.history;
  
  const cutoffDate = new Date();
  cutoffDate.setDate(cutoffDate.getDate() - days);
  
  return consentData.history.filter(h => new Date(h.timestamp) >= cutoffDate);
};

export default consentData;
