// Comprehensive mock data for Medical History section

export const mockMedicalTimeline = [
   {
      id: 1,
      date: "2024-02-05",
      type: "visit",
      title: "Annual Physical Exam",
      doctor: "Dr. Sarah Johnson",
      department: "General Medicine",
      summary: "Routine checkup, all vitals normal. Blood pressure 120/80, weight stable.",
      details: "Comprehensive physical examination including cardiovascular, respiratory, and neurological assessment. Patient reports no new symptoms. Recommended continued exercise and balanced diet.",
      status: "completed"
   },
   {
      id: 2,
      date: "2024-01-28",
      type: "lab",
      title: "Lab Results: Lipid Panel",
      doctor: "Dr. Michael Chen",
      department: "Laboratory",
      summary: "Total cholesterol slightly elevated at 210 mg/dL. HDL and LDL within normal range.",
      details: "Complete lipid panel results: Total Cholesterol 210 mg/dL, HDL 55 mg/dL, LDL 130 mg/dL, Triglycerides 125 mg/dL. Recommended dietary modifications and follow-up in 3 months.",
      status: "completed"
   },
   {
      id: 3,
      date: "2024-01-15",
      type: "prescription",
      title: "Prescription: Metformin 500mg",
      doctor: "Dr. Michael Chen",
      department: "Endocrinology",
      summary: "Started on Metformin for blood sugar management.",
      details: "Prescribed Metformin 500mg twice daily with meals for Type 2 Diabetes management. Patient counseled on potential side effects and importance of medication adherence.",
      status: "active"
   },
   {
      id: 4,
      date: "2023-12-10",
      type: "procedure",
      title: "Colonoscopy",
      doctor: "Dr. Robert Williams",
      department: "Gastroenterology",
      summary: "Routine screening colonoscopy completed successfully.",
      details: "Procedure completed without complications. No polyps or abnormalities detected. Next screening recommended in 10 years.",
      status: "completed"
   },
   {
      id: 5,
      date: "2023-11-20",
      type: "visit",
      title: "Follow-up: Diabetes Management",
      doctor: "Dr. Michael Chen",
      department: "Endocrinology",
      summary: "HbA1c improved to 6.8%. Continue current treatment plan.",
      details: "Patient showing good response to lifestyle modifications and medication. Blood glucose levels well-controlled. Encouraged to maintain current diet and exercise regimen.",
      status: "completed"
   },
   {
      id: 6,
      date: "2023-10-05",
      type: "lab",
      title: "Lab Results: HbA1c Test",
      doctor: "Dr. Michael Chen",
      department: "Laboratory",
      summary: "HbA1c: 7.2% - slightly above target range.",
      details: "Hemoglobin A1c test shows average blood glucose levels over past 3 months. Result of 7.2% indicates need for treatment adjustment.",
      status: "completed"
   }
];

export const mockDiagnosesHistory = [
   {
      id: 1,
      name: "Type 2 Diabetes Mellitus",
      icdCode: "E11.9",
      dateRecorded: "2023-05-15",
      physician: "Dr. Michael Chen",
      department: "Endocrinology",
      status: "active",
      severity: "medium",
      notes: "Controlled with medication (Metformin 500mg BID) and lifestyle modifications. Patient adherent to treatment plan. Regular monitoring of blood glucose and HbA1c levels recommended.",
      relatedMedications: ["Metformin 500mg"],
      lastReview: "2024-01-15"
   },
   {
      id: 2,
      name: "Hypertension",
      icdCode: "I10",
      dateRecorded: "2020-01-15",
      physician: "Dr. Sarah Johnson",
      department: "Cardiology",
      status: "active",
      severity: "medium",
      notes: "Well-controlled with Lisinopril 10mg daily. Blood pressure consistently within target range (120-130/70-80 mmHg). Continue current management.",
      relatedMedications: ["Lisinopril 10mg"],
      lastReview: "2024-02-05"
   },
   {
      id: 3,
      name: "Seasonal Allergic Rhinitis",
      icdCode: "J30.1",
      dateRecorded: "2018-04-10",
      physician: "Dr. Emily Martinez",
      department: "Allergy & Immunology",
      status: "chronic",
      severity: "low",
      notes: "Seasonal symptoms managed with antihistamines as needed. Patient experiences symptoms primarily in spring (March-May). Avoidance of known triggers recommended.",
      relatedMedications: ["Cetirizine 10mg PRN"],
      lastReview: "2023-05-20"
   },
   {
      id: 4,
      name: "Gastroesophageal Reflux Disease (GERD)",
      icdCode: "K21.9",
      dateRecorded: "2022-08-20",
      physician: "Dr. Robert Williams",
      department: "Gastroenterology",
      status: "resolved",
      severity: "low",
      notes: "Symptoms resolved with lifestyle modifications and short-term PPI therapy. Patient reports no recurrence of symptoms for past 6 months. Discharged from active management.",
      relatedMedications: [],
      lastReview: "2023-11-10"
   },
   {
      id: 5,
      name: "Vitamin D Deficiency",
      icdCode: "E55.9",
      dateRecorded: "2023-02-10",
      physician: "Dr. Sarah Johnson",
      department: "General Medicine",
      status: "resolved",
      severity: "low",
      notes: "Treated with Vitamin D3 supplementation 2000 IU daily for 3 months. Follow-up labs showed normalization of Vitamin D levels (35 ng/mL). Continue maintenance dose of 1000 IU daily.",
      relatedMedications: ["Vitamin D3 1000 IU"],
      lastReview: "2023-08-15"
   }
];

export const mockTreatmentHistory = [
   {
      id: 1,
      name: "Diabetes Management Program",
      type: "Medical Management",
      startDate: "2023-05-20",
      endDate: null,
      prescribedBy: "Dr. Michael Chen",
      department: "Endocrinology",
      purpose: "Blood sugar control and lifestyle modification for Type 2 Diabetes",
      status: "ongoing",
      medications: ["Metformin 500mg BID"],
      notes: "Patient responding well to treatment. HbA1c improved from 8.5% to 6.8% over 6 months. Continue current regimen with quarterly monitoring.",
      progress: 75,
      nextReview: "2024-04-15"
   },
   {
      id: 2,
      name: "Hypertension Control",
      type: "Medical Management",
      startDate: "2020-01-20",
      endDate: null,
      prescribedBy: "Dr. Sarah Johnson",
      department: "Cardiology",
      purpose: "Blood pressure management and cardiovascular risk reduction",
      status: "ongoing",
      medications: ["Lisinopril 10mg daily"],
      notes: "Excellent blood pressure control achieved. Patient maintains healthy lifestyle with regular exercise and low-sodium diet. Annual cardiovascular risk assessment recommended.",
      progress: 90,
      nextReview: "2024-08-15"
   },
   {
      id: 3,
      name: "Physical Therapy - Lower Back",
      type: "Physical Therapy",
      startDate: "2023-09-01",
      endDate: "2023-12-15",
      prescribedBy: "Dr. Amanda Foster",
      department: "Orthopedics",
      purpose: "Rehabilitation for chronic lower back pain",
      status: "completed",
      medications: [],
      notes: "12-week physical therapy program completed successfully. Patient reports 80% reduction in pain and improved mobility. Home exercise program provided for maintenance.",
      progress: 100,
      nextReview: null
   },
   {
      id: 4,
      name: "Dietary Counseling",
      type: "Nutritional Therapy",
      startDate: "2023-06-01",
      endDate: null,
      prescribedBy: "Dr. Michael Chen",
      department: "Nutrition Services",
      purpose: "Diabetes management and weight control through dietary modifications",
      status: "ongoing",
      medications: [],
      notes: "Patient working with registered dietitian on meal planning and carbohydrate counting. Lost 8 lbs over 3 months. Continue monthly counseling sessions.",
      progress: 60,
      nextReview: "2024-03-01"
   },
   {
      id: 5,
      name: "Proton Pump Inhibitor Therapy",
      type: "Medical Management",
      startDate: "2022-08-25",
      endDate: "2023-02-25",
      prescribedBy: "Dr. Robert Williams",
      department: "Gastroenterology",
      purpose: "Treatment of GERD symptoms",
      status: "discontinued",
      medications: ["Omeprazole 20mg (discontinued)"],
      notes: "6-month course of PPI therapy completed. Symptoms resolved with lifestyle modifications. Treatment successfully discontinued without recurrence.",
      progress: 100,
      nextReview: null
   }
];

export const mockProcedureHistory = [
   {
      id: 1,
      name: "Colonoscopy",
      date: "2023-12-10",
      physician: "Dr. Robert Williams",
      department: "Gastroenterology",
      location: "City Hospital - Endoscopy Unit",
      status: "completed",
      followUpRequired: false,
      indication: "Routine screening for colorectal cancer",
      findings: "Normal colonic mucosa throughout. No polyps, masses, or other abnormalities detected.",
      preOpNotes: "Patient fasted appropriately. Bowel preparation adequate. Conscious sedation administered without complications.",
      postOpNotes: "Procedure tolerated well. Patient recovered in PACU for 1 hour. Discharged home with family member. No immediate complications.",
      nextProcedure: "2033-12-10",
      documents: ["colonoscopy_report_2023.pdf", "pathology_report.pdf"]
   },
   {
      id: 2,
      name: "Upper Endoscopy (EGD)",
      date: "2022-09-15",
      physician: "Dr. Robert Williams",
      department: "Gastroenterology",
      location: "City Hospital - Endoscopy Unit",
      status: "completed",
      followUpRequired: true,
      indication: "Evaluation of GERD symptoms and dysphagia",
      findings: "Mild esophagitis (Grade A). Gastric mucosa normal. Duodenum normal. Biopsies taken from esophagus.",
      preOpNotes: "NPO since midnight. IV access established. Sedation plan reviewed with patient.",
      postOpNotes: "Procedure completed successfully. Biopsies sent to pathology (results: negative for Barrett's esophagus). Follow-up in 6 months recommended.",
      nextProcedure: "2024-03-15",
      documents: ["egd_report_2022.pdf", "biopsy_results.pdf"]
   },
   {
      id: 3,
      name: "Echocardiogram",
      date: "2023-06-20",
      physician: "Dr. Jennifer Lee",
      department: "Cardiology",
      location: "Heart Center - Imaging Suite",
      status: "completed",
      followUpRequired: false,
      indication: "Assessment of cardiac function in patient with hypertension",
      findings: "Normal left ventricular size and function (EF 60%). No valvular abnormalities. No pericardial effusion.",
      preOpNotes: "Transthoracic echocardiogram ordered for baseline cardiac assessment.",
      postOpNotes: "Study completed successfully. Results reviewed with patient. No intervention required at this time.",
      nextProcedure: "2025-06-20",
      documents: ["echo_report_2023.pdf"]
   },
   {
      id: 4,
      name: "Bone Density Scan (DEXA)",
      date: "2024-03-15",
      physician: "Dr. Sarah Johnson",
      department: "Radiology",
      location: "Imaging Center",
      status: "scheduled",
      followUpRequired: true,
      indication: "Osteoporosis screening",
      findings: "Pending - procedure scheduled",
      preOpNotes: "Patient scheduled for baseline DEXA scan. No special preparation required.",
      postOpNotes: "Pending",
      nextProcedure: null,
      documents: []
   }
];

export const mockAllergies = [
   {
      id: 1,
      allergen: "Penicillin",
      type: "drug",
      severity: "severe",
      reaction: "Anaphylaxis - difficulty breathing, hives, swelling of face and throat",
      dateIdentified: "2015-03-20",
      identifiedBy: "Dr. Emily Martinez",
      notes: "Patient experienced severe allergic reaction after taking amoxicillin for strep throat. Required emergency treatment with epinephrine. All penicillin-based antibiotics contraindicated.",
      alternatives: ["Azithromycin", "Fluoroquinolones", "Cephalosporins (use with caution)"]
   },
   {
      id: 2,
      allergen: "Shellfish",
      type: "food",
      severity: "moderate",
      reaction: "Urticaria (hives), facial swelling, gastrointestinal upset",
      dateIdentified: "2010-07-15",
      identifiedBy: "Dr. Emily Martinez",
      notes: "Patient reports allergic reactions to shrimp, crab, and lobster. Symptoms typically occur within 30 minutes of ingestion. Advised to carry antihistamines and avoid all shellfish.",
      alternatives: []
   },
   {
      id: 3,
      allergen: "Pollen (Ragweed)",
      type: "environmental",
      severity: "mild",
      reaction: "Rhinitis, sneezing, watery eyes, nasal congestion",
      dateIdentified: "2018-04-10",
      identifiedBy: "Dr. Emily Martinez",
      notes: "Seasonal allergies primarily in late summer and fall. Managed with over-the-counter antihistamines as needed. Symptoms typically mild and self-limiting.",
      alternatives: []
   },
   {
      id: 4,
      allergen: "Latex",
      type: "environmental",
      severity: "moderate",
      reaction: "Contact dermatitis, skin rash, itching",
      dateIdentified: "2019-11-05",
      identifiedBy: "Dr. Sarah Johnson",
      notes: "Developed contact dermatitis after wearing latex gloves. Healthcare providers notified to use non-latex gloves during examinations and procedures.",
      alternatives: ["Nitrile gloves", "Vinyl gloves"]
   }
];

export const mockChronicConditions = [
   {
      id: 1,
      name: "Type 2 Diabetes Mellitus",
      dateDiagnosed: "2023-05-15",
      status: "controlled",
      managingPhysician: "Dr. Michael Chen",
      department: "Endocrinology",
      medications: ["Metformin 500mg BID"],
      lastCheckup: "2024-01-15",
      nextReview: "2024-04-15",
      notes: "Well-controlled with medication and lifestyle modifications. HbA1c 6.8% (target <7%). Patient adherent to treatment plan.",
      complications: "None to date",
      monitoring: "Quarterly HbA1c, annual eye exam, annual foot exam"
   },
   {
      id: 2,
      name: "Hypertension (Essential)",
      dateDiagnosed: "2020-01-15",
      status: "controlled",
      managingPhysician: "Dr. Sarah Johnson",
      department: "Cardiology",
      medications: ["Lisinopril 10mg daily"],
      lastCheckup: "2024-02-05",
      nextReview: "2024-08-05",
      notes: "Excellent blood pressure control. Average BP 122/78 mmHg. No end-organ damage. Continue current management.",
      complications: "None",
      monitoring: "Home BP monitoring, office visits every 6 months"
   },
   {
      id: 3,
      name: "Hyperlipidemia",
      dateDiagnosed: "2021-03-10",
      status: "monitoring",
      managingPhysician: "Dr. Sarah Johnson",
      department: "Cardiology",
      medications: [],
      lastCheckup: "2024-01-28",
      nextReview: "2024-04-28",
      notes: "Borderline high cholesterol managed with diet and exercise. Total cholesterol 210 mg/dL. Monitoring response to lifestyle modifications before considering statin therapy.",
      complications: "None",
      monitoring: "Lipid panel every 3 months, cardiovascular risk assessment annually"
   },
   {
      id: 4,
      name: "Seasonal Allergic Rhinitis",
      dateDiagnosed: "2018-04-10",
      status: "controlled",
      managingPhysician: "Dr. Emily Martinez",
      department: "Allergy & Immunology",
      medications: ["Cetirizine 10mg PRN"],
      lastCheckup: "2023-05-20",
      nextReview: "2024-05-20",
      notes: "Seasonal symptoms well-controlled with antihistamines. Symptoms primarily in spring months. Patient manages symptoms independently.",
      complications: "None",
      monitoring: "Annual review, as-needed basis for symptom management"
   }
];
