// Mock data for Lab Results

export const mockLabResults = [
   {
      id: 1,
      testName: "Complete Blood Count (CBC)",
      testDate: "2024-02-10",
      orderingPhysician: "Dr. Sarah Johnson",
      status: "completed",
      overallStatus: "abnormal",
      category: "Blood Test",
      results: [
         {
            parameter: "Hemoglobin",
            value: 13.5,
            unit: "g/dL",
            normalRange: "13.5-17.5",
            status: "normal"
         },
         {
            parameter: "White Blood Cells",
            value: 11.2,
            unit: "10^3/μL",
            normalRange: "4.5-11.0",
            status: "high",
            flag: "abnormal"
         },
         {
            parameter: "Red Blood Cells",
            value: 4.8,
            unit: "10^6/μL",
            normalRange: "4.5-5.5",
            status: "normal"
         },
         {
            parameter: "Platelets",
            value: 220,
            unit: "10^3/μL",
            normalRange: "150-400",
            status: "normal"
         },
         {
            parameter: "Hematocrit",
            value: 42,
            unit: "%",
            normalRange: "40-50",
            status: "normal"
         }
      ],
      downloadUrl: "/downloads/lab-results/1",
      notes: "Slightly elevated WBC count. Recommend follow-up in 2 weeks to monitor for infection or inflammation.",
      canCompare: true,
      previousTests: [
         { date: "2023-12-15", wbc: 9.5, hemoglobin: 14.1, platelets: 210 },
         { date: "2023-09-10", wbc: 8.8, hemoglobin: 13.8, platelets: 205 }
      ]
   },
   {
      id: 2,
      testName: "Lipid Panel",
      testDate: "2024-02-08",
      orderingPhysician: "Dr. Michael Chen",
      status: "completed",
      overallStatus: "borderline",
      category: "Blood Test",
      results: [
         {
            parameter: "Total Cholesterol",
            value: 210,
            unit: "mg/dL",
            normalRange: "<200",
            status: "borderline",
            flag: "borderline"
         },
         {
            parameter: "LDL Cholesterol",
            value: 130,
            unit: "mg/dL",
            normalRange: "<100",
            status: "high",
            flag: "abnormal"
         },
         {
            parameter: "HDL Cholesterol",
            value: 55,
            unit: "mg/dL",
            normalRange: ">40",
            status: "normal"
         },
         {
            parameter: "Triglycerides",
            value: 125,
            unit: "mg/dL",
            normalRange: "<150",
            status: "normal"
         }
      ],
      downloadUrl: "/downloads/lab-results/2",
      notes: "LDL cholesterol slightly elevated. Continue dietary modifications and consider statin therapy if levels don't improve in 3 months.",
      canCompare: true,
      previousTests: [
         { date: "2023-11-15", totalCholesterol: 215, ldl: 135, hdl: 52, triglycerides: 140 },
         { date: "2023-08-10", totalCholesterol: 220, ldl: 140, hdl: 50, triglycerides: 150 }
      ]
   },
   {
      id: 3,
      testName: "HbA1c (Diabetes Screening)",
      testDate: "2024-02-05",
      orderingPhysician: "Dr. Michael Chen",
      status: "completed",
      overallStatus: "normal",
      category: "Blood Test",
      results: [
         {
            parameter: "Hemoglobin A1c",
            value: 6.8,
            unit: "%",
            normalRange: "<7.0",
            status: "normal"
         }
      ],
      downloadUrl: "/downloads/lab-results/3",
      notes: "Good diabetes control. Continue current medication regimen and lifestyle modifications.",
      canCompare: true,
      previousTests: [
         { date: "2023-11-05", hba1c: 7.2 },
         { date: "2023-08-05", hba1c: 7.5 },
         { date: "2023-05-05", hba1c: 8.1 }
      ]
   },
   {
      id: 4,
      testName: "Comprehensive Metabolic Panel (CMP)",
      testDate: "2024-01-28",
      orderingPhysician: "Dr. Sarah Johnson",
      status: "completed",
      overallStatus: "normal",
      category: "Blood Test",
      results: [
         {
            parameter: "Glucose",
            value: 95,
            unit: "mg/dL",
            normalRange: "70-100",
            status: "normal"
         },
         {
            parameter: "Calcium",
            value: 9.5,
            unit: "mg/dL",
            normalRange: "8.5-10.5",
            status: "normal"
         },
         {
            parameter: "Sodium",
            value: 140,
            unit: "mmol/L",
            normalRange: "136-145",
            status: "normal"
         },
         {
            parameter: "Potassium",
            value: 4.2,
            unit: "mmol/L",
            normalRange: "3.5-5.0",
            status: "normal"
         },
         {
            parameter: "Creatinine",
            value: 1.0,
            unit: "mg/dL",
            normalRange: "0.7-1.3",
            status: "normal"
         },
         {
            parameter: "BUN",
            value: 15,
            unit: "mg/dL",
            normalRange: "7-20",
            status: "normal"
         }
      ],
      downloadUrl: "/downloads/lab-results/4",
      notes: "All metabolic parameters within normal limits. Kidney function excellent.",
      canCompare: true
   },
   {
      id: 5,
      testName: "Thyroid Function Panel",
      testDate: "2024-01-20",
      orderingPhysician: "Dr. Emily Roberts",
      status: "completed",
      overallStatus: "normal",
      category: "Blood Test",
      results: [
         {
            parameter: "TSH",
            value: 2.5,
            unit: "mIU/L",
            normalRange: "0.4-4.0",
            status: "normal"
         },
         {
            parameter: "Free T4",
            value: 1.2,
            unit: "ng/dL",
            normalRange: "0.8-1.8",
            status: "normal"
         },
         {
            parameter: "Free T3",
            value: 3.0,
            unit: "pg/mL",
            normalRange: "2.3-4.2",
            status: "normal"
         }
      ],
      downloadUrl: "/downloads/lab-results/5",
      notes: "Thyroid function normal. No intervention needed.",
      canCompare: false
   },
   {
      id: 6,
      testName: "Urinalysis",
      testDate: "2024-02-15",
      orderingPhysician: "Dr. Sarah Johnson",
      status: "pending",
      overallStatus: "pending",
      category: "Urine Test",
      results: null,
      downloadUrl: null,
      notes: "Sample being processed. Results expected within 24-48 hours.",
      canCompare: false
   },
   {
      id: 7,
      testName: "Vitamin D Level",
      testDate: "2024-01-15",
      orderingPhysician: "Dr. Sarah Johnson",
      status: "completed",
      overallStatus: "abnormal",
      category: "Blood Test",
      results: [
         {
            parameter: "25-Hydroxyvitamin D",
            value: 22,
            unit: "ng/mL",
            normalRange: "30-100",
            status: "low",
            flag: "abnormal"
         }
      ],
      downloadUrl: "/downloads/lab-results/7",
      notes: "Vitamin D deficiency detected. Started on Vitamin D3 supplementation 2000 IU daily. Recheck in 3 months.",
      canCompare: true,
      previousTests: [
         { date: "2023-07-15", vitaminD: 25 }
      ]
   }
];

export const mockLabStats = {
   totalTests: 7,
   pendingResults: 1,
   recentAbnormal: 2
};

// Trend data for charts
export const mockTrendData = {
   wbc: [
      { date: "2023-09-10", value: 8.8, normal: true },
      { date: "2023-12-15", value: 9.5, normal: true },
      { date: "2024-02-10", value: 11.2, normal: false }
   ],
   cholesterol: [
      { date: "2023-08-10", value: 220, normal: false },
      { date: "2023-11-15", value: 215, normal: false },
      { date: "2024-02-08", value: 210, normal: false }
   ],
   ldl: [
      { date: "2023-08-10", value: 140, normal: false },
      { date: "2023-11-15", value: 135, normal: false },
      { date: "2024-02-08", value: 130, normal: false }
   ],
   hba1c: [
      { date: "2023-05-05", value: 8.1, normal: false },
      { date: "2023-08-05", value: 7.5, normal: false },
      { date: "2023-11-05", value: 7.2, normal: false },
      { date: "2024-02-05", value: 6.8, normal: true }
   ],
   vitaminD: [
      { date: "2023-07-15", value: 25, normal: false },
      { date: "2024-01-15", value: 22, normal: false }
   ]
};
