// Mock data for Medications

export const mockMedicationsData = {
   active: [
      {
         id: 1,
         name: "Metformin",
         genericName: "Metformin Hydrochloride",
         strength: "500mg",
         form: "Tablet",
         dosage: "500mg twice daily",
         frequency: "Twice daily with meals",
         prescribedBy: {
            name: "Dr. Michael Chen",
            specialty: "Endocrinologist",
            avatar: "MC"
         },
         prescribedDate: "2023-05-15",
         startDate: "2023-05-20",
         endDate: null,
         purpose: "Type 2 Diabetes Management",
         instructions: "Take with food. Do not crush or chew. Drink plenty of water.",
         refillsRemaining: 2,
         totalRefills: 5,
         status: "active",
         pharmacy: "HealthPlus Pharmacy",
         prescriptionNumber: "RX-2023-45678",
         sideEffects: ["Nausea", "Diarrhea", "Stomach upset", "Metallic taste"],
         interactions: [],
         warnings: ["Avoid excessive alcohol consumption"],
         critical: false,
         canRefill: true
      },
      {
         id: 2,
         name: "Lisinopril",
         genericName: "Lisinopril",
         strength: "10mg",
         form: "Tablet",
         dosage: "10mg once daily",
         frequency: "Once daily in the morning",
         prescribedBy: {
            name: "Dr. Sarah Johnson",
            specialty: "Cardiologist",
            avatar: "SJ"
         },
         prescribedDate: "2020-01-15",
         startDate: "2020-01-20",
         endDate: null,
         purpose: "Hypertension (High Blood Pressure)",
         instructions: "Take at the same time each day. Monitor blood pressure regularly. Rise slowly from sitting/lying position.",
         refillsRemaining: 1,
         totalRefills: 6,
         status: "expiring-soon",
         expiryWarning: "Only 1 refill remaining - Request refill soon",
         pharmacy: "HealthPlus Pharmacy",
         prescriptionNumber: "RX-2020-12345",
         sideEffects: ["Dizziness", "Dry cough", "Headache", "Fatigue"],
         interactions: ["Potassium supplements", "NSAIDs"],
         warnings: ["Do not use if pregnant", "Monitor potassium levels"],
         critical: true,
         canRefill: true
      },
      {
         id: 3,
         name: "Atorvastatin",
         genericName: "Atorvastatin Calcium",
         strength: "20mg",
         form: "Tablet",
         dosage: "20mg once daily",
         frequency: "Once daily at bedtime",
         prescribedBy: {
            name: "Dr. Michael Chen",
            specialty: "Endocrinologist",
            avatar: "MC"
         },
         prescribedDate: "2023-08-10",
         startDate: "2023-08-15",
         endDate: null,
         purpose: "High Cholesterol (Hyperlipidemia)",
         instructions: "Take in the evening. Avoid grapefruit juice. Report any muscle pain immediately.",
         refillsRemaining: 4,
         totalRefills: 5,
         status: "active",
         pharmacy: "HealthPlus Pharmacy",
         prescriptionNumber: "RX-2023-78901",
         sideEffects: ["Muscle pain", "Liver enzyme changes", "Digestive problems"],
         interactions: ["Grapefruit juice", "Certain antibiotics"],
         warnings: ["Report unexplained muscle pain", "Periodic liver function tests required"],
         critical: false,
         canRefill: true
      },
      {
         id: 4,
         name: "Aspirin",
         genericName: "Acetylsalicylic Acid",
         strength: "81mg",
         form: "Tablet",
         dosage: "81mg once daily",
         frequency: "Once daily with food",
         prescribedBy: {
            name: "Dr. Sarah Johnson",
            specialty: "Cardiologist",
            avatar: "SJ"
         },
         prescribedDate: "2023-01-10",
         startDate: "2023-01-15",
         endDate: null,
         purpose: "Cardiovascular Protection",
         instructions: "Take with food to reduce stomach upset. Do not crush enteric-coated tablets.",
         refillsRemaining: 5,
         totalRefills: 12,
         status: "active",
         pharmacy: "HealthPlus Pharmacy",
         prescriptionNumber: "RX-2023-11111",
         sideEffects: ["Stomach upset", "Easy bruising", "Ringing in ears"],
         interactions: ["Blood thinners", "NSAIDs", "Alcohol"],
         warnings: ["Increased bleeding risk", "Avoid before surgery"],
         critical: true,
         canRefill: true
      },
      {
         id: 5,
         name: "Vitamin D3",
         genericName: "Cholecalciferol",
         strength: "2000 IU",
         form: "Capsule",
         dosage: "2000 IU once daily",
         frequency: "Once daily",
         prescribedBy: {
            name: "Dr. Sarah Johnson",
            specialty: "General Medicine",
            avatar: "SJ"
         },
         prescribedDate: "2024-01-15",
         startDate: "2024-01-20",
         endDate: "2024-07-20",
         purpose: "Vitamin D Deficiency",
         instructions: "Take with a meal containing fat for better absorption.",
         refillsRemaining: 0,
         totalRefills: 0,
         status: "active",
         pharmacy: "HealthPlus Pharmacy",
         prescriptionNumber: "RX-2024-22222",
         sideEffects: ["Rare: nausea, constipation"],
         interactions: [],
         warnings: ["Do not exceed recommended dose"],
         critical: false,
         canRefill: false
      }
   ],
   history: [
      {
         id: 6,
         name: "Amoxicillin",
         genericName: "Amoxicillin",
         strength: "500mg",
         form: "Capsule",
         dosage: "500mg three times daily",
         frequency: "Three times daily",
         prescribedBy: {
            name: "Dr. Emily Roberts",
            specialty: "General Physician",
            avatar: "ER"
         },
         prescribedDate: "2023-11-05",
         startDate: "2023-11-05",
         endDate: "2023-11-15",
         purpose: "Bacterial Infection (Sinusitis)",
         status: "completed",
         refillsRemaining: 0,
         totalRefills: 0,
         prescriptionNumber: "RX-2023-55555",
         completedDate: "2023-11-15"
      },
      {
         id: 7,
         name: "Omeprazole",
         genericName: "Omeprazole",
         strength: "20mg",
         form: "Capsule",
         dosage: "20mg once daily",
         prescribedBy: {
            name: "Dr. Robert Williams",
            specialty: "Gastroenterologist",
            avatar: "RW"
         },
         prescribedDate: "2022-08-25",
         startDate: "2022-08-25",
         endDate: "2023-02-25",
         purpose: "GERD (Gastroesophageal Reflux Disease)",
         status: "discontinued",
         discontinuedReason: "Symptoms resolved with lifestyle modifications",
         discontinuedDate: "2023-02-25",
         refillsRemaining: 0,
         totalRefills: 6,
         prescriptionNumber: "RX-2022-33333"
      },
      {
         id: 8,
         name: "Prednisone",
         genericName: "Prednisone",
         strength: "10mg",
         form: "Tablet",
         dosage: "10mg daily (tapering dose)",
         prescribedBy: {
            name: "Dr. Emily Roberts",
            specialty: "General Physician",
            avatar: "ER"
         },
         prescribedDate: "2023-09-10",
         startDate: "2023-09-10",
         endDate: "2023-09-25",
         purpose: "Allergic Reaction",
         status: "completed",
         refillsRemaining: 0,
         totalRefills: 0,
         prescriptionNumber: "RX-2023-44444",
         completedDate: "2023-09-25"
      }
   ],
   refillRequests: [
      {
         id: 1,
         medicationId: 2,
         medicationName: "Lisinopril 10mg",
         requestDate: "2024-02-12",
         status: "approved",
         pharmacy: "HealthPlus Pharmacy",
         pickupMethod: "pickup",
         urgency: "standard",
         estimatedReadyDate: "2024-02-14",
         approvedBy: "Dr. Sarah Johnson",
         approvedDate: "2024-02-12"
      }
   ]
};

export const mockDrugInteractions = [
   {
      severity: "moderate",
      medication1: "Lisinopril",
      medication2: "Aspirin",
      description: "NSAIDs and aspirin may reduce the blood pressure-lowering effects of ACE inhibitors like Lisinopril.",
      recommendation: "Monitor blood pressure regularly. Report any significant changes to your doctor.",
      action: "Monitor"
   }
];

export const mockMedicationSchedule = {
   morning: [
      { medicationId: 2, name: "Lisinopril 10mg", time: "8:00 AM", taken: true },
      { medicationId: 1, name: "Metformin 500mg", time: "8:00 AM", taken: true },
      { medicationId: 4, name: "Aspirin 81mg", time: "8:00 AM", taken: false }
   ],
   afternoon: [
      { medicationId: 1, name: "Metformin 500mg", time: "6:00 PM", taken: false }
   ],
   evening: [
      { medicationId: 3, name: "Atorvastatin 20mg", time: "9:00 PM", taken: false },
      { medicationId: 5, name: "Vitamin D3 2000 IU", time: "9:00 PM", taken: false }
   ],
   night: []
};

export const mockMedicationStats = {
   totalActive: 5,
   needingRefill: 1,
   upcomingExpirations: 1,
   adherenceRate: 92
};
