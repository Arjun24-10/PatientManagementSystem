// Mock data for doctors and departments
export const mockDepartments = [
   { id: 'D001', name: 'Cardiology', icon: '❤️' },
   { id: 'D002', name: 'Neurology', icon: '🧠' },
   { id: 'D003', name: 'Orthopedics', icon: '🦴' },
   { id: 'D004', name: 'Pediatrics', icon: '👶' },
   { id: 'D005', name: 'Dermatology', icon: '🩺' },
   { id: 'D006', name: 'General Medicine', icon: '⚕️' },
];

export const mockDoctors = [
   {
      id: 'DOC001',
      name: 'Dr. Sarah Smith',
      department: 'D001',
      departmentName: 'Cardiology',
      specialization: 'Interventional Cardiology',
      avatar: 'SS',
      rating: 4.8,
      experience: '15 years',
   },
   {
      id: 'DOC002',
      name: 'Dr. John Davis',
      department: 'D002',
      departmentName: 'Neurology',
      specialization: 'Neurological Surgery',
      avatar: 'JD',
      rating: 4.9,
      experience: '20 years',
   },
   {
      id: 'DOC003',
      name: 'Dr. Emily Chen',
      department: 'D003',
      departmentName: 'Orthopedics',
      specialization: 'Sports Medicine',
      avatar: 'EC',
      rating: 4.7,
      experience: '12 years',
   },
   {
      id: 'DOC004',
      name: 'Dr. Michael Brown',
      department: 'D004',
      departmentName: 'Pediatrics',
      specialization: 'Child Development',
      avatar: 'MB',
      rating: 4.9,
      experience: '18 years',
   },
   {
      id: 'DOC005',
      name: 'Dr. Lisa Anderson',
      department: 'D005',
      departmentName: 'Dermatology',
      specialization: 'Cosmetic Dermatology',
      avatar: 'LA',
      rating: 4.6,
      experience: '10 years',
   },
   {
      id: 'DOC006',
      name: 'Dr. Robert Wilson',
      department: 'D006',
      departmentName: 'General Medicine',
      specialization: 'Family Medicine',
      avatar: 'RW',
      rating: 4.8,
      experience: '22 years',
   },
];

// Mock available time slots for appointments
export const mockTimeSlots = {
   morning: ['08:00 AM', '08:30 AM', '09:00 AM', '09:30 AM', '10:00 AM', '10:30 AM', '11:00 AM', '11:30 AM'],
   afternoon: ['01:00 PM', '01:30 PM', '02:00 PM', '02:30 PM', '03:00 PM', '03:30 PM', '04:00 PM', '04:30 PM'],
   evening: ['05:00 PM', '05:30 PM', '06:00 PM', '06:30 PM', '07:00 PM'],
};

export const appointmentTypes = [
   'General Consultation',
   'Follow-up',
   'Check-up',
   'Vaccination',
   'Lab Review',
   'Emergency',
   'Physical Therapy',
   'Diagnostic Test',
];

export const cancellationReasons = [
   'Schedule Conflict',
   'Feeling Better',
   'Doctor Unavailable',
   'Personal Emergency',
   'Financial Reasons',
   'Found Another Provider',
   'Other',
];
