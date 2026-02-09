export const mockLabOrders = [
    {
        id: 'L-2023-001',
        patientName: 'Sarah Johnson',
        patientId: 'P-1001',
        testType: 'Complete Blood Count (CBC)',
        priority: 'High',
        status: 'Pending',
        orderDate: '2023-12-14T09:30:00',
        doctorName: 'Dr. Smith',
        sampleType: 'Blood',
        collectionDate: null,
        notes: 'Patient reports fatigue. Check for anemia.'
    },
    {
        id: 'L-2023-002',
        patientName: 'Mike Ross',
        patientId: 'P-1004',
        testType: 'Lipid Panel',
        priority: 'Normal',
        status: 'Collected',
        orderDate: '2023-12-14T10:15:00',
        doctorName: 'Dr. Jones',
        sampleType: 'Blood',
        collectionDate: '2023-12-14T10:45:00',
        notes: 'Routine checkup.'
    },
    {
        id: 'L-2023-003',
        patientName: 'Emily Clark',
        patientId: 'P-1022',
        testType: 'Urinalysis',
        priority: 'Normal',
        status: 'Results Pending',
        orderDate: '2023-12-13T14:20:00',
        doctorName: 'Dr. Smith',
        sampleType: 'Urine',
        collectionDate: '2023-12-13T14:40:00',
        notes: ''
    },
    {
        id: 'L-2023-004',
        patientName: 'David Miller',
        patientId: 'P-1056',
        testType: 'Thyroid Panel',
        priority: 'Urgent',
        status: 'Completed',
        orderDate: '2023-12-12T11:00:00',
        doctorName: 'Dr. Lee',
        sampleType: 'Blood',
        collectionDate: '2023-12-12T11:15:00',
        completedDate: '2023-12-12T16:30:00',
        resultFile: 'results_L-2023-004.pdf',
        notes: 'Monitor TSH levels.'
    },
    {
        id: 'L-2023-005',
        patientName: 'Jessica Pearson',
        patientId: 'P-1089',
        testType: 'Comprehensive Metabolic Panel',
        priority: 'Normal',
        status: 'Pending',
        orderDate: '2023-12-15T08:45:00',
        doctorName: 'Dr. Smith',
        sampleType: 'Blood',
        collectionDate: null,
        notes: 'Fasting required.'
    },
    {
        id: 'L-2023-006',
        patientName: 'Louis Litt',
        patientId: 'P-1090',
        testType: 'Vitamin D',
        priority: 'Normal',
        status: 'Completed',
        orderDate: '2023-12-10T13:30:00',
        doctorName: 'Dr. Jones',
        sampleType: 'Blood',
        collectionDate: '2023-12-10T13:45:00',
        completedDate: '2023-12-11T09:00:00',
        resultFile: 'results_L-2023-006.pdf',
        notes: ''
    }
];

export const mockLabActivity = [
    { id: 1, action: 'Result Uploaded', details: 'Lipid Panel for Mike Ross', time: '10 mins ago', user: 'Tech Mike' },
    { id: 2, action: 'Sample Collected', details: 'Blood sample for Emily Clark', time: '1 hour ago', user: 'Nurse Joy' },
    { id: 3, action: 'Order Received', details: 'Urgent CBC for Sarah Johnson', time: '2 hours ago', user: 'System' },
    { id: 4, action: 'Test Completed', details: 'Thyroid Panel for David Miller', time: 'Yesterday', user: 'Tech Mike' },
];
