import React from 'react';
import { render, screen } from '../../test-utils';
import NurseVitals from './Vitals';

// Mock the nurse overview data
jest.mock('../../mocks/nurseOverview', () => ({
    mockNurseOverview: {
        nurse: {
            id: 'N-12345',
            name: 'Jennifer Martinez',
            role: 'Registered Nurse',
            unit: 'Medical-Surgical Floor 3',
        },
        stats: {
            overdueVitals: 0,
        },
        assignedPatients: [
            {
                id: 'P001',
                name: 'John Smith',
                room: '101A',
                age: 45,
                acuity: 'stable',
                acuityLevel: 'stable',
                vitalsStatus: 'done',
                medicationStatus: 'all-given',
                specialAlerts: [],
            },
            {
                id: 'P002',
                name: 'Jane Doe',
                room: '102B',
                age: 62,
                acuity: 'high',
                acuityLevel: 'critical',
                vitalsStatus: 'due',
                medicationStatus: 'due-soon',
                specialAlerts: [],
            },
        ],
        selectedPatient: {
            id: 'P001',
            name: 'John Smith',
            room: '101A',
            age: 45,
        },
        vitals: {
            current: {
                bp: { systolic: 120, diastolic: 80 },
                heartRate: 72,
                temperature: { value: 98.6, unit: 'F', route: 'oral' },
                respiratoryRate: 16,
                oxygenSaturation: 98,
                painLevel: 2,
            },
            history: [],
        },
        vitalsSchedule: [
            { id: 1, time: '08:00', status: 'completed', patients: [] },
            { id: 2, time: '12:00', status: 'current', patients: [] },
            { id: 3, time: '16:00', status: 'upcoming', patients: [] },
        ],
    },
}));

// Mock recharts to avoid rendering issues in tests
jest.mock('recharts', () => ({
    ResponsiveContainer: ({ children }) => <div data-testid="responsive-container">{children}</div>,
    LineChart: ({ children }) => <div data-testid="line-chart">{children}</div>,
    CartesianGrid: () => <div data-testid="cartesian-grid" />,
    XAxis: () => <div data-testid="x-axis" />,
    YAxis: () => <div data-testid="y-axis" />,
    Tooltip: () => <div data-testid="tooltip" />,
    Legend: () => <div data-testid="legend" />,
    ReferenceArea: () => <div data-testid="reference-area" />,
    Line: () => <div data-testid="line" />,
}));

describe('Nurse Vitals Page', () => {
    test('renders vitals page', () => {
        render(<NurseVitals />);
        
        expect(screen.getAllByText(/patient vitals/i).length).toBeGreaterThan(0);
    });

    test('renders assigned patients section', () => {
        render(<NurseVitals />);
        
        expect(screen.getByText(/my assigned patients/i)).toBeInTheDocument();
    });

    test('displays patient list', () => {
        render(<NurseVitals />);
        
        expect(screen.getByText('John Smith')).toBeInTheDocument();
        expect(screen.getByText('Jane Doe')).toBeInTheDocument();
    });

    test('displays vitals overview section', () => {
        render(<NurseVitals />);
        
        expect(screen.getByText(/current vitals overview/i)).toBeInTheDocument();
    });

    test('displays vital signs data', () => {
        render(<NurseVitals />);
        
        expect(screen.getAllByText(/blood pressure/i).length).toBeGreaterThan(0);
        expect(screen.getAllByText(/heart rate/i).length).toBeGreaterThan(0);
        expect(screen.getAllByText(/temperature/i).length).toBeGreaterThan(0);
    });

    test('displays vitals entry form section', () => {
        render(<NurseVitals />);
        
        expect(screen.getAllByText(/vitals entry/i).length).toBeGreaterThan(0);
    });

    test('displays vitals trend chart section', () => {
        render(<NurseVitals />);
        
        expect(screen.getAllByText(/vitals trend/i).length).toBeGreaterThan(0);
    });

    test('displays vitals log table section', () => {
        render(<NurseVitals />);
        
        expect(screen.getByText(/time-stamped vitals log/i)).toBeInTheDocument();
    });

    test('renders view mode toggle buttons', () => {
        render(<NurseVitals />);
        
        expect(screen.getAllByText(/grid/i).length).toBeGreaterThan(0);
        expect(screen.getAllByText(/list/i).length).toBeGreaterThan(0);
    });

    test('renders export and print buttons', () => {
        render(<NurseVitals />);
        
        expect(screen.getAllByText(/export/i).length).toBeGreaterThan(0);
        expect(screen.getAllByText(/print/i).length).toBeGreaterThan(0);
    });

    test('displays room and age information for selected patient', () => {
        render(<NurseVitals />);
        
        expect(screen.getAllByText(/room/i).length).toBeGreaterThan(0);
        expect(screen.getAllByText(/age/i).length).toBeGreaterThan(0);
    });
});
