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

    test('displays patient list', () => {
        render(<NurseVitals />);

        expect(screen.getByText('John Smith')).toBeInTheDocument();
        expect(screen.getByText('Jane Doe')).toBeInTheDocument();
    });

    test('displays room information for patients', () => {
        render(<NurseVitals />);

        expect(screen.getAllByText(/room/i).length).toBeGreaterThan(0);
    });
});
