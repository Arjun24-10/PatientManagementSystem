import React from 'react';
import { render, screen, waitFor } from '../../test-utils';
import NurseVitals from './Vitals';
import api from '../../services/api';

jest.mock('../../services/api', () => ({
    nurse: {
        getAssignedPatients: jest.fn(),
    }
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

const mockPatients = [
    {
        profileId: 'P001',
        firstName: 'John',
        lastName: 'Smith',
        room: '101A',
        acuityLevel: 'stable',
        vitalsStatus: 'done',
        medicationStatus: 'all-given',
        specialAlerts: [],
    },
    {
        profileId: 'P002',
        firstName: 'Jane',
        lastName: 'Doe',
        room: '102B',
        acuityLevel: 'critical',
        vitalsStatus: 'due',
        medicationStatus: 'due-soon',
        specialAlerts: [],
    },
];

describe('Nurse Vitals Page', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        api.nurse.getAssignedPatients.mockResolvedValue(mockPatients);
    });

    test('renders vitals page', async () => {
        render(<NurseVitals />);

        expect(screen.getAllByText(/patient vitals/i).length).toBeGreaterThan(0);
    });

    test('renders assigned patients section', async () => {
        render(<NurseVitals />);

        expect(await screen.findByText(/my assigned patients/i)).toBeInTheDocument();
    });

    test('displays patient list', async () => {
        render(<NurseVitals />);

        expect(await screen.findByText('John Smith')).toBeInTheDocument();
        expect(screen.getByText('Jane Doe')).toBeInTheDocument();
    });

    test('displays vitals overview section', async () => {
        render(<NurseVitals />);

        expect(await screen.findByText(/current vitals overview/i)).toBeInTheDocument();
    });

    test('displays vital signs data', async () => {
        render(<NurseVitals />);

        expect(await screen.findAllByText(/blood pressure/i)).toBeTruthy();
        expect(screen.getAllByText(/heart rate/i).length).toBeGreaterThan(0);
        expect(screen.getAllByText(/temperature/i).length).toBeGreaterThan(0);
    });

    test('displays vitals entry form section', async () => {
        render(<NurseVitals />);

        expect(await screen.findAllByText(/vitals entry/i)).toBeTruthy();
    });

    test('displays vitals trend chart section', async () => {
        render(<NurseVitals />);

        expect(await screen.findAllByText(/vitals trend/i)).toBeTruthy();
    });
});
