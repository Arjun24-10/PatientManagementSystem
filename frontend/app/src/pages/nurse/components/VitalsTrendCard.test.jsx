import React from 'react';
import { render, screen, fireEvent } from '../../../test-utils';

import VitalsTrendCard from './VitalsTrendCard';

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

const mockProps = {
    timeRange: '24h',
    onTimeRangeChange: jest.fn(),
    customRange: { start: '2024-01-01', end: '2024-01-31' },
    onCustomRangeChange: jest.fn(),
    visibleVitals: {
        bpSystolic: true,
        bpDiastolic: true,
        heartRate: true,
        temperature: false,
        respiratoryRate: false,
        oxygenSaturation: false,
    },
    onToggleVital: jest.fn(),
    chartData: [
        { time: '06:00', bpSystolic: 120, bpDiastolic: 80, heartRate: 72 },
        { time: '10:00', bpSystolic: 125, bpDiastolic: 82, heartRate: 75 },
        { time: '14:00', bpSystolic: 118, bpDiastolic: 78, heartRate: 70 },
    ],
    chartDomain: { min: 40, max: 200 },
    vitalLimits: {
        bp: { 
            normal: {
                systolic: [90, 130],
                diastolic: [60, 80]
            }
        },
        heartRate: { normal: [60, 100] },
        temperature: { normal: [97.0, 99.0] },
        respiratoryRate: { normal: [12, 20] },
        oxygenSaturation: { normal: [95, 100] },
    },
    onExport: jest.fn(),
};

describe('VitalsTrendCard', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    test('renders card with title', () => {
        render(<VitalsTrendCard {...mockProps} />);
        
        expect(screen.getByText(/vitals trend/i)).toBeInTheDocument();
    });

    test('renders card description', () => {
        render(<VitalsTrendCard {...mockProps} />);
        
        expect(screen.getByText(/multi-parameter view/i)).toBeInTheDocument();
    });

    test('renders time range buttons', () => {
        render(<VitalsTrendCard {...mockProps} />);
        
        expect(screen.getByText(/last 24 hrs/i)).toBeInTheDocument();
        expect(screen.getByText(/last 48 hrs/i)).toBeInTheDocument();
        expect(screen.getByText(/last 7 days/i)).toBeInTheDocument();
        expect(screen.getByText(/custom/i)).toBeInTheDocument();
    });

    test('calls onTimeRangeChange when time range button is clicked', () => {
        render(<VitalsTrendCard {...mockProps} />);
        
        const weekButton = screen.getByText(/last 7 days/i);
        fireEvent.click(weekButton);
        
        expect(mockProps.onTimeRangeChange).toHaveBeenCalledWith('7d');
    });

    test('shows custom date inputs when custom range is selected', () => {
        render(<VitalsTrendCard {...mockProps} timeRange="custom" />);
        
        expect(screen.getByDisplayValue('2024-01-01')).toBeInTheDocument();
        expect(screen.getByDisplayValue('2024-01-31')).toBeInTheDocument();
    });

    test('does not show custom date inputs for preset ranges', () => {
        render(<VitalsTrendCard {...mockProps} timeRange="24h" />);
        
        expect(screen.queryByDisplayValue('2024-01-01')).not.toBeInTheDocument();
    });

    test('calls onCustomRangeChange when custom start date changes', () => {
        render(<VitalsTrendCard {...mockProps} timeRange="custom" />);
        
        const startInput = screen.getByDisplayValue('2024-01-01');
        fireEvent.change(startInput, { target: { value: '2024-01-15' } });
        
        expect(mockProps.onCustomRangeChange).toHaveBeenCalled();
    });

    test('renders vital toggle buttons', () => {
        render(<VitalsTrendCard {...mockProps} />);
        
        expect(screen.getByText(/systolic bp/i)).toBeInTheDocument();
        expect(screen.getByText(/diastolic bp/i)).toBeInTheDocument();
        expect(screen.getByText(/heart rate/i)).toBeInTheDocument();
    });

    test('renders chart container', () => {
        render(<VitalsTrendCard {...mockProps} />);
        
        expect(screen.getByTestId('responsive-container')).toBeInTheDocument();
    });

    test('renders line chart', () => {
        render(<VitalsTrendCard {...mockProps} />);
        
        expect(screen.getByTestId('line-chart')).toBeInTheDocument();
    });

    test('highlights active time range button', () => {
        render(<VitalsTrendCard {...mockProps} timeRange="24h" />);
        
        const activeButton = screen.getByText(/last 24 hrs/i);
        expect(activeButton).toHaveClass('bg-brand-medium');
    });

    test('calls onCustomRangeChange when custom end date changes', () => {
        render(<VitalsTrendCard {...mockProps} timeRange="custom" />);
        
        const endInput = screen.getByDisplayValue('2024-01-31');
        fireEvent.change(endInput, { target: { value: '2024-02-15' } });
        
        expect(mockProps.onCustomRangeChange).toHaveBeenCalled();
    });
});
