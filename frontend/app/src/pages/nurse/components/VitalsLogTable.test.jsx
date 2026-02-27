import React from 'react';
import { render, screen, fireEvent } from '../../../test-utils';

import VitalsLogTable from './VitalsLogTable';

const mockProps = {
    historySearch: '',
    onSearch: jest.fn(),
    historyRange: { start: '2024-01-01', end: '2024-01-31' },
    onHistoryRangeChange: jest.fn(),
    filteredVitalsLog: [
        {
            timestamp: '2024-01-15T10:30:00Z',
            bp: '120/80',
            hr: 72,
            temp: 98.6,
            rr: 16,
            spo2: 98,
            pain: 2,
            recordedBy: 'Nurse Joy',
        },
        {
            timestamp: '2024-01-15T06:30:00Z',
            bp: '118/78',
            hr: 70,
            temp: 98.4,
            rr: 14,
            spo2: 99,
            pain: 1,
            recordedBy: 'Nurse Jenny',
        },
    ],
    formatTimestamp: (ts) => new Date(ts).toLocaleString(),
    parseBpString: (bp) => {
        const [systolic, diastolic] = bp.split('/').map(Number);
        return { systolic, diastolic };
    },
    classifyBp: (systolic, diastolic) => 
        systolic > 140 || diastolic > 90 ? 'critical' : 
        systolic > 130 || diastolic > 85 ? 'abnormal' : 'normal',
    classifyValue: (type, value) => 
        type === 'heartRate' ? (value > 100 ? 'abnormal' : 'normal') : 'normal',
    getStatusClasses: (status) => ({
        text: status === 'normal' ? 'text-green-600' : 'text-red-600',
        bg: status === 'normal' ? 'bg-green-50' : 'bg-red-50',
    }),
    defaultRecorder: 'Nurse Joy',
    onPrint: jest.fn(),
    onExport: jest.fn(),
};

describe('VitalsLogTable', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    test('renders table with title', () => {
        render(<VitalsLogTable {...mockProps} />);
        
        expect(screen.getByText(/time-stamped vitals log/i)).toBeInTheDocument();
    });

    test('renders table description', () => {
        render(<VitalsLogTable {...mockProps} />);
        
        expect(screen.getByText(/complete record of submissions/i)).toBeInTheDocument();
    });

    test('renders search input', () => {
        render(<VitalsLogTable {...mockProps} />);
        
        expect(screen.getByPlaceholderText(/search vitals/i)).toBeInTheDocument();
    });

    test('calls onSearch when search input changes', () => {
        render(<VitalsLogTable {...mockProps} />);
        
        const searchInput = screen.getByPlaceholderText(/search vitals/i);
        fireEvent.change(searchInput, { target: { value: 'nurse' } });
        
        expect(mockProps.onSearch).toHaveBeenCalledWith('nurse');
    });

    test('renders date range inputs', () => {
        render(<VitalsLogTable {...mockProps} />);
        
        expect(screen.getByDisplayValue('2024-01-01')).toBeInTheDocument();
        expect(screen.getByDisplayValue('2024-01-31')).toBeInTheDocument();
    });

    test('calls onHistoryRangeChange when start date changes', () => {
        render(<VitalsLogTable {...mockProps} />);
        
        const startInput = screen.getByDisplayValue('2024-01-01');
        fireEvent.change(startInput, { target: { value: '2024-01-05' } });
        
        expect(mockProps.onHistoryRangeChange).toHaveBeenCalled();
    });

    test('renders Print button', () => {
        render(<VitalsLogTable {...mockProps} />);
        
        expect(screen.getByRole('button', { name: /print/i })).toBeInTheDocument();
    });

    test('calls onPrint when Print button is clicked', () => {
        render(<VitalsLogTable {...mockProps} />);
        
        const printButton = screen.getByRole('button', { name: /print/i });
        fireEvent.click(printButton);
        
        expect(mockProps.onPrint).toHaveBeenCalled();
    });

    test('renders Export button', () => {
        render(<VitalsLogTable {...mockProps} />);
        
        expect(screen.getByRole('button', { name: /export/i })).toBeInTheDocument();
    });

    test('calls onExport when Export button is clicked', () => {
        render(<VitalsLogTable {...mockProps} />);
        
        const exportButton = screen.getByRole('button', { name: /export/i });
        fireEvent.click(exportButton);
        
        expect(mockProps.onExport).toHaveBeenCalled();
    });

    test('renders table with correct headers', () => {
        render(<VitalsLogTable {...mockProps} />);
        
        expect(screen.getByRole('columnheader', { name: /timestamp/i })).toBeInTheDocument();
        expect(screen.getByRole('columnheader', { name: /^bp$/i })).toBeInTheDocument();
        expect(screen.getByRole('columnheader', { name: /^hr$/i })).toBeInTheDocument();
        expect(screen.getByRole('columnheader', { name: /temp/i })).toBeInTheDocument();
        expect(screen.getByRole('columnheader', { name: /^rr$/i })).toBeInTheDocument();
        expect(screen.getByRole('columnheader', { name: /spo2/i })).toBeInTheDocument();
        expect(screen.getByRole('columnheader', { name: /pain/i })).toBeInTheDocument();
        expect(screen.getByRole('columnheader', { name: /recorded by/i })).toBeInTheDocument();
    });

    test('displays vitals log entries', () => {
        render(<VitalsLogTable {...mockProps} />);
        
        expect(screen.getByText('120/80')).toBeInTheDocument();
        expect(screen.getByText('118/78')).toBeInTheDocument();
    });

    test('displays recorder names', () => {
        render(<VitalsLogTable {...mockProps} />);
        
        expect(screen.getByText('Nurse Joy')).toBeInTheDocument();
        expect(screen.getByText('Nurse Jenny')).toBeInTheDocument();
    });

    test('displays heart rate values', () => {
        render(<VitalsLogTable {...mockProps} />);
        
        // Text is split with "bpm" suffix, use regex
        expect(screen.getByText(/72\s*bpm/i)).toBeInTheDocument();
        expect(screen.getByText(/70\s*bpm/i)).toBeInTheDocument();
    });
});
