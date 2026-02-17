import React from 'react';
import { render, screen, fireEvent } from '../../../test-utils';

import VitalsEntryForm from './VitalsEntryForm';

const mockProps = {
    form: {
        systolic: '120',
        diastolic: '80',
        heartRate: '72',
        temperature: '98.6',
        respiratoryRate: '16',
        oxygenSaturation: '98',
        painLevel: '2',
    },
    formStatuses: {
        bp: 'normal',
        heartRate: 'normal',
        temperature: 'normal',
        respiratoryRate: 'normal',
        oxygenSaturation: 'normal',
        painLevel: 'normal',
    },
    getStatusClasses: (status) => ({
        text: status === 'normal' ? 'text-green-600' : status === 'critical' ? 'text-red-600' : 'text-amber-600',
        border: status === 'normal' ? 'border-green-400' : status === 'critical' ? 'border-red-400' : 'border-amber-400',
        bg: status === 'normal' ? 'bg-green-50' : status === 'critical' ? 'bg-red-50' : 'bg-amber-50',
    }),
    getInputStatusClasses: (status) => 
        status === 'normal' ? 'border-gray-200 focus:ring-brand-medium' : 
        status === 'critical' ? 'border-red-400 focus:ring-red-500' : 
        'border-amber-400 focus:ring-amber-500',
    normalText: {
        bp: 'Normal: 90-130 / 60-85',
        heartRate: 'Normal: 60-100 bpm',
        temperature: 'Normal: 97-99°F',
        respiratoryRate: 'Normal: 12-20 /min',
        oxygenSaturation: 'Normal: 95-100%',
        painLevel: 'Normal: 0-3',
    },
    temperatureUnit: 'F',
    temperatureRoute: 'oral',
    onUnitToggle: jest.fn(),
    onRouteSelect: jest.fn(),
    onFieldChange: jest.fn(),
    selectedPainFace: { icon: null, label: 'Mild' },
    notes: '',
    onNotesChange: jest.fn(),
    formError: '',
    onSave: jest.fn(),
    onNotify: jest.fn(),
    onCancel: jest.fn(),
    lastTimestamp: '10:30 AM',
    recordedBy: 'Nurse Joy',
    unit: '3 East',
};

describe('VitalsEntryForm', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    test('renders form with vitals entry title', () => {
        render(<VitalsEntryForm {...mockProps} />);
        
        expect(screen.getByText(/vitals entry/i)).toBeInTheDocument();
    });

    test('displays shift assessment header', () => {
        render(<VitalsEntryForm {...mockProps} />);
        
        expect(screen.getByText(/shift assessment/i)).toBeInTheDocument();
    });

    test('displays last entry timestamp', () => {
        render(<VitalsEntryForm {...mockProps} />);
        
        expect(screen.getByText(/last entry 10:30 am/i)).toBeInTheDocument();
    });

    test('displays recorded by information', () => {
        render(<VitalsEntryForm {...mockProps} />);
        
        expect(screen.getByText(/recorded by nurse joy/i)).toBeInTheDocument();
    });

    test('renders blood pressure input fields', () => {
        render(<VitalsEntryForm {...mockProps} />);
        
        expect(screen.getByText(/blood pressure/i)).toBeInTheDocument();
        expect(screen.getByText(/systolic/i)).toBeInTheDocument();
        expect(screen.getByText(/diastolic/i)).toBeInTheDocument();
    });

    test('renders heart rate input field', () => {
        render(<VitalsEntryForm {...mockProps} />);
        
        expect(screen.getByText(/heart rate/i)).toBeInTheDocument();
    });

    test('renders temperature input field', () => {
        render(<VitalsEntryForm {...mockProps} />);
        
        expect(screen.getByText(/temperature/i)).toBeInTheDocument();
    });

    test('renders respiratory rate input field', () => {
        render(<VitalsEntryForm {...mockProps} />);
        
        expect(screen.getByText(/respiratory/i)).toBeInTheDocument();
    });

    test('renders oxygen saturation input field', () => {
        render(<VitalsEntryForm {...mockProps} />);
        
        expect(screen.getAllByText(/spo2|oxygen/i).length).toBeGreaterThan(0);
    });

    test('renders pain level input field', () => {
        render(<VitalsEntryForm {...mockProps} />);
        
        expect(screen.getByText(/pain level/i)).toBeInTheDocument();
    });

    test('displays normal range text for blood pressure', () => {
        render(<VitalsEntryForm {...mockProps} />);
        
        expect(screen.getByText(/normal: 90-130/i)).toBeInTheDocument();
    });

    test('calls onFieldChange when systolic value changes', () => {
        render(<VitalsEntryForm {...mockProps} />);
        
        // Labels don't have for attribute, use displayValue to find input
        const systolicInput = screen.getByDisplayValue('120');
        fireEvent.change(systolicInput, { target: { value: '130' } });
        
        expect(mockProps.onFieldChange).toHaveBeenCalledWith('systolic', '130');
    });

    test('calls onFieldChange when diastolic value changes', () => {
        render(<VitalsEntryForm {...mockProps} />);
        
        // Labels don't have for attribute, use displayValue to find input
        const diastolicInput = screen.getByDisplayValue('80');
        fireEvent.change(diastolicInput, { target: { value: '85' } });
        
        expect(mockProps.onFieldChange).toHaveBeenCalledWith('diastolic', '85');
    });

    test('renders save button', () => {
        render(<VitalsEntryForm {...mockProps} />);
        
        expect(screen.getAllByRole('button', { name: /save/i }).length).toBeGreaterThan(0);
    });

    test('calls onSave when form is submitted', () => {
        render(<VitalsEntryForm {...mockProps} />);
        
        const saveButtons = screen.getAllByRole('button', { name: /save/i });
        const form = saveButtons[0].closest('form');
        fireEvent.submit(form);
        
        expect(mockProps.onSave).toHaveBeenCalled();
    });

    test('displays form error when provided', () => {
        render(<VitalsEntryForm {...mockProps} formError="Please fill all required fields" />);
        
        expect(screen.getByText(/please fill all required fields/i)).toBeInTheDocument();
    });
});
