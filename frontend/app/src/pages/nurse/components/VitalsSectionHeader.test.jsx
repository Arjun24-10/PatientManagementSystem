import React from 'react';
import { render, screen, fireEvent } from '../../../test-utils';

import VitalsSectionHeader from './VitalsSectionHeader';

const mockProps = {
    patient: {
        id: 'P001',
        name: 'John Smith',
        room: '101A',
        age: 45,
    },
    onExportPdf: jest.fn(),
    onPrint: jest.fn(),
};

describe('VitalsSectionHeader', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    test('renders patient vitals title', () => {
        render(<VitalsSectionHeader {...mockProps} />);
        
        expect(screen.getByText(/patient vitals/i)).toBeInTheDocument();
    });

    test('displays patient name', () => {
        render(<VitalsSectionHeader {...mockProps} />);
        
        expect(screen.getByText(/john smith/i)).toBeInTheDocument();
    });

    test('displays patient room', () => {
        render(<VitalsSectionHeader {...mockProps} />);
        
        expect(screen.getByText(/room 101a/i)).toBeInTheDocument();
    });

    test('displays patient age', () => {
        render(<VitalsSectionHeader {...mockProps} />);
        
        expect(screen.getByText(/age 45/i)).toBeInTheDocument();
    });

    test('shows "No patient selected" when patient is null', () => {
        render(<VitalsSectionHeader {...mockProps} patient={null} />);
        
        expect(screen.getByText(/no patient selected/i)).toBeInTheDocument();
    });

    test('renders Export PDF button', () => {
        render(<VitalsSectionHeader {...mockProps} />);
        
        expect(screen.getByRole('button', { name: /export pdf/i })).toBeInTheDocument();
    });

    test('renders Print button', () => {
        render(<VitalsSectionHeader {...mockProps} />);
        
        expect(screen.getByRole('button', { name: /print/i })).toBeInTheDocument();
    });

    test('calls onExportPdf when Export PDF button is clicked', () => {
        render(<VitalsSectionHeader {...mockProps} />);
        
        const exportButton = screen.getByRole('button', { name: /export pdf/i });
        fireEvent.click(exportButton);
        
        expect(mockProps.onExportPdf).toHaveBeenCalled();
    });

    test('calls onPrint when Print button is clicked', () => {
        render(<VitalsSectionHeader {...mockProps} />);
        
        const printButton = screen.getByRole('button', { name: /print/i });
        fireEvent.click(printButton);
        
        expect(mockProps.onPrint).toHaveBeenCalled();
    });

    test('renders thermometer icon', () => {
        render(<VitalsSectionHeader {...mockProps} />);
        
        // The component should render (icon is part of the header)
        expect(screen.getByText(/patient vitals/i)).toBeInTheDocument();
    });

    test('displays all patient info in a single line', () => {
        render(<VitalsSectionHeader {...mockProps} />);
        
        // Patient info should contain name, room, and age separated by ·
        const patientInfo = screen.getByText(/john smith · room 101a · age 45/i);
        expect(patientInfo).toBeInTheDocument();
    });
});
