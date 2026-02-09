import React from 'react';
import { render, screen, fireEvent } from '../../../test-utils';

import AssignedPatientsPanel from './AssignedPatientsPanel';

const mockProps = {
    totalCount: 5,
    viewMode: 'grid',
    onViewModeChange: jest.fn(),
    sortBy: 'acuity',
    onSortChange: jest.fn(),
    sortOptions: [
        { id: 'acuity', label: 'Acuity' },
        { id: 'room', label: 'Room' },
        { id: 'name', label: 'Name' },
    ],
    filterPresets: ['All', 'Critical', 'Due'],
    activeFilter: 'All',
    onFilterChange: jest.fn(),
    filteredPatients: [
        {
            id: 'P001',
            name: 'John Smith',
            room: '101A',
            age: 45,
            acuity: 'stable',
            vitalsStatus: 'done',
            medicationStatus: 'all-given',
            specialAlerts: [],
        },
        {
            id: 'P002',
            name: 'Jane Doe',
            room: '102B',
            age: 62,
            acuity: 'critical',
            vitalsStatus: 'overdue',
            medicationStatus: 'overdue',
            specialAlerts: ['fall-risk'],
        },
    ],
    acuityStyles: {
        critical: { label: 'Critical', badge: 'bg-red-500 text-white', border: 'border-l-4 border-red-500' },
        stable: { label: 'Stable', badge: 'bg-green-500 text-white', border: 'border-l-4 border-green-500' },
    },
    vitalsStatusMap: {
        done: { icon: () => null, text: 'Vitals done', classes: 'text-green-600' },
        overdue: { icon: () => null, text: 'Overdue', classes: 'text-red-500' },
    },
    medicationStatusMap: {
        'all-given': { icon: () => null, text: 'All given', classes: 'text-green-600' },
        overdue: { icon: () => null, text: 'Overdue', classes: 'text-red-500' },
    },
};

describe('AssignedPatientsPanel', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    test('renders panel with title', () => {
        render(<AssignedPatientsPanel {...mockProps} />);
        
        expect(screen.getByText(/my assigned patients/i)).toBeInTheDocument();
    });

    test('displays total patient count', () => {
        render(<AssignedPatientsPanel {...mockProps} />);
        
        expect(screen.getByText(/total 5/i)).toBeInTheDocument();
    });

    test('renders view mode toggle buttons', () => {
        render(<AssignedPatientsPanel {...mockProps} />);
        
        expect(screen.getByText(/grid/i)).toBeInTheDocument();
        expect(screen.getByText(/list/i)).toBeInTheDocument();
    });

    test('calls onViewModeChange when grid button is clicked', () => {
        render(<AssignedPatientsPanel {...mockProps} viewMode="list" />);
        
        const gridButton = screen.getByText(/grid/i);
        fireEvent.click(gridButton);
        
        expect(mockProps.onViewModeChange).toHaveBeenCalledWith('grid');
    });

    test('calls onViewModeChange when list button is clicked', () => {
        render(<AssignedPatientsPanel {...mockProps} />);
        
        const listButton = screen.getByText(/list/i);
        fireEvent.click(listButton);
        
        expect(mockProps.onViewModeChange).toHaveBeenCalledWith('list');
    });

    test('renders sort dropdown', () => {
        render(<AssignedPatientsPanel {...mockProps} />);
        
        expect(screen.getByRole('combobox')).toBeInTheDocument();
    });

    test('displays all sort options', () => {
        render(<AssignedPatientsPanel {...mockProps} />);
        
        const dropdown = screen.getByRole('combobox');
        expect(dropdown).toHaveTextContent(/acuity/i);
    });

    test('calls onSortChange when sort option changes', () => {
        render(<AssignedPatientsPanel {...mockProps} />);
        
        const dropdown = screen.getByRole('combobox');
        fireEvent.change(dropdown, { target: { value: 'room' } });
        
        expect(mockProps.onSortChange).toHaveBeenCalledWith('room');
    });

    test('displays patient names', () => {
        render(<AssignedPatientsPanel {...mockProps} />);
        
        expect(screen.getByText('John Smith')).toBeInTheDocument();
        expect(screen.getByText('Jane Doe')).toBeInTheDocument();
    });

    test('displays room information', () => {
        render(<AssignedPatientsPanel {...mockProps} />);
        
        expect(screen.getByText(/101a/i)).toBeInTheDocument();
        expect(screen.getByText(/102b/i)).toBeInTheDocument();
    });
});
