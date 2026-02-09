import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import LabHistory from './History';

// Mock the mock data
jest.mock('../../mocks/labOrders', () => ({
    mockLabOrders: [
        {
            id: 'L-100',
            patientName: 'John Doe',
            testType: 'Blood Test',
            status: 'Completed',
            completedDate: '2023-01-01'
        },
        {
            id: 'L-101',
            patientName: 'Jane Smith',
            testType: 'Urine Test',
            status: 'Pending', // Should be filtered out by initial filtering logic in component
            completedDate: null
        }
    ]
}));

const renderWithRouter = (component) => {
    return render(
        <BrowserRouter>
            {component}
        </BrowserRouter>
    );
};

describe('LabHistory Component', () => {
    test('renders history table with only completed orders', () => {
        renderWithRouter(<LabHistory />);
        expect(screen.getByText('Lab History')).toBeInTheDocument();
        expect(screen.getByText('L-100')).toBeInTheDocument();
        expect(screen.queryByText('L-101')).not.toBeInTheDocument(); // Should filter out non-completed
    });

    test('filters history by search term', () => {
        renderWithRouter(<LabHistory />);
        const searchInput = screen.getByPlaceholderText(/Search by patient or test/i);

        fireEvent.change(searchInput, { target: { value: 'NonExistent' } });
        expect(screen.queryByText('John Doe')).not.toBeInTheDocument();

        fireEvent.change(searchInput, { target: { value: 'Blood' } });
        expect(screen.getByText('John Doe')).toBeInTheDocument();
    });
});
