import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import LabOrders from './Orders';

// Mock the mock data
jest.mock('../../mocks/labOrders', () => ({
    mockLabOrders: [
        {
            id: 'L-2023-001',
            patientName: 'John Doe',
            patientId: 'P-TEST',
            testType: 'Blood Test',
            priority: 'High',
            status: 'Pending',
            orderDate: '2023-01-01'
        },
        {
            id: 'L-2023-002',
            patientName: 'Jane Smith',
            patientId: 'P-TEST2',
            testType: 'Urine Test',
            priority: 'Normal',
            status: 'Completed',
            orderDate: '2023-01-02'
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

describe('LabOrders Component', () => {
    test('renders orders table', () => {
        renderWithRouter(<LabOrders />);
        expect(screen.getByText('Lab Orders')).toBeInTheDocument();
        expect(screen.getByText('L-2023-001')).toBeInTheDocument();
        expect(screen.getByText('John Doe')).toBeInTheDocument();
        expect(screen.getByText('Blood Test')).toBeInTheDocument();
    });

    test('filters orders by search term', () => {
        renderWithRouter(<LabOrders />);
        const searchInput = screen.getByPlaceholderText('Search orders...');
        fireEvent.change(searchInput, { target: { value: 'Jane' } });

        expect(screen.queryByText('John Doe')).not.toBeInTheDocument();
        expect(screen.getByText('Jane Smith')).toBeInTheDocument();
    });

    test('filters orders by status', () => {
        renderWithRouter(<LabOrders />);
        const completedFilterBtn = screen.getByText('Completed');
        fireEvent.click(completedFilterBtn);

        expect(screen.queryByText('John Doe')).not.toBeInTheDocument(); // Pending
        expect(screen.getByText('Jane Smith')).toBeInTheDocument(); // Completed
    });

    test('renders "View" button for navigation', () => {
        renderWithRouter(<LabOrders />);
        const viewButtons = screen.getAllByText('View');
        expect(viewButtons.length).toBeGreaterThan(0);
    });
});
