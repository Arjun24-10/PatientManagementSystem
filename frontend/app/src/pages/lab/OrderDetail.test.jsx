import React from 'react';
import { render, screen } from '@testing-library/react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import LabOrderDetail from './OrderDetail';

// Mock the mock data
jest.mock('../../mocks/labOrders', () => ({
    mockLabOrders: [
        {
            id: 'L-1',
            patientName: 'John Doe',
            patientId: 'P-1',
            testType: 'Blood Test',
            priority: 'High',
            status: 'Pending',
            orderDate: '2023-01-01',
            doctorName: 'Dr. House',
            sampleType: 'Blood',
            notes: 'Test Notes'
        }
    ]
}));

const renderWithRouter = (component, route = '/dashboard/lab/orders/L-1') => {
    window.history.pushState({}, 'Test page', route);
    return render(
        <BrowserRouter>
            <Routes>
                <Route path="/dashboard/lab/orders/:id" element={component} />
            </Routes>
        </BrowserRouter>
    );
};

describe('LabOrderDetail Component', () => {
    test('renders order details correctly', () => {
        renderWithRouter(<LabOrderDetail />);

        expect(screen.getByText('Order #L-1')).toBeInTheDocument();
        expect(screen.getByText('John Doe')).toBeInTheDocument();
        expect(screen.getByText('Blood Test')).toBeInTheDocument();
        expect(screen.getByText('Test Notes')).toBeInTheDocument();
        expect(screen.getByText('Pending')).toBeInTheDocument();
    });

    test('shows correct action button based on status', () => {
        renderWithRouter(<LabOrderDetail />);
        // Setup mock is Pending, so valid action is "Mark Sample Collected"
        expect(screen.getByText('Mark Sample Collected')).toBeInTheDocument();
        expect(screen.queryByText('Upload Results')).not.toBeInTheDocument();
    });

    test('renders restricted access warning', () => {
        renderWithRouter(<LabOrderDetail />);
        expect(screen.getByText(/Restricted Access/i)).toBeInTheDocument();
    });
});
