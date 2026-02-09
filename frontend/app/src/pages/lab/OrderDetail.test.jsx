import React from 'react';
import { render, screen, fireEvent } from '../../test-utils';
import LabOrderDetail from './OrderDetail';

// Mock useParams and useNavigate
const mockNavigate = jest.fn();
jest.mock('react-router-dom', () => ({
    ...jest.requireActual('react-router-dom'),
    useParams: () => ({ id: 'LAB001' }),
    useNavigate: () => mockNavigate,
}));

// Mock the lab orders data
jest.mock('../../mocks/labOrders', () => ({
    mockLabOrders: [
        {
            id: 'LAB001',
            patientName: 'John Smith',
            patientId: 'P001',
            testType: 'Complete Blood Count',
            status: 'Pending',
            priority: 'High',
            sampleType: 'Blood',
            notes: 'Fasting required',
            doctorName: 'Dr. Wilson',
            orderDate: '2024-01-15T08:00:00Z',
        },
        {
            id: 'LAB002',
            patientName: 'Jane Doe',
            patientId: 'P002',
            testType: 'Lipid Panel',
            status: 'Collected',
            priority: 'Normal',
            sampleType: 'Blood',
            doctorName: 'Dr. Brown',
            orderDate: '2024-01-14T09:00:00Z',
            collectionDate: '2024-01-14T10:00:00Z',
        },
    ],
}));

describe('Lab Order Detail Page', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    test('renders order detail page', () => {
        render(<LabOrderDetail />);
        
        expect(screen.getByText(/order #lab001/i)).toBeInTheDocument();
    });

    test('displays patient and order information', () => {
        render(<LabOrderDetail />);
        
        expect(screen.getByText(/complete blood count/i)).toBeInTheDocument();
        expect(screen.getByText(/dr. wilson/i)).toBeInTheDocument();
    });

    test('displays test details section', () => {
        render(<LabOrderDetail />);
        
        expect(screen.getByText(/test details/i)).toBeInTheDocument();
        expect(screen.getByText(/sample type/i)).toBeInTheDocument();
        expect(screen.getByText(/fasting required/i)).toBeInTheDocument();
    });

    test('displays priority badge', () => {
        render(<LabOrderDetail />);
        
        expect(screen.getByText(/high/i)).toBeInTheDocument();
    });

    test('displays status badge', () => {
        render(<LabOrderDetail />);
        
        expect(screen.getByText(/pending/i)).toBeInTheDocument();
    });

    test('shows Mark Sample Collected button for pending orders', () => {
        render(<LabOrderDetail />);
        
        expect(screen.getByText(/mark sample collected/i)).toBeInTheDocument();
    });

    test('navigates back to orders list', () => {
        render(<LabOrderDetail />);
        
        const backButton = screen.getByText(/back to orders/i);
        fireEvent.click(backButton);
        
        expect(mockNavigate).toHaveBeenCalledWith('/dashboard/lab/orders');
    });

    test('displays timeline section', () => {
        render(<LabOrderDetail />);
        
        expect(screen.getByText(/timeline/i)).toBeInTheDocument();
        expect(screen.getByText(/order placed/i)).toBeInTheDocument();
    });

    test('handles collect sample button click', () => {
        const alertMock = jest.spyOn(window, 'alert').mockImplementation(() => {});
        
        render(<LabOrderDetail />);
        
        const collectButton = screen.getByText(/mark sample collected/i);
        fireEvent.click(collectButton);
        
        expect(alertMock).toHaveBeenCalledWith('Sample marked as collected');
        alertMock.mockRestore();
    });
});

describe('Lab Order Detail - Navigation', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    test('has back to orders button', () => {
        render(<LabOrderDetail />);
        
        // The component should have a back button to navigate to orders list
        expect(screen.getByText(/back to orders/i)).toBeInTheDocument();
    });
});
