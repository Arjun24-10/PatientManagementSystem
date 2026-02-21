import React from 'react';
import { render, screen, fireEvent } from '../../test-utils';
import userEvent from '@testing-library/user-event';
import LabOrders from './Orders';

// Mock useNavigate
const mockNavigate = jest.fn();
jest.mock('react-router-dom', () => ({
    ...jest.requireActual('react-router-dom'),
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
            orderDate: '2024-01-15T08:00:00Z',
        },
        {
            id: 'LAB002',
            patientName: 'Jane Doe',
            patientId: 'P002',
            testType: 'Lipid Panel',
            status: 'Collected',
            priority: 'Normal',
            orderDate: '2024-01-14T09:00:00Z',
        },
        {
            id: 'LAB003',
            patientName: 'Bob Wilson',
            patientId: 'P003',
            testType: 'Metabolic Panel',
            status: 'Completed',
            priority: 'Urgent',
            orderDate: '2024-01-13T10:00:00Z',
        },
    ],
}));

describe('Lab Orders Page', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    test('renders lab orders page with title', () => {
        render(<LabOrders />);

        expect(screen.getByText(/lab orders/i)).toBeInTheDocument();
        expect(screen.getByText(/manage and process patient lab tests/i)).toBeInTheDocument();
    });

    test('renders search input', () => {
        render(<LabOrders />);

        expect(screen.getByPlaceholderText(/search orders/i)).toBeInTheDocument();
    });

    test('renders Upload Results button', () => {
        render(<LabOrders />);

        expect(screen.getByRole('button', { name: /upload results/i })).toBeInTheDocument();
    });

    test('displays all orders initially', () => {
        render(<LabOrders />);

        expect(screen.getByText('John Smith')).toBeInTheDocument();
        expect(screen.getByText('Jane Doe')).toBeInTheDocument();
        expect(screen.getByText('Bob Wilson')).toBeInTheDocument();
    });

    test('filters orders by search term', async () => {
        render(<LabOrders />);

        const searchInput = screen.getByPlaceholderText(/search orders/i);
        await userEvent.type(searchInput, 'John');

        expect(screen.getByText('John Smith')).toBeInTheDocument();
        expect(screen.queryByText('Jane Doe')).not.toBeInTheDocument();
    });

    test('filters orders by order ID', async () => {
        render(<LabOrders />);

        const searchInput = screen.getByPlaceholderText(/search orders/i);
        await userEvent.type(searchInput, 'LAB002');

        expect(screen.getByText('Jane Doe')).toBeInTheDocument();
        expect(screen.queryByText('John Smith')).not.toBeInTheDocument();
    });

    test('renders status filter buttons', () => {
        render(<LabOrders />);

        const filterButton = screen.getByRole('button', { name: /^all$/i });
        expect(filterButton).toBeInTheDocument();

        // Open dropdown
        fireEvent.click(filterButton);

        expect(screen.getByRole('button', { name: /^pending$/i })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /^collected$/i })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /^completed$/i })).toBeInTheDocument();
    });

    test('filters orders by status', async () => {
        render(<LabOrders />);

        // Open dropdown
        const filterButton = screen.getByRole('button', { name: /^all$/i });
        fireEvent.click(filterButton);

        const pendingButton = screen.getByRole('button', { name: /^pending$/i });
        fireEvent.click(pendingButton);

        expect(screen.getByText('John Smith')).toBeInTheDocument();
        expect(screen.queryByText('Jane Doe')).not.toBeInTheDocument();
        expect(screen.queryByText('Bob Wilson')).not.toBeInTheDocument();
    });

    test('renders table headers', () => {
        render(<LabOrders />);

        expect(screen.getByText(/order id/i)).toBeInTheDocument();
        expect(screen.getByRole('columnheader', { name: /patient/i })).toBeInTheDocument();
        expect(screen.getByText(/test type/i)).toBeInTheDocument();
        expect(screen.getByRole('columnheader', { name: /priority/i })).toBeInTheDocument();
        expect(screen.getByRole('columnheader', { name: /status/i })).toBeInTheDocument();
        expect(screen.getByRole('columnheader', { name: /date/i })).toBeInTheDocument();
    });

    test('displays priority badges', () => {
        render(<LabOrders />);

        expect(screen.getByText('High')).toBeInTheDocument();
        expect(screen.getByText('Normal')).toBeInTheDocument();
        expect(screen.getByText('Urgent')).toBeInTheDocument();
    });

    test('navigates to upload results page', () => {
        render(<LabOrders />);

        const uploadButton = screen.getByRole('button', { name: /upload results/i });
        fireEvent.click(uploadButton);

        expect(mockNavigate).toHaveBeenCalledWith('/dashboard/lab/upload');
    });

    test('displays View Details buttons for each order', () => {
        render(<LabOrders />);

        const viewButtons = screen.getAllByText(/view/i);
        expect(viewButtons.length).toBeGreaterThan(0);
    });
});
