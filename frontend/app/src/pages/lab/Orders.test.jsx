import React from 'react';
import { render, screen, fireEvent, waitFor } from '../../test-utils';
import userEvent from '@testing-library/user-event';
import LabOrders from './Orders';
import api from '../../services/api';

// Mock useNavigate
const mockNavigate = jest.fn();
jest.mock('react-router-dom', () => ({
    ...jest.requireActual('react-router-dom'),
    useNavigate: () => mockNavigate,
}));

jest.mock('../../services/api', () => ({
    labTechnician: {
        getOrders: jest.fn(),
    }
}));

const mockOrders = [
    {
        testId: 'LAB001',
        patientName: 'John Smith',
        patientId: 'P001',
        testType: 'Complete Blood Count',
        testName: 'Complete Blood Count',
        status: 'Pending',
        testCategory: 'High',
        orderedAt: '2024-01-15T08:00:00Z',
    },
    {
        testId: 'LAB002',
        patientName: 'Jane Doe',
        patientId: 'P002',
        testType: 'Lipid Panel',
        testName: 'Lipid Panel',
        status: 'Collected',
        testCategory: 'Normal',
        orderedAt: '2024-01-14T09:00:00Z',
    },
    {
        testId: 'LAB003',
        patientName: 'Bob Wilson',
        patientId: 'P003',
        testType: 'Metabolic Panel',
        testName: 'Metabolic Panel',
        status: 'Completed',
        testCategory: 'Urgent',
        orderedAt: '2024-01-13T10:00:00Z',
    },
];

describe('Lab Orders Page', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        api.labTechnician.getOrders.mockResolvedValue(mockOrders);
    });

    test('renders lab orders page with title', async () => {
        render(<LabOrders />);

        expect(await screen.findByText(/lab orders/i)).toBeInTheDocument();
        expect(screen.getByText(/manage and process patient lab tests/i)).toBeInTheDocument();
    });

    test('renders search input', async () => {
        render(<LabOrders />);
        await screen.findByText('John Smith');
        expect(screen.getByPlaceholderText(/search orders/i)).toBeInTheDocument();
    });

    test('renders Upload Results button', async () => {
        render(<LabOrders />);
        expect(await screen.findByRole('button', { name: /upload results/i })).toBeInTheDocument();
    });

    test('displays all orders initially', async () => {
        render(<LabOrders />);

        expect(await screen.findByText('John Smith')).toBeInTheDocument();
        expect(screen.getByText('Jane Doe')).toBeInTheDocument();
        expect(screen.getByText('Bob Wilson')).toBeInTheDocument();
    });

    test('filters orders by search term', async () => {
        render(<LabOrders />);

        await screen.findByText('John Smith');

        const searchInput = screen.getByPlaceholderText(/search orders/i);
        await userEvent.type(searchInput, 'John');

        expect(screen.getByText('John Smith')).toBeInTheDocument();
        expect(screen.queryByText('Jane Doe')).not.toBeInTheDocument();
    });

    test('filters orders by order ID', async () => {
        render(<LabOrders />);

        await screen.findByText('John Smith');

        const searchInput = screen.getByPlaceholderText(/search orders/i);
        await userEvent.type(searchInput, 'LAB002');

        expect(screen.getByText('Jane Doe')).toBeInTheDocument();
        expect(screen.queryByText('John Smith')).not.toBeInTheDocument();
    });

    test('renders status filter dropdown', async () => {
        render(<LabOrders />);

        await screen.findByText('John Smith');

        const filterButton = screen.getByRole('button', { name: /^all$/i });
        expect(filterButton).toBeInTheDocument();

        fireEvent.click(filterButton);
        expect(screen.getAllByText('Pending').length).toBeGreaterThanOrEqual(1);
        expect(screen.getAllByText('Collected').length).toBeGreaterThanOrEqual(1);
        expect(screen.getAllByText('Completed').length).toBeGreaterThanOrEqual(1);
    });

    test('filters orders by status', async () => {
        // Component re-fetches when filter changes; second call returns only Pending orders
        api.labTechnician.getOrders.mockResolvedValueOnce(mockOrders);
        api.labTechnician.getOrders.mockResolvedValueOnce(mockOrders.filter(o => o.status === 'Pending'));

        render(<LabOrders />);

        await screen.findByText('John Smith');

        const filterButton = screen.getByRole('button', { name: /^all$/i });
        fireEvent.click(filterButton);

        const pendingElements = screen.getAllByText('Pending');
        const pendingOption = pendingElements.find(el => el.tagName === 'BUTTON' && el.classList.contains('w-full'));
        fireEvent.click(pendingOption);

        await waitFor(() => {
            expect(screen.getByText('John Smith')).toBeInTheDocument();
        });
        expect(screen.queryByText('Jane Doe')).not.toBeInTheDocument();
        expect(screen.queryByText('Bob Wilson')).not.toBeInTheDocument();
    });

    test('renders table headers', async () => {
        render(<LabOrders />);

        await screen.findByText('John Smith');

        expect(screen.getByText(/order id/i)).toBeInTheDocument();
        expect(screen.getByRole('columnheader', { name: /patient/i })).toBeInTheDocument();
        expect(screen.getByText(/test type/i)).toBeInTheDocument();
        expect(screen.getByRole('columnheader', { name: /priority/i })).toBeInTheDocument();
        expect(screen.getByRole('columnheader', { name: /status/i })).toBeInTheDocument();
        expect(screen.getByRole('columnheader', { name: /date/i })).toBeInTheDocument();
    });

    test('displays priority badges', async () => {
        render(<LabOrders />);

        await screen.findByText('John Smith');

        expect(screen.getByText('High')).toBeInTheDocument();
        expect(screen.getByText('Normal')).toBeInTheDocument();
        expect(screen.getByText('Urgent')).toBeInTheDocument();
    });

    test('navigates to upload results page', async () => {
        render(<LabOrders />);

        const uploadButton = await screen.findByRole('button', { name: /upload results/i });
        fireEvent.click(uploadButton);

        expect(mockNavigate).toHaveBeenCalledWith('/dashboard/lab/upload');
    });

    test('displays View Details buttons for each order', async () => {
        render(<LabOrders />);

        await screen.findByText('John Smith');

        const viewButtons = screen.getAllByText(/view/i);
        expect(viewButtons.length).toBeGreaterThan(0);
    });
});
