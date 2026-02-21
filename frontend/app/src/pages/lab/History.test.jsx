import React from 'react';
import { render, screen, fireEvent } from '../../test-utils';
import userEvent from '@testing-library/user-event';
import LabHistory from './History';

// Mock the lab orders data
jest.mock('../../mocks/labOrders', () => ({
    mockLabOrders: [
        {
            id: 'LAB001',
            patientName: 'John Smith',
            patientId: 'P001',
            testType: 'Complete Blood Count',
            status: 'Completed',
            completedDate: '2024-01-15T10:00:00Z',
            priority: 'Normal',
        },
        {
            id: 'LAB002',
            patientName: 'Jane Doe',
            patientId: 'P002',
            testType: 'Lipid Panel',
            status: 'Completed',
            completedDate: '2024-01-14T14:30:00Z',
            priority: 'High',
        },
        {
            id: 'LAB003',
            patientName: 'Bob Wilson',
            patientId: 'P003',
            testType: 'Metabolic Panel',
            status: 'Pending',
            priority: 'Normal',
        },
    ],
}));

describe('Lab History Page', () => {
    test('renders lab history page with title', () => {
        render(<LabHistory />);

        expect(screen.getByText(/lab history/i)).toBeInTheDocument();
        expect(screen.getByText(/archive of all completed lab tests/i)).toBeInTheDocument();
    });

    test('renders search input', () => {
        render(<LabHistory />);

        expect(screen.getByPlaceholderText(/search by patient or test/i)).toBeInTheDocument();
    });

    test('displays all orders', () => {
        render(<LabHistory />);

        expect(screen.getByText('John Smith')).toBeInTheDocument();
        expect(screen.getByText('Jane Doe')).toBeInTheDocument();
        expect(screen.getByText('Bob Wilson')).toBeInTheDocument();
    });

    test('filters orders by patient name', async () => {
        render(<LabHistory />);

        const searchInput = screen.getByPlaceholderText(/search by patient or test/i);
        await userEvent.type(searchInput, 'John');

        expect(screen.getByText('John Smith')).toBeInTheDocument();
        expect(screen.queryByText('Jane Doe')).not.toBeInTheDocument();
    });

    test('filters orders by test type', async () => {
        render(<LabHistory />);

        const searchInput = screen.getByPlaceholderText(/search by patient or test/i);
        await userEvent.type(searchInput, 'Lipid');

        expect(screen.getByText('Jane Doe')).toBeInTheDocument();
        expect(screen.queryByText('John Smith')).not.toBeInTheDocument();
    });

    test('renders table headers', () => {
        render(<LabHistory />);

        expect(screen.getByRole('columnheader', { name: /order id/i })).toBeInTheDocument();
        expect(screen.getByRole('columnheader', { name: /patient/i })).toBeInTheDocument();
        expect(screen.getByRole('columnheader', { name: /^test$/i })).toBeInTheDocument();
        expect(screen.getByRole('columnheader', { name: /completed date/i })).toBeInTheDocument();
        expect(screen.getByRole('columnheader', { name: /status/i })).toBeInTheDocument();
        expect(screen.getByRole('columnheader', { name: /report/i })).toBeInTheDocument();
    });

    test('renders date range inputs', () => {
        render(<LabHistory />);

        // The component now uses date input fields instead of a "Date Range" button
        const dateInputs = document.querySelectorAll('input[type="date"]');
        expect(dateInputs.length).toBe(2);
    });

    test('displays completed badge for orders', () => {
        render(<LabHistory />);

        const completedBadges = screen.getAllByText(/completed/i);
        expect(completedBadges.length).toBeGreaterThan(0);
    });

    test('renders PDF download buttons', () => {
        render(<LabHistory />);

        const pdfButtons = screen.getAllByText(/pdf/i);
        expect(pdfButtons.length).toBeGreaterThan(0);
    });
});
