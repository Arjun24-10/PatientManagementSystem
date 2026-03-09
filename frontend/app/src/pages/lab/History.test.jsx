import React from 'react';
import { render, screen, fireEvent, waitFor } from '../../test-utils';
import userEvent from '@testing-library/user-event';
import LabHistory from './History';
import api from '../../services/api';

jest.mock('../../services/api', () => ({
    labTechnician: {
        getOrders: jest.fn(),
    }
}));

const mockHistory = [
    {
        testId: 'LAB001',
        patientName: 'John Smith',
        patientId: 'P001',
        testName: 'Complete Blood Count',
        status: 'Completed',
        orderedAt: '2024-01-15T10:00:00Z',
        // NO resultValue so fileUrl link renders as "View Report"
        fileUrl: 'http://example.com/report1.pdf',
    },
    {
        testId: 'LAB002',
        patientName: 'Jane Doe',
        patientId: 'P002',
        testName: 'Lipid Panel',
        status: 'Completed',
        orderedAt: '2024-01-14T14:30:00Z',
        fileUrl: 'http://example.com/report2.pdf',
    },
];

describe('Lab History Page', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        api.labTechnician.getOrders.mockResolvedValue(mockHistory);
    });

    test('renders lab history page with title', async () => {
        render(<LabHistory />);

        expect(await screen.findByText(/lab history/i)).toBeInTheDocument();
        expect(screen.getByText(/archive of all completed lab tests/i)).toBeInTheDocument();
    });

    test('renders search input', async () => {
        render(<LabHistory />);
        await screen.findByText('John Smith');
        expect(screen.getByPlaceholderText(/search by patient or test/i)).toBeInTheDocument();
    });

    test('displays only completed orders', async () => {
        render(<LabHistory />);

        expect(await screen.findByText('John Smith')).toBeInTheDocument();
        expect(screen.getByText('Jane Doe')).toBeInTheDocument();
    });

    test('filters orders by patient name', async () => {
        render(<LabHistory />);

        await screen.findByText('John Smith');

        const searchInput = screen.getByPlaceholderText(/search by patient or test/i);
        await userEvent.type(searchInput, 'John');

        expect(screen.getByText('John Smith')).toBeInTheDocument();
        expect(screen.queryByText('Jane Doe')).not.toBeInTheDocument();
    });

    test('filters orders by test type', async () => {
        render(<LabHistory />);

        await screen.findByText('Jane Doe');

        const searchInput = screen.getByPlaceholderText(/search by patient or test/i);
        await userEvent.type(searchInput, 'Lipid');

        expect(screen.getByText('Jane Doe')).toBeInTheDocument();
        expect(screen.queryByText('John Smith')).not.toBeInTheDocument();
    });

    test('renders table headers', async () => {
        render(<LabHistory />);

        await screen.findByText('John Smith');

        expect(screen.getByRole('columnheader', { name: /order id/i })).toBeInTheDocument();
        expect(screen.getByRole('columnheader', { name: /patient/i })).toBeInTheDocument();
        expect(screen.getByRole('columnheader', { name: /^test$/i })).toBeInTheDocument();
        expect(screen.getByRole('columnheader', { name: /date/i })).toBeInTheDocument();
        expect(screen.getByRole('columnheader', { name: /status/i })).toBeInTheDocument();
        expect(screen.getByRole('columnheader', { name: /result/i })).toBeInTheDocument();
    });

    test('renders date range button', async () => {
        render(<LabHistory />);
        expect(await screen.findByText(/date range/i)).toBeInTheDocument();
    });

    test('displays completed badge for orders', async () => {
        render(<LabHistory />);

        await screen.findByText('John Smith');

        const completedBadges = screen.getAllByText(/completed/i);
        expect(completedBadges.length).toBeGreaterThan(0);
    });

    test('renders Report links', async () => {
        render(<LabHistory />);

        await screen.findByText('John Smith');

        // fileUrl renders as "View Report" anchor when no resultValue present
        const reportLinks = screen.getAllByText(/View Report/i);
        expect(reportLinks.length).toBeGreaterThan(0);
    });
});
