import React from 'react';
import { render, screen, fireEvent, waitFor } from '../../test-utils';
import { act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import UploadResults from './UploadResults';

// Mock the lab orders data
jest.mock('../../mocks/labOrders', () => ({
    mockLabOrders: [
        {
            id: 'LAB001',
            patientName: 'John Smith',
            testType: 'Complete Blood Count',
            status: 'Pending',
        },
        {
            id: 'LAB002',
            patientName: 'Jane Doe',
            testType: 'Lipid Panel',
            status: 'Collected',
        },
        {
            id: 'LAB003',
            patientName: 'Bob Wilson',
            testType: 'Metabolic Panel',
            status: 'Completed',
        },
    ],
}));

describe('Upload Results Page', () => {
    beforeEach(() => {
        jest.useFakeTimers();
    });

    afterEach(() => {
        jest.useRealTimers();
    });

    test('renders upload results page with title', () => {
        render(<UploadResults />);

        expect(screen.getByText(/upload lab results/i)).toBeInTheDocument();
        expect(screen.getByText(/attach files or enter manual results/i)).toBeInTheDocument();
    });

    test('renders order selection dropdown', () => {
        render(<UploadResults />);

        expect(screen.getByText(/select lab order/i)).toBeInTheDocument();
        expect(screen.getByRole('combobox')).toBeInTheDocument();
    });

    test('only shows non-completed orders in dropdown', () => {
        render(<UploadResults />);

        const dropdown = screen.getByRole('combobox');

        // Check dropdown options - Completed orders should not be shown
        expect(screen.getByText(/lab001 - john smith/i)).toBeInTheDocument();
        expect(screen.getByText(/lab002 - jane doe/i)).toBeInTheDocument();
        expect(screen.queryByText(/lab003 - bob wilson/i)).not.toBeInTheDocument();
    });

    test('renders file upload area', () => {
        render(<UploadResults />);

        expect(screen.getByText(/upload report file/i)).toBeInTheDocument();
        expect(screen.getByText(/upload a file/i)).toBeInTheDocument();
        expect(screen.getByText(/or drag and drop/i)).toBeInTheDocument();
    });

    test('renders manual result entry textarea', () => {
        render(<UploadResults />);

        expect(screen.getByText(/manual result entry/i)).toBeInTheDocument();
        expect(screen.getByPlaceholderText(/enter test values/i)).toBeInTheDocument();
    });

    test('allows selecting a lab order', async () => {
        render(<UploadResults />);

        const dropdown = screen.getByRole('combobox');
        await userEvent.selectOptions(dropdown, 'LAB001');

        expect(dropdown).toHaveValue('LAB001');
    });

    test('allows entering manual results', async () => {
        render(<UploadResults />);

        const textarea = screen.getByPlaceholderText(/enter test values/i);
        await userEvent.type(textarea, 'WBC: 7.5 x10^9/L');

        expect(textarea).toHaveValue('WBC: 7.5 x10^9/L');
    });

    test('renders submit button', () => {
        render(<UploadResults />);

        expect(screen.getByRole('button', { name: /submit results/i })).toBeInTheDocument();
    });

    test('shows file info when file is selected', async () => {
        render(<UploadResults />);

        const file = new File(['test content'], 'test-report.pdf', { type: 'application/pdf' });
        const fileInput = screen.getByLabelText(/upload a file/i);

        Object.defineProperty(fileInput, 'files', {
            value: [file],
        });

        fireEvent.change(fileInput);

        await waitFor(() => {
            expect(screen.getByText('test-report.pdf')).toBeInTheDocument();
        });
    });

    test('allows removing selected file', async () => {
        render(<UploadResults />);

        const file = new File(['test content'], 'test-report.pdf', { type: 'application/pdf' });
        const fileInput = screen.getByLabelText(/upload a file/i);

        Object.defineProperty(fileInput, 'files', {
            value: [file],
        });

        fireEvent.change(fileInput);

        await waitFor(() => {
            expect(screen.getByText('test-report.pdf')).toBeInTheDocument();
        });

        const removeButton = screen.getByText(/remove/i);
        fireEvent.click(removeButton);

        expect(screen.queryByText('test-report.pdf')).not.toBeInTheDocument();
    });

    test('shows uploading state when submitting', async () => {
        render(<UploadResults />);

        const dropdown = screen.getByRole('combobox');
        fireEvent.change(dropdown, { target: { value: 'LAB001' } });

        // Need to enter testValues or file to enable submit
        const textarea = screen.getByPlaceholderText(/enter test values/i);
        fireEvent.change(textarea, { target: { value: 'WBC: 7.5' } });

        const submitButton = screen.getByRole('button', { name: /submit results/i });
        fireEvent.click(submitButton);

        expect(screen.getByText(/uploading/i)).toBeInTheDocument();
    });

    test('shows success state after upload', async () => {
        render(<UploadResults />);

        const dropdown = screen.getByRole('combobox');
        fireEvent.change(dropdown, { target: { value: 'LAB001' } });

        // Need to enter testValues or file to enable submit
        const textarea = screen.getByPlaceholderText(/enter test values/i);
        fireEvent.change(textarea, { target: { value: 'WBC: 7.5' } });

        const submitButton = screen.getByRole('button', { name: /submit results/i });
        fireEvent.click(submitButton);

        // Fast-forward timers to complete upload simulation
        act(() => {
            jest.advanceTimersByTime(1500);
        });

        await waitFor(() => {
            expect(screen.getByText(/results uploaded successfully/i)).toBeInTheDocument();
        });

        // Fast-forward the rest of the timers so they don't fire after test completes
        act(() => {
            jest.runAllTimers();
        });
    });

    test('displays file type restrictions', () => {
        render(<UploadResults />);

        expect(screen.getByText(/pdf, png, jpg up to 10mb/i)).toBeInTheDocument();
    });
});
