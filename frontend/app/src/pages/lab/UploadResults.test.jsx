import React from 'react';
import { render, screen, fireEvent, waitFor } from '../../test-utils';
import { act } from '@testing-library/react';
import UploadResults from './UploadResults';
import api from '../../services/api';

jest.mock('../../services/api', () => ({
    labTechnician: {
        getOrders: jest.fn(),
        uploadResults: jest.fn()
    }
}));

const mockOrders = [
    { testId: 'LAB001', patientName: 'John Smith', testName: 'Complete Blood Count', status: 'Pending' },
    { testId: 'LAB002', patientName: 'Jane Doe', testName: 'Lipid Panel', status: 'Collected' },
    { testId: 'LAB003', patientName: 'Bob Wilson', testName: 'Metabolic Panel', status: 'Completed' },
];

describe('Upload Results Page', () => {
    beforeEach(() => {
        // NO fake timers here — useFakeTimers breaks waitFor/findBy* for all tests
        jest.clearAllMocks();
        api.labTechnician.getOrders.mockResolvedValue(mockOrders);
        api.labTechnician.uploadResults.mockResolvedValue({});
    });

    test('renders upload results page with title', async () => {
        render(<UploadResults />);

        expect(await screen.findByText(/upload lab results/i)).toBeInTheDocument();
        expect(screen.getByText(/attach files or enter manual results/i)).toBeInTheDocument();
    });

    test('renders order selection dropdown', async () => {
        render(<UploadResults />);

        expect(await screen.findByText(/select lab order/i)).toBeInTheDocument();
        expect(screen.getByRole('combobox')).toBeInTheDocument();
    });

    test('only shows non-completed orders in dropdown', async () => {
        render(<UploadResults />);

        const dropdown = screen.getByRole('combobox');
        // Wait for options to populate in DOM (happens after async state update)
        await waitFor(() => expect(dropdown.options.length).toBeGreaterThan(1));

        // Completed order (LAB003) should not be in the options
        const optionValues = Array.from(dropdown.options).map(o => o.value);
        expect(optionValues).not.toContain('LAB003');
        expect(optionValues).toContain('LAB001');
        expect(optionValues).toContain('LAB002');
    });

    test('renders file upload area', async () => {
        render(<UploadResults />);

        expect(await screen.findByText(/reference report file/i)).toBeInTheDocument();
        expect(screen.getByText(/upload a file/i)).toBeInTheDocument();
        expect(screen.getByText(/or drag and drop/i)).toBeInTheDocument();
    });

    test('renders manual result entry textarea', async () => {
        render(<UploadResults />);

        expect(await screen.findByText(/Test Result Value/i)).toBeInTheDocument();
        expect(screen.getByPlaceholderText(/enter test results/i)).toBeInTheDocument();
    });

    test('allows selecting a lab order', async () => {
        render(<UploadResults />);

        const dropdown = screen.getByRole('combobox');
        await waitFor(() => expect(dropdown.options.length).toBeGreaterThan(1));

        fireEvent.change(dropdown, { target: { value: 'LAB001' } });

        expect(dropdown).toHaveValue('LAB001');
    });

    test('allows entering manual results', async () => {
        render(<UploadResults />);

        const textarea = await screen.findByPlaceholderText(/enter test results/i);
        fireEvent.change(textarea, { target: { value: 'WBC: 7.5 x10^9/L' } });

        expect(textarea).toHaveValue('WBC: 7.5 x10^9/L');
    });

    test('renders submit button', async () => {
        render(<UploadResults />);

        expect(await screen.findByRole('button', { name: /submit/i })).toBeInTheDocument();
    });

    test('shows file info when file is selected', async () => {
        render(<UploadResults />);

        const file = new File(['test content'], 'test-report.pdf', { type: 'application/pdf' });
        const fileInput = await screen.findByLabelText(/upload a file/i);

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
        const fileInput = await screen.findByLabelText(/upload a file/i);

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
        await waitFor(() => expect(dropdown.options.length).toBeGreaterThan(1));
        fireEvent.change(dropdown, { target: { value: 'LAB001' } });

        const textarea = screen.getByPlaceholderText(/enter test results/i);
        fireEvent.change(textarea, { target: { value: 'WBC: 7.5' } });

        const submitButton = screen.getByRole('button', { name: /submit/i });
        await waitFor(() => expect(submitButton).not.toBeDisabled());
        fireEvent.click(submitButton);

        expect(await screen.findByText(/uploading/i)).toBeInTheDocument();
    });

    test('shows success state after upload', async () => {
        render(<UploadResults />);

        const dropdown = screen.getByRole('combobox');
        await waitFor(() => expect(dropdown.options.length).toBeGreaterThan(1));
        fireEvent.change(dropdown, { target: { value: 'LAB001' } });

        const textarea = screen.getByPlaceholderText(/enter test results/i);
        fireEvent.change(textarea, { target: { value: 'WBC: 7.5' } });

        const submitButton = screen.getByRole('button', { name: /submit/i });
        await waitFor(() => expect(submitButton).not.toBeDisabled());
        fireEvent.click(submitButton);

        // uploadResults resolves immediately, success state should appear
        await waitFor(() => {
            expect(screen.getByText(/results uploaded successfully/i)).toBeInTheDocument();
        });
    });

    test('displays file type restrictions', async () => {
        render(<UploadResults />);

        expect(await screen.findByText(/pdf, png, jpg up to 10mb/i)).toBeInTheDocument();
    });
});
