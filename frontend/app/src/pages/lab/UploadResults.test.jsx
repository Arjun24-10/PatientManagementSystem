import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import UploadResults from './UploadResults';

// Mock the mock data
jest.mock('../../mocks/labOrders', () => ({
    mockLabOrders: [
        { id: 'L-1', patientName: 'John Doe', status: 'Pending', testType: 'Blood' }
    ]
}));

const renderWithRouter = (component) => {
    return render(
        <BrowserRouter>
            {component}
        </BrowserRouter>
    );
};

describe('UploadResults Component', () => {
    test('renders upload form', () => {
        renderWithRouter(<UploadResults />);
        expect(screen.getByText('Upload Lab Results')).toBeInTheDocument();
        expect(screen.getByText(/Select Lab Order/i)).toBeInTheDocument();
        expect(screen.getByText(/Manual Result Entry/i)).toBeInTheDocument();
    });

    test('submit button is disabled initially', () => {
        renderWithRouter(<UploadResults />);
        const submitBtn = screen.getByText('Submit Results');
        expect(submitBtn).toBeDisabled();
    });

    test('submit button enables when order and manual entry are filled', () => {
        renderWithRouter(<UploadResults />);

        const select = screen.getByRole('combobox');
        fireEvent.change(select, { target: { value: 'L-1' } });

        const textarea = screen.getByPlaceholderText(/Enter test values/i);
        fireEvent.change(textarea, { target: { value: 'Test value 123' } });

        const submitBtn = screen.getByText('Submit Results');
        expect(submitBtn).not.toBeDisabled();
    });
});
