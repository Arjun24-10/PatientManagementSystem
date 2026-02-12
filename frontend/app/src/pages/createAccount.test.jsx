import React from 'react';
import { render, screen, fireEvent, waitFor } from '../test-utils';
import CreateAccount from './createAccount';
import { useAuth } from '../contexts/AuthContext';

// Mock the hooks
jest.mock('react-router-dom', () => ({
    ...jest.requireActual('react-router-dom'),
    useNavigate: () => jest.fn(),
}));

jest.mock('../contexts/AuthContext', () => ({
    useAuth: jest.fn(),
}));

describe('CreateAccount Page', () => {
    const mockSignup = jest.fn();
    const mockNavigate = jest.fn();

    beforeEach(() => {
        useAuth.mockReturnValue({
            signup: mockSignup,
        });
        // Reset mocks
        mockSignup.mockReset();
    });

    test('renders create account form correctly', () => {
        render(<CreateAccount />);

        expect(screen.getByText(/Create Account/i)).toBeInTheDocument();
        expect(screen.getByLabelText(/Full Name/i)).toBeInTheDocument();
        expect(screen.getByLabelText(/Email Address/i)).toBeInTheDocument();
        expect(screen.getByLabelText(/Mobile Number/i)).toBeInTheDocument();
        expect(screen.getByLabelText(/Password/i)).toBeInTheDocument();
        expect(screen.getByLabelText(/Confirm Password/i)).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /Create Account/i })).toBeInTheDocument();
    });

    test('shows error when fields are empty', async () => {
        render(<CreateAccount />);

        // Fill only one field
        fireEvent.change(screen.getByLabelText(/Full Name/i), { target: { value: 'Test User' } });

        fireEvent.click(screen.getByRole('button', { name: /Create Account/i }));

        // Check for error message
        // Note: The component sets error state if validation fails.
        expect(await screen.findByText(/Please complete all required fields/i)).toBeInTheDocument();
        expect(mockSignup).not.toHaveBeenCalled();
    });

    test('shows error when passwords do not match', async () => {
        render(<CreateAccount />);

        fireEvent.change(screen.getByLabelText(/Full Name/i), { target: { value: 'Test User' } });
        fireEvent.change(screen.getByLabelText(/Email Address/i), { target: { value: 'test@example.com' } });
        fireEvent.change(screen.getByLabelText(/Mobile Number/i), { target: { value: '1234567890' } });
        fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'password12345' } });
        fireEvent.change(screen.getByLabelText(/Confirm Password/i), { target: { value: 'passwordDifferent' } });

        fireEvent.click(screen.getByRole('button', { name: /Create Account/i }));

        expect(await screen.findByText(/Passwords do not match/i)).toBeInTheDocument();
        expect(mockSignup).not.toHaveBeenCalled();
    });

    test('shows error when password is too short', async () => {
        render(<CreateAccount />);

        fireEvent.change(screen.getByLabelText(/Full Name/i), { target: { value: 'Test User' } });
        fireEvent.change(screen.getByLabelText(/Email Address/i), { target: { value: 'test@example.com' } });
        fireEvent.change(screen.getByLabelText(/Mobile Number/i), { target: { value: '1234567890' } });
        fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'short' } });
        fireEvent.change(screen.getByLabelText(/Confirm Password/i), { target: { value: 'short' } });

        fireEvent.click(screen.getByRole('button', { name: /Create Account/i }));

        expect(await screen.findByText(/Password must be at least 12 characters long/i)).toBeInTheDocument();
    });

    test('calls signup on valid submission', async () => {
        mockSignup.mockResolvedValue({ success: true });

        render(<CreateAccount />);

        fireEvent.change(screen.getByLabelText(/Full Name/i), { target: { value: 'Test User' } });
        fireEvent.change(screen.getByLabelText(/Email Address/i), { target: { value: 'test@example.com' } });
        fireEvent.change(screen.getByLabelText(/Mobile Number/i), { target: { value: '9876543210' } });
        fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'password123456' } });
        fireEvent.change(screen.getByLabelText(/Confirm Password/i), { target: { value: 'password123456' } });

        fireEvent.click(screen.getByRole('button', { name: /Create Account/i }));

        await waitFor(() => {
            expect(mockSignup).toHaveBeenCalledWith('test@example.com', 'password123456', {
                role: 'PATIENT',
                name: 'Test User',
                phone: '9876543210'
            });
        });

        expect(await screen.findByText(/Account created successfully/i)).toBeInTheDocument();
    });

    test('displays error from backend', async () => {
        mockSignup.mockResolvedValue({ success: false, error: 'Email already in use' });

        render(<CreateAccount />);

        fireEvent.change(screen.getByLabelText(/Full Name/i), { target: { value: 'Test User' } });
        fireEvent.change(screen.getByLabelText(/Email Address/i), { target: { value: 'test@example.com' } });
        fireEvent.change(screen.getByLabelText(/Mobile Number/i), { target: { value: '9876543210' } });
        fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'password123456' } });
        fireEvent.change(screen.getByLabelText(/Confirm Password/i), { target: { value: 'password123456' } });

        fireEvent.click(screen.getByRole('button', { name: /Create Account/i }));

        await waitFor(() => {
            expect(mockSignup).toHaveBeenCalled();
        });

        expect(await screen.findByText(/Email already in use/i)).toBeInTheDocument();
    });
});
