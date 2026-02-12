import React from 'react';
import { render, screen, fireEvent, waitFor } from '../test-utils';
import Login from './login';
import { useAuth } from '../contexts/AuthContext';
import { mockLogin } from '../mocks/auth';

// Mock the hooks and dependencies
jest.mock('react-router-dom', () => ({
    ...jest.requireActual('react-router-dom'),
    useNavigate: () => jest.fn(),
}));

jest.mock('../contexts/AuthContext', () => ({
    useAuth: jest.fn(),
}));

jest.mock('../mocks/auth', () => ({
    mockLogin: jest.fn(),
}));

describe('Login Page', () => {
    const mockAuthLogin = jest.fn();
    const mockNavigate = jest.fn();

    beforeEach(() => {
        useAuth.mockReturnValue({
            login: mockAuthLogin,
        });
        // Reset mocks
        mockAuthLogin.mockReset();
        mockLogin.mockReset();

        // Mock useNavigate (a bit tricky with jest.mock factory, but we can rely on integration or simplistic mocking)
        // For this test specific setup, we might need to verify calls if we could import the mock, 
        // but typically we test the side effects like calls to login.
    });

    test('renders login form correctly', () => {
        render(<Login />);

        expect(screen.getByText(/Welcome Back/i)).toBeInTheDocument();
        expect(screen.getByLabelText(/Email or Username/i)).toBeInTheDocument();
        expect(screen.getByLabelText(/Password/i)).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /Sign In/i })).toBeInTheDocument();
        expect(screen.getByText(/Don't have an account\?/i)).toBeInTheDocument();
    });

    test('shows validation errors for empty fields', async () => {
        render(<Login />);

        fireEvent.click(screen.getByRole('button', { name: /Sign In/i }));

        expect(await screen.findByText(/Please enter email and password/i)).toBeInTheDocument();
        expect(mockLogin).not.toHaveBeenCalled();
        expect(mockAuthLogin).not.toHaveBeenCalled();
    });

    test('handles successful login via mock auth', async () => {
        mockLogin.mockResolvedValue({
            success: true,
            user: { id: '1', name: 'Test User', role: 'PATIENT' },
            redirectTo: '/dashboard/patient'
        });

        render(<Login />);

        fireEvent.change(screen.getByLabelText(/Email or Username/i), { target: { value: 'test@example.com' } });
        fireEvent.change(screen.getByLabelText(/Password/i), { target: { value: 'password123' } });

        fireEvent.click(screen.getByRole('button', { name: /Sign In/i }));

        await waitFor(() => {
            expect(mockLogin).toHaveBeenCalledWith('test@example.com', 'password123', false);
        });

        expect(await screen.findByText(/Login successful!/i)).toBeInTheDocument();
    });

    test('handles failed login', async () => {
        mockLogin.mockResolvedValue({ success: false, error: 'Invalid credentials' });
        mockAuthLogin.mockResolvedValue({ success: false, error: 'Invalid credentials' }); // Fallback also fails

        render(<Login />);

        fireEvent.change(screen.getByLabelText(/Email or Username/i), { target: { value: 'wrong@example.com' } });
        fireEvent.change(screen.getByLabelText(/Password/i), { target: { value: 'wrongpass' } });

        fireEvent.click(screen.getByRole('button', { name: /Sign In/i }));

        await waitFor(() => {
            expect(mockLogin).toHaveBeenCalled();
        });

        expect(await screen.findByText(/Invalid credentials/i)).toBeInTheDocument();
    });

    test('toggles password visibility', () => {
        render(<Login />);

        const passwordInput = screen.getByLabelText(/Password/i);
        expect(passwordInput).toHaveAttribute('type', 'password');

        const toggleButton = screen.getByLabel('Show password');
        fireEvent.click(toggleButton);

        expect(passwordInput).toHaveAttribute('type', 'text');

        fireEvent.click(screen.getByLabel('Hide password'));
        expect(passwordInput).toHaveAttribute('type', 'password');
    });
});
