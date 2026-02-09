import React from 'react';
import { render, screen, fireEvent, waitFor } from '../test-utils';
import userEvent from '@testing-library/user-event';
import CreateAccount from './createAccount';

// Mock useNavigate
const mockNavigate = jest.fn();
jest.mock('react-router-dom', () => ({
    ...jest.requireActual('react-router-dom'),
    useNavigate: () => mockNavigate,
}));

describe('CreateAccount Page', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    test('renders signup form with all fields', () => {
        render(<CreateAccount />);
        
        expect(screen.getByPlaceholderText(/enter your full name/i)).toBeInTheDocument();
        expect(screen.getByPlaceholderText(/you@example.com/i)).toBeInTheDocument();
        expect(screen.getByPlaceholderText(/10-digit mobile number/i)).toBeInTheDocument();
        expect(screen.getByPlaceholderText(/at least 12 characters/i)).toBeInTheDocument();
        expect(screen.getByPlaceholderText(/re-enter password/i)).toBeInTheDocument();
    });

    test('renders branding content', () => {
        render(<CreateAccount />);
        
        expect(screen.getByText(/bank-grade security/i)).toBeInTheDocument();
    });

    test('shows error when passwords do not match', async () => {
        render(<CreateAccount />);
        
        const nameInput = screen.getByPlaceholderText(/enter your full name/i);
        const emailInput = screen.getByPlaceholderText(/you@example.com/i);
        const phoneInput = screen.getByPlaceholderText(/10-digit mobile number/i);
        const passwordInput = screen.getByPlaceholderText(/at least 12 characters/i);
        const confirmInput = screen.getByPlaceholderText(/re-enter password/i);
        
        await userEvent.type(nameInput, 'John Doe');
        await userEvent.type(emailInput, 'john@example.com');
        await userEvent.type(phoneInput, '1234567890');
        await userEvent.type(passwordInput, 'SecurePass123!');
        await userEvent.type(confirmInput, 'DifferentPass123!');
        
        const submitButton = screen.getByRole('button', { name: /create account/i });
        fireEvent.click(submitButton);
        
        await waitFor(() => {
            expect(screen.getByText(/passwords do not match/i)).toBeInTheDocument();
        });
    });

    test('shows error for short password', async () => {
        render(<CreateAccount />);
        
        const nameInput = screen.getByPlaceholderText(/enter your full name/i);
        const emailInput = screen.getByPlaceholderText(/you@example.com/i);
        const phoneInput = screen.getByPlaceholderText(/10-digit mobile number/i);
        const passwordInput = screen.getByPlaceholderText(/at least 12 characters/i);
        const confirmInput = screen.getByPlaceholderText(/re-enter password/i);
        
        await userEvent.type(nameInput, 'John Doe');
        await userEvent.type(emailInput, 'john@example.com');
        await userEvent.type(phoneInput, '1234567890');
        await userEvent.type(passwordInput, 'short');
        await userEvent.type(confirmInput, 'short');
        
        const submitButton = screen.getByRole('button', { name: /create account/i });
        fireEvent.click(submitButton);
        
        await waitFor(() => {
            expect(screen.getByText(/password must be at least 12 characters/i)).toBeInTheDocument();
        });
    });

    test('shows error for invalid phone number', async () => {
        render(<CreateAccount />);
        
        const nameInput = screen.getByPlaceholderText(/enter your full name/i);
        const emailInput = screen.getByPlaceholderText(/you@example.com/i);
        const phoneInput = screen.getByPlaceholderText(/10-digit mobile number/i);
        const passwordInput = screen.getByPlaceholderText(/at least 12 characters/i);
        const confirmInput = screen.getByPlaceholderText(/re-enter password/i);
        
        await userEvent.type(nameInput, 'John Doe');
        await userEvent.type(emailInput, 'john@example.com');
        await userEvent.type(phoneInput, '123');
        await userEvent.type(passwordInput, 'SecurePass123!');
        await userEvent.type(confirmInput, 'SecurePass123!');
        
        const submitButton = screen.getByRole('button', { name: /create account/i });
        fireEvent.click(submitButton);
        
        await waitFor(() => {
            expect(screen.getByText(/valid 10-digit phone number/i)).toBeInTheDocument();
        });
    });

    test('shows error when required fields are empty', async () => {
        render(<CreateAccount />);
        
        const submitButton = screen.getByRole('button', { name: /create account/i });
        fireEvent.click(submitButton);
        
        await waitFor(() => {
            expect(screen.getByText(/please complete all required fields/i)).toBeInTheDocument();
        });
    });

    test('has link to sign in page', () => {
        render(<CreateAccount />);
        
        expect(screen.getByText(/already have an account/i)).toBeInTheDocument();
        expect(screen.getByText(/sign in/i)).toBeInTheDocument();
    });
});
