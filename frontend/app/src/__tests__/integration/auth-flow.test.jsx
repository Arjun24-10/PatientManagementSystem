import React from 'react';
import { render, screen } from '@testing-library/react';
import Login from '../../components/Login'; // Adjust path as necessary

describe('Login Component', () => {
  test('renders the component with correct placeholder text', () => {
    render(<Login />);

    const usernameInput = screen.getByPlaceholderText(/username/i);
    expect(usernameInput).toBeInTheDocument();

    const passwordInput = screen.getByPlaceholderText(/password/i);
    expect(passwordInput).toBeInTheDocument();
  });

  test('renders the submit button', () => {
    render(<Login />);
    const submitButton = screen.getByRole('button', { name: /submit/i });
    expect(submitButton).toBeInTheDocument();
  });
});