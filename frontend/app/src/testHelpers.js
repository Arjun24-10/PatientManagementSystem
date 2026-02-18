// Integration Test Utilities
// Helper functions for rendering components with all necessary providers

import React from 'react';
import { render } from '@testing-library/react';
import { BrowserRouter, MemoryRouter } from 'react-router-dom';
import { AuthContext } from './contexts/AuthContext';

// Default authenticated user for tests
const defaultAuthUser = {
  user: {
    id: '1',
    email: 'test@example.com',
    name: 'Test User',
    role: 'DOCTOR',
  },
  session: {
    access_token: 'mock-token',
  },
  loading: false,
  error: null,
  login: jest.fn(),
  signup: jest.fn(),
  logout: jest.fn(),
  isAuthenticated: true,
};

// Wrapper with all providers needed for integration tests
const IntegrationWrapper = ({ children, authValue, initialRoute = '/' }) => {
  return (
    <AuthContext.Provider value={{ ...defaultAuthUser, ...authValue }}>
      <MemoryRouter initialEntries={[initialRoute]}>
        {children}
      </MemoryRouter>
    </AuthContext.Provider>
  );
};

/**
 * Render component with all providers for integration testing
 * @param {React.Component} ui - Component to render
 * @param {Object} options - Render options
 * @param {Object} options.authValue - Override auth context values
 * @param {string} options.initialRoute - Initial route for MemoryRouter
 */
export const renderWithProviders = (ui, options = {}) => {
  const { authValue, initialRoute, ...renderOptions } = options;

  return render(ui, {
    wrapper: (props) => (
      <IntegrationWrapper {...props} authValue={authValue} initialRoute={initialRoute} />
    ),
    ...renderOptions,
  });
};

/**
 * Render the full App for end-to-end integration tests
 */
export const renderApp = (options = {}) => {
  const { authValue, initialRoute = '/' } = options;
  
  // Import App dynamically to avoid circular dependencies
  const App = require('./App').default;
  
  return render(
    <AuthContext.Provider value={{ ...defaultAuthUser, ...authValue }}>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </AuthContext.Provider>
  );
};

// Mock user data for different roles
export const mockAuthUsers = {
  doctor: {
    user: {
      id: '1',
      email: 'doctor@test.com',
      name: 'Dr. Smith',
      role: 'DOCTOR',
    },
    session: { access_token: 'doctor-token' },
    loading: false,
    error: null,
    isAuthenticated: true,
  },
  patient: {
    user: {
      id: '2',
      email: 'patient@test.com',
      name: 'John Doe',
      role: 'PATIENT',
    },
    session: { access_token: 'patient-token' },
    loading: false,
    error: null,
    isAuthenticated: true,
  },
  nurse: {
    user: {
      id: '3',
      email: 'nurse@test.com',
      name: 'Nurse Joy',
      role: 'NURSE',
    },
    session: { access_token: 'nurse-token' },
    loading: false,
    error: null,
    isAuthenticated: true,
  },
  lab: {
    user: {
      id: '4',
      email: 'lab@test.com',
      name: 'Tech Mike',
      role: 'LAB',
    },
    session: { access_token: 'lab-token' },
    loading: false,
    error: null,
    isAuthenticated: true,
  },
  unauthenticated: {
    user: null,
    session: null,
    loading: false,
    error: null,
    login: jest.fn(),
    signup: jest.fn(),
    logout: jest.fn(),
    isAuthenticated: false,
  },
};

// Helper to wait for async operations
export const waitForLoadingToFinish = () => {
  return new Promise(resolve => setTimeout(resolve, 0));
};

// Re-export everything from testing library
export * from '@testing-library/react';
export { default as userEvent } from '@testing-library/user-event';
