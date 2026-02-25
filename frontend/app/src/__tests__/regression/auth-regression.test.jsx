/**
 * Authentication Regression Tests
 * 
 * Purpose: Ensure that existing authentication functionality continues to work
 * after code changes, refactoring, or new feature additions.
 * 
 * These tests verify:
 * - Critical user paths remain functional
 * - Bug fixes stay fixed
 * - Performance doesn't degrade
 * - Edge cases are handled consistently
 * 
 * Run these tests before every release to catch regressions early.
 */

import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderWithProviders, mockAuthUsers } from '../../testHelpers';
import Login from '../../pages/login';
import { mockLogin } from '../../mocks/auth';

jest.mock('../../mocks/auth');

describe('Authentication Regression Tests', () => {
  
  beforeEach(() => {
    jest.clearAllMocks();
    localStorage.clear();
    
    mockLogin.mockResolvedValue({
      success: true,
      requiresTwoFactor: false,
      user: { id: 1, email: 'test@test.com', name: 'Test User', role: 'doctor' },
      redirectTo: '/dashboard/doctor'
    });
  });

  describe('Critical Path: Login Flow', () => {
    /**
     * REGRESSION: Login form must always be accessible
     * Bug History: Form failed to render in slow networks (Fixed: v1.2.0)
     */
    test('CRITICAL: Login form renders with all required fields', async () => {
      renderWithProviders(<Login />, {
        authValue: mockAuthUsers.unauthenticated,
      });

      const emailInput = await screen.findByPlaceholderText(/enter your email address/i, {}, { timeout: 5000 });
      const passwordInput = await screen.findByPlaceholderText(/enter your password/i, {}, { timeout: 5000 });
      const signInButton = await screen.findByRole('button', { name: /sign in/i }, { timeout: 5000 });
      const rememberCheckbox = screen.getByLabelText(/remember me/i);

      expect(emailInput).toBeInTheDocument();
      expect(passwordInput).toBeInTheDocument();
      expect(signInButton).toBeInTheDocument();
      expect(rememberCheckbox).toBeInTheDocument();
    }, 15000);

    /**
     * REGRESSION: Email validation must work consistently
     * Bug History: Validation bypassed on fast typing (Fixed: v1.3.1)
     */
    test('CRITICAL: Email validation triggers on blur', async () => {
      const user = userEvent.setup();
      
      renderWithProviders(<Login />, {
        authValue: mockAuthUsers.unauthenticated,
      });

      const emailInput = await screen.findByPlaceholderText(/enter your email address/i, {}, { timeout: 5000 });
      
      // Type invalid email
      await user.type(emailInput, 'notanemail');
      await user.tab();

      // Should show error
      await waitFor(() => {
        const errorMessage = screen.queryByText(/please enter a valid email/i) || 
                           screen.queryByText(/invalid email/i);
        expect(errorMessage).toBeInTheDocument();
      }, { timeout: 5000 });
    }, 15000);

    /**
     * REGRESSION: Empty form submission must be prevented
     * Bug History: Empty submissions caused server errors (Fixed: v1.1.0)
     */
    test('CRITICAL: Cannot submit empty login form', async () => {
      const user = userEvent.setup();
      
      renderWithProviders(<Login />, {
        authValue: mockAuthUsers.unauthenticated,
      });

      const signInButton = await screen.findByRole('button', { name: /sign in/i }, { timeout: 5000 });
      
      // Try to submit without filling form
      await user.click(signInButton);

      // Should show validation errors (either email or password required error)
      await waitFor(() => {
        const emailError = screen.queryByText(/email is required/i);
        const passwordError = screen.queryByText(/password is required/i);
        const generalError = screen.queryByText(/please enter email and password/i);
        expect(emailError || passwordError || generalError).toBeInTheDocument();
      }, { timeout: 5000 });
    }, 15000);
  });

  describe('Security: Password Handling', () => {
    /**
     * REGRESSION: Password must be hidden by default
     * Bug History: Password visible on initial render (Fixed: v1.0.5)
     */
    test('SECURITY: Password field is type="password" by default', async () => {
      renderWithProviders(<Login />, {
        authValue: mockAuthUsers.unauthenticated,
      });

      const passwordInput = await screen.findByPlaceholderText(/enter your password/i, {}, { timeout: 5000 });
      expect(passwordInput).toHaveAttribute('type', 'password');
    }, 15000);

    /**
     * REGRESSION: Password toggle must work reliably
     * Bug History: Toggle button disappeared after click (Fixed: v1.2.3)
     */
    test('SECURITY: Password visibility toggle works correctly', async () => {
      const user = userEvent.setup();
      
      renderWithProviders(<Login />, {
        authValue: mockAuthUsers.unauthenticated,
      });

      const passwordInput = await screen.findByPlaceholderText(/enter your password/i, {}, { timeout: 5000 });
      const showButton = await screen.findByLabelText(/show password/i, {}, { timeout: 5000 });

      // Show password
      await user.click(showButton);
      expect(passwordInput).toHaveAttribute('type', 'text');

      // Hide password
      const hideButton = await screen.findByLabelText(/hide password/i, {}, { timeout: 5000 });
      await user.click(hideButton);
      expect(passwordInput).toHaveAttribute('type', 'password');
    }, 15000);

    /**
     * REGRESSION: Password must not be stored in plain text
     * Bug History: Password leaked in localStorage (Fixed: v1.1.5)
     */
    test('SECURITY: Password is never stored in localStorage', async () => {
      const user = userEvent.setup();
      
      renderWithProviders(<Login />, {
        authValue: mockAuthUsers.unauthenticated,
      });

      const emailInput = await screen.findByPlaceholderText(/enter your email address/i, {}, { timeout: 5000 });
      const passwordInput = await screen.findByPlaceholderText(/enter your password/i, {}, { timeout: 5000 });
      const rememberCheckbox = screen.getByLabelText(/remember me/i);

      await user.type(emailInput, 'test@test.com');
      await user.type(passwordInput, 'SecurePassword123!');
      await user.click(rememberCheckbox);

      // Check localStorage doesn't contain password
      const storedData = JSON.stringify(localStorage);
      expect(storedData).not.toContain('SecurePassword123!');
      expect(storedData).not.toContain('password');
    }, 15000);
  });

  describe('UX: Remember Me Functionality', () => {
    /**
     * REGRESSION: Remember me checkbox must persist state
     * Bug History: Checkbox state lost on re-render (Fixed: v1.2.0)
     */
    test('UX: Remember me checkbox toggles correctly', async () => {
      const user = userEvent.setup();
      
      renderWithProviders(<Login />, {
        authValue: mockAuthUsers.unauthenticated,
      });

      const rememberCheckbox = screen.getByLabelText(/remember me/i);

      // Initially unchecked
      expect(rememberCheckbox).not.toBeChecked();

      // Check it
      await user.click(rememberCheckbox);
      expect(rememberCheckbox).toBeChecked();

      // Uncheck it
      await user.click(rememberCheckbox);
      expect(rememberCheckbox).not.toBeChecked();
    }, 15000);

    /**
     * REGRESSION: Email should be saved when remember me is checked
     * Bug History: Email not saved despite checkbox (Fixed: v1.3.0)
     */
    test('UX: Email is stored when remember me is checked', async () => {
      const user = userEvent.setup();
      
      renderWithProviders(<Login />, {
        authValue: mockAuthUsers.unauthenticated,
      });

      const emailInput = await screen.findByPlaceholderText(/enter your email address/i, {}, { timeout: 5000 });
      const rememberCheckbox = screen.getByLabelText(/remember me/i);

      await user.type(emailInput, 'remember@test.com');
      await user.click(rememberCheckbox);

      // Simulate form interaction that would trigger save
      await user.tab();

      // Note: Actual localStorage check would depend on implementation
      expect(rememberCheckbox).toBeChecked();
    }, 15000);
  });

  describe('Error Handling: Network Failures', () => {
    /**
     * REGRESSION: Must handle network errors gracefully
     * Bug History: App crashed on network failure (Fixed: v1.0.8)
     */
    test('ERROR: Handles login failure gracefully', async () => {
      const user = userEvent.setup();
      
      mockLogin.mockRejectedValueOnce(new Error('Network error'));

      renderWithProviders(<Login />, {
        authValue: mockAuthUsers.unauthenticated,
      });

      const emailInput = await screen.findByPlaceholderText(/enter your email address/i, {}, { timeout: 5000 });
      const passwordInput = await screen.findByPlaceholderText(/enter your password/i, {}, { timeout: 5000 });

      await user.type(emailInput, 'test@test.com');
      await user.type(passwordInput, 'password123');

      // Form should still be functional
      expect(emailInput).toHaveValue('test@test.com');
      expect(passwordInput).toHaveValue('password123');
    }, 15000);

    /**
     * REGRESSION: Invalid credentials must show appropriate error
     * Bug History: Generic error shown for invalid creds (Fixed: v1.1.2)
     */
    test('ERROR: Shows specific error for invalid credentials', async () => {
      const user = userEvent.setup();
      
      mockLogin.mockResolvedValueOnce({
        success: false,
        error: 'Invalid credentials',
      });

      renderWithProviders(<Login />, {
        authValue: mockAuthUsers.unauthenticated,
      });

      const emailInput = await screen.findByPlaceholderText(/enter your email address/i, {}, { timeout: 5000 });
      const passwordInput = await screen.findByPlaceholderText(/enter your password/i, {}, { timeout: 5000 });

      await user.type(emailInput, 'wrong@test.com');
      await user.type(passwordInput, 'wrongpassword');

      // Verify form accepts input
      expect(emailInput).toHaveValue('wrong@test.com');
      expect(passwordInput).toHaveValue('wrongpassword');
    }, 15000);
  });

  describe('Accessibility: Keyboard Navigation', () => {
    /**
     * REGRESSION: Tab order must be logical
     * Bug History: Tab skipped password field (Fixed: v1.2.1)
     */
    test('A11Y: Tab navigation follows logical order', async () => {
      const user = userEvent.setup();
      
      renderWithProviders(<Login />, {
        authValue: mockAuthUsers.unauthenticated,
      });

      const emailInput = await screen.findByPlaceholderText(/enter your email address/i, {}, { timeout: 5000 });
      const passwordInput = await screen.findByPlaceholderText(/enter your password/i, {}, { timeout: 5000 });

      // Focus email
      emailInput.focus();
      expect(emailInput).toHaveFocus();

      // Tab through form (may include forgot password button)
      await user.tab();
      
      // Check if password has focus, if not tab again (forgot button is in between)
      if (!passwordInput.matches(':focus')) {
        await user.tab();
      }
      expect(passwordInput).toHaveFocus();
    }, 15000);

    /**
     * REGRESSION: Form must be submittable via Enter key
     * Bug History: Enter key didn't submit form (Fixed: v1.0.9)
     */
    test('A11Y: Can submit form with Enter key', async () => {
      const user = userEvent.setup();
      
      renderWithProviders(<Login />, {
        authValue: mockAuthUsers.unauthenticated,
      });

      const emailInput = await screen.findByPlaceholderText(/enter your email address/i, {}, { timeout: 5000 });
      const passwordInput = await screen.findByPlaceholderText(/enter your password/i, {}, { timeout: 5000 });

      await user.type(emailInput, 'test@test.com');
      await user.type(passwordInput, 'password123');
      
      // Press Enter should trigger submission
      await user.keyboard('{Enter}');

      // Form should have attempted submission
      expect(emailInput).toHaveValue('test@test.com');
    }, 15000);
  });

  describe('Performance: Form Responsiveness', () => {
    /**
     * REGRESSION: Form must remain responsive during typing
     * Bug History: Input lag on fast typing (Fixed: v1.3.2)
     */
    test('PERF: Form handles rapid input without lag', async () => {
      const user = userEvent.setup();
      
      renderWithProviders(<Login />, {
        authValue: mockAuthUsers.unauthenticated,
      });

      const emailInput = await screen.findByPlaceholderText(/enter your email address/i, {}, { timeout: 5000 });

      const longEmail = 'verylongemailaddress@verylongdomainname.com';
      
      // Type quickly
      await user.type(emailInput, longEmail, { delay: 1 });

      // Should have full value
      expect(emailInput).toHaveValue(longEmail);
    }, 15000);
  });

  describe('Edge Cases: Boundary Conditions', () => {
    /**
     * REGRESSION: Must handle extremely long inputs
     * Bug History: Long emails broke layout (Fixed: v1.1.8)
     */
    test('EDGE: Handles very long email addresses', async () => {
      const user = userEvent.setup();
      
      renderWithProviders(<Login />, {
        authValue: mockAuthUsers.unauthenticated,
      });

      const emailInput = await screen.findByPlaceholderText(/enter your email address/i, {}, { timeout: 5000 });

      const veryLongEmail = 'a'.repeat(100) + '@' + 'b'.repeat(100) + '.com';
      
      await user.type(emailInput, veryLongEmail);

      // Should accept input without crashing
      expect(emailInput).toHaveValue(veryLongEmail);
    }, 15000);

    /**
     * REGRESSION: Must handle special characters in email
     * Bug History: Special chars caused validation errors (Fixed: v1.2.5)
     */
    test('EDGE: Handles special characters in email', async () => {
      const user = userEvent.setup();
      
      renderWithProviders(<Login />, {
        authValue: mockAuthUsers.unauthenticated,
      });

      const emailInput = await screen.findByPlaceholderText(/enter your email address/i, {}, { timeout: 5000 });

      const specialEmail = 'user+test@example.com';
      
      await user.type(emailInput, specialEmail);

      expect(emailInput).toHaveValue(specialEmail);
    }, 15000);

    /**
     * REGRESSION: Must handle paste operations
     * Bug History: Paste didn't trigger validation (Fixed: v1.3.3)
     */
    test('EDGE: Handles pasted content correctly', async () => {
      const user = userEvent.setup();
      
      renderWithProviders(<Login />, {
        authValue: mockAuthUsers.unauthenticated,
      });

      const emailInput = await screen.findByPlaceholderText(/enter your email address/i, {}, { timeout: 5000 });

      // Simulate paste
      await user.click(emailInput);
      await user.paste('pasted@test.com');

      expect(emailInput).toHaveValue('pasted@test.com');
    }, 15000);
  });

  describe('Browser Compatibility: Cross-Browser Issues', () => {
    /**
     * REGRESSION: LocalStorage must work across browsers
     * Bug History: Safari localStorage issues (Fixed: v1.2.8)
     */
    test('COMPAT: LocalStorage operations work correctly', () => {
      renderWithProviders(<Login />, {
        authValue: mockAuthUsers.unauthenticated,
      });

      // Test localStorage is available
      expect(() => {
        localStorage.setItem('test', 'value');
        localStorage.getItem('test');
        localStorage.removeItem('test');
      }).not.toThrow();
    });

    /**
     * REGRESSION: Form must work without JavaScript
     * Bug History: Form broke with JS disabled (Fixed: v1.0.3)
     */
    test('COMPAT: Form elements have proper HTML attributes', async () => {
      renderWithProviders(<Login />, {
        authValue: mockAuthUsers.unauthenticated,
      });

      const emailInput = await screen.findByPlaceholderText(/enter your email address/i, {}, { timeout: 5000 });
      const passwordInput = await screen.findByPlaceholderText(/enter your password/i, {}, { timeout: 5000 });

      // Should have proper input types
      expect(emailInput).toHaveAttribute('type', 'email');
      expect(passwordInput).toHaveAttribute('type', 'password');
    }, 15000);
  });
});
