import React from 'react';
import { render, screen, act, waitFor } from '@testing-library/react';
import { AuthProvider, useAuth } from './AuthContext';
import * as authService from '../services/supabaseAuth';

// Mock auth service
jest.mock('../services/supabaseAuth');

const TestComponent = () => {
   const { user, login, logout, signup, loading } = useAuth();
   return (
      <div>
         {loading ? <p>Loading...</p> : <p>Loaded</p>}
         {user ? <p>User: {user.email}</p> : <p>No User</p>}
         <button onClick={() => login('test@example.com', 'password')}>Login</button>
         <button onClick={() => logout()}>Logout</button>
         <button onClick={() => signup('new@example.com', 'password', {})}>Signup</button>
      </div>
   );
};

describe('AuthContext', () => {
   beforeEach(() => {
      jest.clearAllMocks();
   });

   test('initializes with loading state and checks session', async () => {
      authService.getCurrentSession.mockResolvedValue(null);
      authService.onAuthStateChange.mockReturnValue(() => { });

      render(
         <AuthProvider>
            <TestComponent />
         </AuthProvider>
      );

      expect(screen.getByText('Loading...')).toBeInTheDocument();

      await waitFor(() => expect(screen.getByText('Loaded')).toBeInTheDocument());
      expect(authService.getCurrentSession).toHaveBeenCalled();
   });

   test('login calls authService.signIn', async () => {
      authService.getCurrentSession.mockResolvedValue(null);
      authService.onAuthStateChange.mockReturnValue(() => { });
      authService.signIn.mockResolvedValue({ success: true, user: { email: 'test@example.com' }, session: {} });

      render(
         <AuthProvider>
            <TestComponent />
         </AuthProvider>
      );

      await waitFor(() => expect(screen.getByText('Loaded')).toBeInTheDocument());

      await act(async () => {
         screen.getByText('Login').click();
      });

      expect(authService.signIn).toHaveBeenCalledWith('test@example.com', 'password');
      expect(screen.getByText('User: test@example.com')).toBeInTheDocument();
   });

   test('logout calls authService.signOut', async () => {
      authService.getCurrentSession.mockResolvedValue({ user: { email: 'test@example.com' } });
      authService.onAuthStateChange.mockReturnValue(() => { });
      authService.signOut.mockResolvedValue({ success: true });

      render(
         <AuthProvider>
            <TestComponent />
         </AuthProvider>
      );

      await waitFor(() => expect(screen.getByText('Loaded')).toBeInTheDocument());
      expect(screen.getByText('User: test@example.com')).toBeInTheDocument();

      await act(async () => {
         screen.getByText('Logout').click();
      });

      expect(authService.signOut).toHaveBeenCalled();
      expect(screen.getByText('No User')).toBeInTheDocument();
   });
});
