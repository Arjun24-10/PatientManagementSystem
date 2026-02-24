import React from 'react';
import { render, screen, waitFor } from '../../test-utils';
import PatientDashboard from './Dashboard';

describe('Patient Dashboard', () => {
   test('renders dashboard', () => {
      const { container } = render(<PatientDashboard />);
      expect(container).toBeInTheDocument();
   });

   test('displays patient welcome message', async () => {
      render(<PatientDashboard />);
      await waitFor(() => {
         expect(screen.getByText(/welcome back/i)).toBeInTheDocument();
      });
   });
});
