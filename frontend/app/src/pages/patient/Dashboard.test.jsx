import React from 'react';
import { render, screen } from '../../test-utils';
import PatientDashboard from './Dashboard';

describe('Patient Dashboard', () => {


   test('renders dashboard', () => {
      const { container } = render(<PatientDashboard />, {
         authValue: {
            user: { id: 'P001', fullName: 'Emily Blunt' }
         }
      });
      expect(container).toBeInTheDocument();
   });

   test('displays patient welcome message', () => {
      render(<PatientDashboard />, {
         authValue: {
            user: { id: 'P001', fullName: 'Emily Blunt' }
         }
      });
      expect(screen.getByText(/welcome back/i)).toBeInTheDocument();
      expect(screen.getByText(/Emily Blunt/i)).toBeInTheDocument();
   });
});
