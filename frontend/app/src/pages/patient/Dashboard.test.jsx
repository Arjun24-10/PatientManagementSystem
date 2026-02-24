import React from 'react';
import { render, screen } from '../../test-utils';
import PatientDashboard from './Dashboard';
import api from '../../services/api';

jest.mock('../../services/api', () => ({
   patients: {
      getMe: jest.fn()
   },
   appointments: { getByPatient: jest.fn().mockResolvedValue([]) },
   prescriptions: { getByPatient: jest.fn().mockResolvedValue([]) },
   labResults: { getByPatient: jest.fn().mockResolvedValue([]) },
   medicalRecords: { getByPatient: jest.fn().mockResolvedValue([]) },
   vitalSigns: { getByPatient: jest.fn().mockResolvedValue([]) },
}));

describe('Patient Dashboard', () => {
   beforeEach(() => {
      jest.clearAllMocks();
   });

   test('renders dashboard', async () => {
      api.patients.getMe.mockResolvedValueOnce({ id: 'P001', name: 'Emily Blunt' });

      const { container } = render(<PatientDashboard />, {
         authValue: {
            user: { id: 'P001', fullName: 'Emily Blunt' }
         }
      });
      expect(await screen.findByText(/welcome back/i)).toBeInTheDocument();
      expect(container).toBeInTheDocument();
   });

   test('displays patient welcome message', async () => {
      api.patients.getMe.mockResolvedValueOnce({ id: 'P001', name: 'Emily Blunt' });

      render(<PatientDashboard />, {
         authValue: {
            user: { id: 'P001', fullName: 'Emily Blunt' }
         }
      });
      expect(await screen.findByText(/welcome back/i)).toBeInTheDocument();
      expect(screen.getByText(/Emily Blunt/i)).toBeInTheDocument();
   });
});
