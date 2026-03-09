import React from 'react';
import { render, screen, waitFor } from '../../test-utils';
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

// Must include userId so the component's `if (!user?.userId) return` guard passes
const authValue = {
   user: { userId: 'U001', id: 'P001', firstName: 'Emily', lastName: 'Blunt' }
};

describe('Patient Dashboard', () => {
   beforeEach(() => {
      jest.clearAllMocks();
      api.patients.getMe.mockResolvedValue({ id: 'P001', firstName: 'Emily', lastName: 'Blunt' });
   });

   test('renders dashboard', async () => {
      const { container } = render(<PatientDashboard />, { authValue });
      expect(await screen.findByText(/welcome back/i)).toBeInTheDocument();
      expect(container).toBeInTheDocument();
   });

   test('displays patient welcome message', async () => {
      render(<PatientDashboard />, { authValue });
      expect(await screen.findByText(/welcome back/i)).toBeInTheDocument();
      expect(screen.getByText(/Emily Blunt/i)).toBeInTheDocument();
   });
});
