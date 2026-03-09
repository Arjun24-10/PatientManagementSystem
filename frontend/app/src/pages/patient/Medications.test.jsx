import React from 'react';
import { render, screen, waitFor } from '../../test-utils';
import Medications from './Medications';
import api from '../../services/api';

// Mock the API calls
jest.mock('../../services/api', () => ({
   patients: {
      getMe: jest.fn(),
   },
   prescriptions: {
      getByPatient: jest.fn(),
   },
}));

// Provide userId so the component's guard passes
const authValue = { user: { userId: 'U001', id: 'U001', name: 'Test Patient' } };

describe('Medications Page', () => {
   beforeEach(() => {
      jest.clearAllMocks();
      api.patients.getMe.mockResolvedValue({ id: 'P001' });
      api.prescriptions.getByPatient.mockResolvedValue([
         {
            prescriptionId: 'RX001',
            medicationName: 'Aspirin',
            status: 'ACTIVE',
            dosage: '81mg',
            frequency: 'Once daily',
            doctorName: 'Dr. Smith',
            refillsRemaining: 2
         }
      ]);
   });

   test('renders medications page', async () => {
      render(<Medications />, { authValue });
      expect(await screen.findByText('Medications')).toBeInTheDocument();
   });

   test('displays page header with title', async () => {
      render(<Medications />, { authValue });
      expect(await screen.findByText('Medications')).toBeInTheDocument();
      expect(screen.getByText('Current and past prescriptions')).toBeInTheDocument();
   });

   test('displays medication cards with details', async () => {
      render(<Medications />, { authValue });

      expect(await screen.findByText('Aspirin')).toBeInTheDocument();
      expect(screen.getByText('ACTIVE')).toBeInTheDocument();
      expect(screen.getByText('81mg • Once daily')).toBeInTheDocument();
      expect(screen.getByText('Doctor: Dr. Smith')).toBeInTheDocument();
      expect(screen.getByText('Refills remaining: 2')).toBeInTheDocument();
   });

   test('displays empty state when no active medications', async () => {
      api.prescriptions.getByPatient.mockResolvedValue([]);
      render(<Medications />, { authValue });

      expect(await screen.findByText('No active medications.')).toBeInTheDocument();
   });
});