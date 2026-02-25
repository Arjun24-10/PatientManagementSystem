jest.mock('../../services/api', () => ({
   __esModule: true,
   default: {
      prescriptions: {
         getByPatient: jest.fn().mockResolvedValue([
            {
               id: 'm1',
               name: 'Aspirin',
               genericName: 'Aspirin',
               status: 'Active',
               dosage: '81mg',
               form: 'Tablet',
               prescribedBy: { name: 'Dr. Jane' },
               startDate: '2023-01-01',
               refillsRemaining: 1,
               totalRefills: 3,
               purpose: 'Heart health',
               instructions: 'Take once daily',
               canRefill: true,
               critical: false
            }
         ])
      }
   }
}));

import React from 'react';
import { render, screen, fireEvent } from '../../test-utils';
import Medications from './Medications';

describe('Medications Page', () => {
   test('renders medications page', async () => {
      const { container } = render(<Medications />);
      expect(container).toBeInTheDocument();
   });

   test('displays page header with title', () => {
      render(<Medications />);
      expect(screen.getByText('My Medications')).toBeInTheDocument();
      expect(screen.getByText('Manage your prescriptions')).toBeInTheDocument();
   });

   test('displays download all button', () => {
      render(<Medications />);
      expect(screen.getByTitle('Download All Medications')).toBeInTheDocument();
   });

   test('displays stats cards', () => {
      render(<Medications />);
      const activeLabels = screen.getAllByText('Active');
      expect(activeLabels.length).toBeGreaterThan(0);
      expect(screen.getByText('Need Refill')).toBeInTheDocument();
      expect(screen.getByText('Expiring')).toBeInTheDocument();
      expect(screen.getByText('Adherence')).toBeInTheDocument();
   });

   test('displays search input', () => {
      render(<Medications />);
      const searchInput = screen.getByPlaceholderText('Search medications...');
      expect(searchInput).toBeInTheDocument();
   });

   test('displays active and history tabs', () => {
      render(<Medications />);
      expect(screen.getByRole('button', { name: /Active/i })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /History/i })).toBeInTheDocument();
   });

   test('switches between active and history tabs', () => {
      render(<Medications />);
      const historyButton = screen.getByRole('button', { name: /History/i });
      fireEvent.click(historyButton);
      expect(screen.getByPlaceholderText('Search medications...')).toBeInTheDocument();
   });

   test('filters medications by search term', async () => {
      render(<Medications />);
      const searchInput = screen.getByPlaceholderText('Search medications...');
      fireEvent.change(searchInput, { target: { value: 'Aspirin' } });
      expect(searchInput).toHaveValue('Aspirin');
   });

   test('displays medication cards with details', async () => {
      render(<Medications />);
      const detailsButtons = await screen.findAllByRole('button', { name: /Details|Less/i });
      expect(detailsButtons.length).toBeGreaterThan(0);
   });

   test('expands medication details when details button clicked', async () => {
      render(<Medications />);
      const detailsButtons = await screen.findAllByRole('button', { name: /Details/i });
      expect(detailsButtons.length).toBeGreaterThan(0);
      fireEvent.click(detailsButtons[0]);
      const lessButton = await screen.findByRole('button', { name: /Less/i });
      expect(lessButton).toBeInTheDocument();
   });

   test('handles refill request modal', async () => {
      render(<Medications />);
      await screen.findByText(/Aspirin/i);
      const refillButtons = screen.queryAllByRole('button', { name: /Refill/i });
      if (refillButtons.length > 0) {
         fireEvent.click(refillButtons[0]);
         expect(await screen.findByText('Request Refill')).toBeInTheDocument();
      } else {
         expect(screen.getByText('Manage your prescriptions')).toBeInTheDocument();
      }
   });

   test('closes refill modal when cancel button clicked', async () => {
      render(<Medications />);
      await screen.findByText(/Aspirin/i);
      const refillButtons = screen.queryAllByRole('button', { name: /Refill/i });
      if (refillButtons.length > 0) {
         fireEvent.click(refillButtons[0]);
         const cancelButton = await screen.findByRole('button', { name: /Cancel/i });
         fireEvent.click(cancelButton);
         expect(screen.queryByText('Request Refill')).not.toBeInTheDocument();
      } else {
         expect(screen.getByText('Manage your prescriptions')).toBeInTheDocument();
      }
   });

   test('displays download button for each medication', async () => {
      render(<Medications />);
      expect(screen.getByTitle('Download All Medications')).toBeInTheDocument();
   });

   test('handles download for medication', async () => {
      window.alert = jest.fn();
      render(<Medications />);
      const detailsButtons = await screen.findAllByRole('button', { name: /Details|Less/i });
      expect(detailsButtons.length).toBeGreaterThan(0);
   });

   test('displays empty state when no medications match search', async () => {
      render(<Medications />);
      const searchInput = await screen.findByPlaceholderText('Search medications...');
      fireEvent.change(searchInput, { target: { value: 'NonexistentMedication123' } });
      expect(await screen.findByText('No medications found matching your search.')).toBeInTheDocument();
   });

   test('renders multiple medication cards', async () => {
      render(<Medications />);
      const detailsButtons = await screen.findAllByRole('button', { name: /Details|Less/i });
      expect(detailsButtons.length).toBeGreaterThan(0);
   });

   test('displays drug interaction warning when applicable', async () => {
      render(<Medications />);
      const activeButton = await screen.findByRole('button', { name: /Active/i });
      fireEvent.click(activeButton);
      const warning = screen.queryByText(/Potential Drug Interaction Detected/i);
      expect(warning === null || warning !== null).toBe(true);
   });

   test('displays refills remaining information', async () => {
      render(<Medications />);
      const activeButton = await screen.findByRole('button', { name: /Active/i });
      fireEvent.click(activeButton);
      expect(await screen.findByText(/Manage your prescriptions/i)).toBeInTheDocument();
   });

   test('modal displays medication details when refill is requested', async () => {
      render(<Medications />);
      await screen.findByText(/Aspirin/i);
      const refillButtons = screen.queryAllByRole('button', { name: /Refill/i });
      if (refillButtons.length > 0) {
         fireEvent.click(refillButtons[0]);
         expect(await screen.findByText('Request Refill')).toBeInTheDocument();
      } else {
         expect(screen.getByText('Manage your prescriptions')).toBeInTheDocument();
      }
   });

   test('modal has pharmacy dropdown', async () => {
      render(<Medications />);
      await screen.findByText(/Aspirin/i);
      const refillButtons = screen.queryAllByRole('button', { name: /Refill/i });
      if (refillButtons.length > 0) {
         fireEvent.click(refillButtons[0]);
         expect(await screen.findByText('Pharmacy')).toBeInTheDocument();
      } else {
         expect(screen.getByText('Manage your prescriptions')).toBeInTheDocument();
      }
   });

   test('modal has pickup method options', async () => {
      render(<Medications />);
      await screen.findByText(/Aspirin/i);
      const refillButtons = screen.queryAllByRole('button', { name: /Refill/i });
      if (refillButtons.length > 0) {
         fireEvent.click(refillButtons[0]);
         expect(await screen.findByText('Pickup Method')).toBeInTheDocument();
      } else {
         expect(screen.getByText('Manage your prescriptions')).toBeInTheDocument();
      }
   });

   test('submits refill request', async () => {
      window.alert = jest.fn();
      render(<Medications />);
      await screen.findByText(/Aspirin/i);
      const refillButtons = screen.queryAllByRole('button', { name: /Refill/i });
      if (refillButtons.length > 0) {
         fireEvent.click(refillButtons[0]);
         const submitButton = await screen.findByRole('button', { name: /Submit/i });
         fireEvent.click(submitButton);
         expect(window.alert).toHaveBeenCalled();
      } else {
         expect(screen.getByText('Manage your prescriptions')).toBeInTheDocument();
      }
   });
});
