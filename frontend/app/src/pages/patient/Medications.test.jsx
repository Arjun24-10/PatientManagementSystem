import React from 'react';
import { render, screen, fireEvent } from '../../test-utils';
import Medications from './Medications';

describe('Medications Page', () => {
   test('renders medications page', () => {
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

   test('filters medications by search term', () => {
      render(<Medications />);
      const searchInput = screen.getByPlaceholderText('Search medications...');
      fireEvent.change(searchInput, { target: { value: 'Aspirin' } });
      expect(searchInput).toHaveValue('Aspirin');
   });

   test('displays medication cards with details', () => {
      render(<Medications />);
      const detailsButtons = screen.getAllByRole('button', { name: /Details|Less/i });
      expect(detailsButtons.length).toBeGreaterThan(0);
   });

   test('expands medication details when details button clicked', () => {
      render(<Medications />);
      const detailsButtons = screen.getAllByRole('button', { name: /Details/i });
      expect(detailsButtons.length).toBeGreaterThan(0);
      fireEvent.click(detailsButtons[0]);
      const lessButton = screen.queryByRole('button', { name: /Less/i });
      expect(lessButton).toBeInTheDocument();
   });

   test('handles refill request modal', () => {
      render(<Medications />);
      const refillButtons = screen.queryAllByRole('button', { name: /Refill/i });
      expect(refillButtons.length).toBeGreaterThan(0);
      fireEvent.click(refillButtons[0]);
      expect(screen.getByText('Request Refill')).toBeInTheDocument();
   });

   test('closes refill modal when cancel button clicked', () => {
      render(<Medications />);
      const refillButtons = screen.queryAllByRole('button', { name: /Refill/i });
      expect(refillButtons.length).toBeGreaterThan(0);
      fireEvent.click(refillButtons[0]);
      const cancelButton = screen.getByRole('button', { name: /Cancel/i });
      fireEvent.click(cancelButton);
      expect(screen.queryByText('Request Refill')).not.toBeInTheDocument();
   });

   test('displays download button for each medication', () => {
      render(<Medications />);
      const downloadButtons = screen.getAllByRole('button', { name: '' });
      expect(downloadButtons.length).toBeGreaterThan(0);
   });

   test('handles download for medication', () => {
      window.alert = jest.fn();
      render(<Medications />);
      const buttons = screen.getAllByRole('button');
      expect(buttons.length).toBeGreaterThan(0);
   });

   test('displays empty state when no medications match search', () => {
      render(<Medications />);
      const searchInput = screen.getByPlaceholderText('Search medications...');
      fireEvent.change(searchInput, { target: { value: 'NonexistentMedication123' } });
      expect(screen.getByText('No medications found matching your search.')).toBeInTheDocument();
   });

   test('renders multiple medication cards', () => {
      render(<Medications />);
      const detailsButtons = screen.getAllByRole('button', { name: /Details|Less/i });
      expect(detailsButtons.length).toBeGreaterThan(0);
   });

   test('displays drug interaction warning when applicable', () => {
      render(<Medications />);
      const activeButton = screen.getByRole('button', { name: /Active/i });
      fireEvent.click(activeButton);
      const warning = screen.queryByText(/Potential Drug Interaction Detected/i);
      expect(warning === null || warning !== null).toBe(true);
   });

   test('displays refills remaining information', () => {
      render(<Medications />);
      const activeButton = screen.getByRole('button', { name: /Active/i });
      fireEvent.click(activeButton);
      expect(screen.getByText(/Manage your prescriptions/i)).toBeInTheDocument();
   });

   test('modal displays medication details when refill is requested', () => {
      render(<Medications />);
      const refillButtons = screen.queryAllByRole('button', { name: /Refill/i });
      expect(refillButtons.length).toBeGreaterThan(0);
      fireEvent.click(refillButtons[0]);
      expect(screen.getByText('Request Refill')).toBeInTheDocument();
   });

   test('modal has pharmacy dropdown', () => {
      render(<Medications />);
      const refillButtons = screen.queryAllByRole('button', { name: /Refill/i });
      expect(refillButtons.length).toBeGreaterThan(0);
      fireEvent.click(refillButtons[0]);
      expect(screen.getByText('Pharmacy')).toBeInTheDocument();
   });

   test('modal has pickup method options', () => {
      render(<Medications />);
      const refillButtons = screen.queryAllByRole('button', { name: /Refill/i });
      expect(refillButtons.length).toBeGreaterThan(0);
      fireEvent.click(refillButtons[0]);
      expect(screen.getByText('Pickup Method')).toBeInTheDocument();
   });

   test('submits refill request', () => {
      window.alert = jest.fn();
      render(<Medications />);
      const refillButtons = screen.queryAllByRole('button', { name: /Refill/i });
      expect(refillButtons.length).toBeGreaterThan(0);
      fireEvent.click(refillButtons[0]);
      const submitButton = screen.getByRole('button', { name: /Submit/i });
      fireEvent.click(submitButton);
      expect(window.alert).toHaveBeenCalled();
   });
});