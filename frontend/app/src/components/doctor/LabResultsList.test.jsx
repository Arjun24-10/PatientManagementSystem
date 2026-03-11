import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import LabResultsList from './LabResultsList';
import Button from '../common/Button';

// Mock dependencies
jest.mock('../common/Card', () => ({ children, className }) => <div className={`mock-card ${className}`}>{children}</div>);
jest.mock('../common/Badge', () => ({ children }) => <span data-testid="badge">{children}</span>);
jest.mock('../common/Button', () => ({ children, onClick, className }) => (
   <button onClick={onClick} className={className}>
      {children}
   </button>
));

jest.mock('./LabTestModal', () => ({ isOpen }) => (
   isOpen ? <div data-testid="lab-test-modal">Lab Test Modal</div> : null
));

describe('LabResultsList', () => {
   const mockLabs = [
      {
         id: 1,
         name: 'Blood Test',
         orderedDate: '2023-01-01',
         date: '2023-01-02',
         status: 'Normal',
         type: 'Completed',
      },
      {
         id: 2,
         name: 'Urine Test',
         orderedDate: '2023-01-03',
         date: 'TBD',
         status: 'Pending',
         type: 'Pending',
      },
   ];

   test('renders no results message when labs are empty', () => {
      render(<LabResultsList labs={[]} />);
      expect(screen.getByText(/No lab results found/i)).toBeInTheDocument();
   });

   test('renders list of labs', () => {
      render(<LabResultsList labs={mockLabs} />);
      expect(screen.getByText('Blood Test')).toBeInTheDocument();
      expect(screen.getByText('Urine Test')).toBeInTheDocument();
   });

   test('renders status badges', () => {
      render(<LabResultsList labs={mockLabs} />);
      expect(screen.getByText('Normal')).toBeInTheDocument();
      expect(screen.getByText('Pending')).toBeInTheDocument();
   });

   test('renders order button and opens modal', () => {
      render(<LabResultsList labs={mockLabs} patientId="patient123" />);
      const button = screen.getByText(/Order New Labs/i);
      fireEvent.click(button);
      expect(screen.getByTestId('lab-test-modal')).toBeInTheDocument();
   });
});
