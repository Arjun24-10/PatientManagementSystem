import React from 'react';
import { render, screen } from '@testing-library/react';
import MedicalHistoryList from './MedicalHistoryList';

// Mock dependencies
jest.mock('../common/Card', () => ({ children, className }) => <div className={`mock-card ${className}`}>{children}</div>);
jest.mock('../common/Badge', () => ({ children }) => <span data-testid="badge">{children}</span>);

describe('MedicalHistoryList', () => {
   const mockHistory = [
      {
         id: 1,
         type: 'Diagnosis',
         date: '2023-01-01',
         note: 'Flu',
      },
      {
         id: 2,
         type: 'Surgery',
         date: '2022-05-20',
         note: 'Appendectomy',
      },
   ];

   test('renders no history message when history is empty', () => {
      render(<MedicalHistoryList history={[]} />);
      expect(screen.getByText(/No medical history records found/i)).toBeInTheDocument();
   });

   test('renders list of history records', () => {
      render(<MedicalHistoryList history={mockHistory} />);
      expect(screen.getByText('Diagnosis')).toBeInTheDocument();
      expect(screen.getByText('Flu')).toBeInTheDocument();
      expect(screen.getByText('Surgery')).toBeInTheDocument();
      expect(screen.getByText('Appendectomy')).toBeInTheDocument();
   });
});
