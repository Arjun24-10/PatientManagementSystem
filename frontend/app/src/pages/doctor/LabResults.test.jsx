import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import LabResults from './LabResults';

// Mock dependencies
jest.mock('../../components/common/Card', () => ({ children, className }) => <div className={`mock-card ${className}`}>{children}</div>);
jest.mock('../../components/common/Input', () => ({ value, onChange, placeholder }) => (
   <input
      value={value}
      onChange={onChange}
      placeholder={placeholder}
      data-testid="search-input"
   />
));
jest.mock('../../components/doctor/LabResultsList', () => ({ labs }) => (
   <div data-testid="lab-results-list">
      {labs.map(lab => <div key={lab.id}>{lab.name}</div>)}
   </div>
));
jest.mock('lucide-react', () => ({
   Search: () => <span>SearchIcon</span>,
   Filter: () => <span>FilterIcon</span>,
   FlaskConical: () => <span>FlaskIcon</span>,
}));

// Mock data
jest.mock('../../mocks/records', () => ({
   mockLabs: [
      { id: 1, name: 'Blood Test', status: 'Normal' },
      { id: 2, name: 'X-Ray', status: 'Pending' },
   ],
}));

describe('LabResults Page', () => {
   test('renders page title', () => {
      render(<LabResults />);
      expect(screen.getByText('Lab Results')).toBeInTheDocument();
   });

   test('renders search input', () => {
      render(<LabResults />);
      expect(screen.getByPlaceholderText('Search by test name...')).toBeInTheDocument();
   });

   test('renders filter buttons', () => {
      render(<LabResults />);
      expect(screen.getByText('All')).toBeInTheDocument();
      expect(screen.getByText('Completed')).toBeInTheDocument();
      expect(screen.getByText('Pending')).toBeInTheDocument();
      expect(screen.getByText('Abnormal')).toBeInTheDocument();
   });

   test('renders lab results list', () => {
      render(<LabResults />);
      expect(screen.getByTestId('lab-results-list')).toBeInTheDocument();
      expect(screen.getByText('Blood Test')).toBeInTheDocument();
      expect(screen.getByText('X-Ray')).toBeInTheDocument();
   });

   test('filters results by search term', () => {
      render(<LabResults />);
      const searchInput = screen.getByPlaceholderText('Search by test name...');

      fireEvent.change(searchInput, { target: { value: 'Blood' } });

      expect(screen.getByText('Blood Test')).toBeInTheDocument();
      expect(screen.queryByText('X-Ray')).not.toBeInTheDocument();
   });

   test('filters results by status', () => {
      render(<LabResults />);

      fireEvent.click(screen.getByText('Pending'));

      expect(screen.queryByText('Blood Test')).not.toBeInTheDocument();
      expect(screen.getByText('X-Ray')).toBeInTheDocument();
   });
});
