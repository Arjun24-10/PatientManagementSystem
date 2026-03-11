import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import LabResults from './LabResults';

import api from '../../services/api';

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

// Mock API
jest.mock('../../services/api', () => ({
   labResults: {
      getAll: jest.fn(),
   }
}));

const mockLabsData = [
   { id: 3, name: 'CT Scan', orderedDate: '2023-11-19', date: '2023-11-20', expectedDate: '2023-11-21', status: 'Completed', file: 'ct_scan.pdf', type: 'Completed' },
   { id: 4, name: 'Ultrasound', orderedDate: '2023-11-19', date: '2023-11-20', expectedDate: '2023-11-22', status: 'Pending', file: 'ultrasound.pdf', type: 'Pending' },
   { id: 5, name: 'Blood Test', orderedDate: '2023-11-20', date: '2023-11-21', expectedDate: '2023-11-21', status: 'Completed', file: 'blood.pdf', type: 'Completed' },
   { id: 6, name: 'X-Ray', orderedDate: '2023-11-21', date: '2023-11-22', expectedDate: '2023-11-23', status: 'Pending', file: 'xray.pdf', type: 'Pending' },
];

describe('LabResults Page', () => {
   beforeEach(() => {
      jest.clearAllMocks();
      api.labResults.getAll.mockResolvedValue(mockLabsData);
   });

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

   test('renders lab results list', async () => {
      render(<LabResults />);
      expect(screen.getByTestId('lab-results-list')).toBeInTheDocument();
      expect(await screen.findByText('Blood Test')).toBeInTheDocument();
      expect(screen.getByText('X-Ray')).toBeInTheDocument();
   });

   test('filters results by search term', async () => {
      render(<LabResults />);
      await screen.findByText('Blood Test'); // Wait for initial render

      const searchInput = screen.getByPlaceholderText('Search by test name...');
      fireEvent.change(searchInput, { target: { value: 'Blood' } });

      expect(screen.getByText('Blood Test')).toBeInTheDocument();
      expect(screen.queryByText('X-Ray')).not.toBeInTheDocument();
   });

   test('filters results by status', async () => {
      render(<LabResults />);
      await screen.findByText('Blood Test'); // Wait for initial render

      fireEvent.click(screen.getByText('Pending'));

      expect(screen.queryByText('Blood Test')).not.toBeInTheDocument();
      expect(screen.getByText('X-Ray')).toBeInTheDocument();
      expect(screen.getByText('Ultrasound')).toBeInTheDocument();
   });
});
