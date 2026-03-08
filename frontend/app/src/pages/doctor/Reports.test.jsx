import React from 'react';
import { render, screen } from '@testing-library/react';
import Reports from './Reports';

// Mock dependencies
jest.mock('../../components/common/Card', () => ({ children, className }) => <div className={`mock-card ${className}`}>{children}</div>);
jest.mock('../../components/common/Button', () => ({ children, onClick }) => <button onClick={onClick}>{children}</button>);
jest.mock('../../components/common/IconButton', () => ({ label, onClick }) => <button onClick={onClick}>{label}</button>);
jest.mock('../../components/common/Modal', () => ({ children, isOpen }) => isOpen ? <div>{children}</div> : null);
jest.mock('lucide-react', () => ({
   FileText: () => <span>FileTextIcon</span>,
   Download: () => <span>DownloadIcon</span>,
   BarChart2: () => <span>BarChartIcon</span>,
   PieChart: () => <span>PieChartIcon</span>,
   Check: () => <span>CheckIcon</span>,
}));

// Mock data - not directly used by component, but keeping for reference
jest.mock('../../mocks/communication', () => ({
   mockReports: [
      {
         id: 1,
         title: 'Monthly Analytics',
         date: '2023-01-01',
         type: 'PDF',
         size: '2MB',
      },
   ],
}));

describe('Reports Page', () => {
   test('renders reports page title', () => {
      render(<Reports />);
      expect(screen.getByText('Reports & Analytics')).toBeInTheDocument();
   });

   test('renders quick stats', () => {
      render(<Reports />);
      expect(screen.getByText('Total Reports')).toBeInTheDocument();
      expect(screen.getByText('Analytics')).toBeInTheDocument();
   });

   test('renders empty state for no reports', () => {
      render(<Reports />);
      expect(screen.getByText('No reports generated yet.')).toBeInTheDocument();
   });
});
