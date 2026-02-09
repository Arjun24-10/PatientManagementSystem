import React from 'react';
import { render, screen } from '@testing-library/react';
import Reports from './Reports';

// Mock dependencies
jest.mock('../../components/common/Card', () => ({ children, className }) => <div className={`mock-card ${className}`}>{children}</div>);
jest.mock('../../components/common/Button', () => ({ children }) => <button>{children}</button>);
jest.mock('lucide-react', () => ({
   FileText: () => <span>FileTextIcon</span>,
   Download: () => <span>DownloadIcon</span>,
   BarChart2: () => <span>BarChartIcon</span>,
   PieChart: () => <span>PieChartIcon</span>,
}));

// Mock data
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

   test('renders list of reports', () => {
      render(<Reports />);
      expect(screen.getByText('Monthly Analytics')).toBeInTheDocument();
      expect(screen.getByText('PDF')).toBeInTheDocument();
   });
});
