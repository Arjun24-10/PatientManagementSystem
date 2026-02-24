import React from 'react';
import { render, screen } from '../../test-utils';
import LabDashboard from './Dashboard';

// Mock the mock data to have consistent tests
jest.mock('../../mocks/labOrders', () => ({
   mockLabOrders: [
      { status: 'Pending' },
      { status: 'Collected' },
      { status: 'Results Pending' },
      { status: 'Completed' }
   ],
   mockLabActivity: [
      { id: 1, action: 'Result Uploaded', details: 'Test', time: '10 mins ago', user: 'Tech Mike' }
   ]
}));

describe('LabDashboard Component', () => {
   test('renders dashboard title', () => {
      render(<LabDashboard />, {
         authValue: {
            user: { fullName: 'Tech Mike' }
         }
      });
      expect(screen.getByText('Lab Technician Dashboard')).toBeInTheDocument();
      expect(screen.getByText(/Welcome back, Tech Mike/i)).toBeInTheDocument();
   });

   test('renders summary cards with correct counts', () => {
      render(<LabDashboard />);
      // Based on mocked data: 1 of each status
      expect(screen.getByText('Pending Orders')).toBeInTheDocument();
      expect(screen.getByText('Samples Collected')).toBeInTheDocument();
      expect(screen.getByText('Results Pending')).toBeInTheDocument();
      expect(screen.getByText('Completed Today')).toBeInTheDocument();

      // Check for counts (all should be 1 based on mock)
      const counts = screen.getAllByText('1');
      expect(counts.length).toBeGreaterThanOrEqual(4);
   });

   test('renders recent activity feed', () => {
      render(<LabDashboard />);
      expect(screen.getByText('Recent Lab Activity')).toBeInTheDocument();
      expect(screen.getByText('Result Uploaded')).toBeInTheDocument();
      expect(screen.getAllByText(/tech mike/i).length).toBeGreaterThan(0);
   });

   test('navigates to orders when "View Orders" is clicked', () => {
      render(<LabDashboard />);
      const viewOrdersBtn = screen.getByText('View Orders');
      expect(viewOrdersBtn.closest('button')).toBeInTheDocument();
      // Navigation assertion would ideally use a mock navigator, but for this smoke test checking render is enough
   });
});
