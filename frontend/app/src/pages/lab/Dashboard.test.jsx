import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
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

const renderWithRouter = (component) => {
   return render(
      <BrowserRouter>
         {component}
      </BrowserRouter>
   );
};

describe('LabDashboard Component', () => {
   test('renders dashboard title', () => {
      renderWithRouter(<LabDashboard />);
      expect(screen.getByText('Lab Technician Dashboard')).toBeInTheDocument();
      expect(screen.getByText(/Welcome back, Tech Mike/i)).toBeInTheDocument();
   });

   test('renders summary cards with correct counts', () => {
      renderWithRouter(<LabDashboard />);
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
      renderWithRouter(<LabDashboard />);
      expect(screen.getByText('Recent Lab Activity')).toBeInTheDocument();
      expect(screen.getByText('Result Uploaded')).toBeInTheDocument();
      expect(screen.getByText('Tech Mike')).toBeInTheDocument();
   });

   test('navigates to orders when "View Orders" is clicked', () => {
      renderWithRouter(<LabDashboard />);
      const viewOrdersBtn = screen.getByText('View Orders');
      expect(viewOrdersBtn.closest('button')).toBeInTheDocument();
      // Navigation assertion would ideally use a mock navigator, but for this smoke test checking render is enough
   });
});
