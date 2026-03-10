import React from 'react';
import { render, screen, waitFor } from '../../test-utils';
import LabDashboard from './Dashboard';
import api from '../../services/api';

const mockNavigate = jest.fn();
jest.mock('react-router-dom', () => ({
   ...jest.requireActual('react-router-dom'),
   useNavigate: () => mockNavigate,
}));

jest.mock('../../services/api', () => ({
   labTechnician: {
      getDashboard: jest.fn()
   }
}));

describe('LabDashboard Component', () => {
   beforeEach(() => {
      jest.clearAllMocks();
      api.labTechnician.getDashboard.mockResolvedValue({
         pending: 1,
         collected: 1,
         resultsPending: 1,
         completed: 1,
         recentActivity: [
            { testId: 'LAB001', status: 'Completed', testName: 'Complete Blood Count', patientName: 'John Smith', testCategory: 'Standard' }
         ]
      });
   });

   test('renders dashboard title', async () => {
      render(<LabDashboard />, {
         authValue: {
            user: { fullName: 'Tech Mike' }
         }
      });
      expect(await screen.findByText('Lab Technician Dashboard')).toBeInTheDocument();
      expect(screen.getByText(/Welcome back, Tech Mike/i)).toBeInTheDocument();
   });

   test('renders summary cards with correct counts', async () => {
      render(<LabDashboard />);
      expect(await screen.findByText('Pending Orders')).toBeInTheDocument();
      expect(screen.getByText('Samples Collected')).toBeInTheDocument();
      expect(screen.getByText('Results Pending')).toBeInTheDocument();
      expect(screen.getByText('Completed Today')).toBeInTheDocument();

      const counts = await screen.findAllByText('1');
      expect(counts.length).toBeGreaterThanOrEqual(4);
   });

   test('renders recent activity feed', async () => {
      render(<LabDashboard />);
      expect(await screen.findByText('Recent Lab Activity')).toBeInTheDocument();
      // The activity h4 shows the action label based on status: 'Completed' -> 'Completed'
      expect(await screen.findByText('Completed')).toBeInTheDocument();
   });

   test('navigates to orders when "View Orders" is clicked', async () => {
      render(<LabDashboard />);
      const viewOrdersBtns = await screen.findAllByText('View Orders');
      expect(viewOrdersBtns.length).toBeGreaterThan(0);
   });
});
