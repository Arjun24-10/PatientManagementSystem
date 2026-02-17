import React from 'react';
import { render, fireEvent } from '../test-utils';
import DashboardLayout from './DashboardLayout';

const mockNavigate = jest.fn();

jest.mock('react-router-dom', () => ({
   ...jest.requireActual('react-router-dom'),
   useNavigate: () => mockNavigate,
   useLocation: () => ({ pathname: '/dashboard/doctor' }),
}));

describe('DashboardLayout Component', () => {
   beforeEach(() => {
      mockNavigate.mockClear();
   });

   test('renders layout', () => {
      const { container } = render(
         <DashboardLayout role="doctor" userName="Dr. Smith">
            <div>Content</div>
         </DashboardLayout>
      );
      expect(container).toBeInTheDocument();
   });

   test('sidebar profile click navigates to profile page', () => {
      const { getAllByText } = render(
         <DashboardLayout role="doctor" userName="Dr. Smith">
            <div>Content</div>
         </DashboardLayout>
      );

      // Find the user name in the sidebar (there are two, one in mobile/header and one in sidebar)
      const profileNames = getAllByText('Dr. Smith');
      // Click the first one
      fireEvent.click(profileNames[0]);

      // Verify navigation
      expect(mockNavigate).toHaveBeenCalledWith('/dashboard/doctor/profile');
   });
});
