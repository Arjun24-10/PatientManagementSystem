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
      const { getByText } = render(
         <DashboardLayout role="doctor" userName="Dr. Smith">
            <div>Content</div>
         </DashboardLayout>
      );

      // Find the user name in the sidebar (there are two, one in mobile/header (hidden on desktop) and one in sidebar)
      // The sidebar one is in the "Premium User Profile Section"
      // We can search for the role text "doctor" which is also present.
      // A better way is to look for the container with the onClick. 
      // Since we added `glass-card-dark` class to the clickable div, we can try to find by text and traverse up, or just click the text.
      // The text "Dr. Smith" appears in the sidebar.

      const profileName = getByText('Dr. Smith');
      // Click it
      fireEvent.click(profileName);

      // Verify navigation
      expect(mockNavigate).toHaveBeenCalledWith('/dashboard/doctor/profile');
   });
});
