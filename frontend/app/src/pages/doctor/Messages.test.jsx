import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import Messages from './Messages';

// Mock dependencies
jest.mock('../../components/common/Card', () => ({ children, className }) => <div className={`mock-card ${className}`}>{children}</div>);
jest.mock('../../components/common/Button', () => ({ children }) => <button>{children}</button>);
jest.mock('lucide-react', () => ({
   Search: () => <span>SearchIcon</span>,
   PenSquare: () => <span>PenSquareIcon</span>,
   MessageSquare: () => <span>MessageSquareIcon</span>,
}));

// Mock data
jest.mock('../../mocks/communication', () => ({
   mockMessages: [
      {
         id: 1,
         sender: 'John Doe',
         role: 'Patient',
         time: '10:00 AM',
         preview: 'Hello doctor',
         avatar: 'JD',
         unread: true,
      },
      {
         id: 2,
         sender: 'Jane Smith',
         role: 'Nurse',
         time: '11:00 AM',
         preview: 'Update on patient',
         avatar: 'JS',
         unread: false,
      },
   ],
}));

describe('Messages Page', () => {
   test('renders messages list', () => {
      render(<Messages />);
      expect(screen.getAllByText('John Doe')[0]).toBeInTheDocument();
      expect(screen.getAllByText('Jane Smith')[0]).toBeInTheDocument();
   });

   test('renders active message details', () => {
      render(<Messages />);
      // Initial active message is the first one
      expect(screen.getAllByText('Hello doctor')[0]).toBeInTheDocument();
   });

   test('switches active message on click', () => {
      render(<Messages />);
      const messageItem = screen.getAllByText('Jane Smith')[0];

      fireEvent.click(messageItem);

      expect(screen.getAllByText('Update on patient')[0]).toBeInTheDocument();
   });

   test('renders reply input', () => {
      render(<Messages />);
      expect(screen.getByPlaceholderText('Type your reply...')).toBeInTheDocument();
   });
});
