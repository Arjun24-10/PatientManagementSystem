import React from 'react';
import { screen, fireEvent, waitFor } from '@testing-library/react';
import Prescriptions from './Prescriptions';
import { renderWithProviders } from '../../testHelpers';

// Test data
const TEST_PRESCRIPTIONS = [
   {
      id: 1,
      name: 'Amoxicillin',
      dosage: '500mg',
      frequency: '3x daily',
      prescribedBy: 'Dr. Smith',
      active: true,
   },
   {
      id: 2,
      name: 'Ibuprofen',
      dosage: '200mg',
      frequency: 'As needed',
      prescribedBy: 'Dr. Jones',
      active: false,
   }
];

// Mock dependencies
jest.mock('../../components/common/Card', () => ({ children, className }) => <div className={`mock-card ${className}`}>{children}</div>);
jest.mock('../../components/common/Button', () => ({ children, onClick, className }) => (
   <button onClick={onClick} className={className}>
      {children}
   </button>
));
jest.mock('../../components/common/IconButton', () => ({ label, onClick }) => (
   <button onClick={onClick}>{label}</button>
));
jest.mock('../../components/common/Badge', () => ({ children }) => <span>{children}</span>);
jest.mock('../../components/common/Modal', () => ({ children, isOpen, title }) => (
   isOpen ? (
      <div data-testid="modal">
         <h1>{title}</h1>
         {children}
      </div>
   ) : null
));
jest.mock('../../components/common/Input', () => ({ value, onChange, placeholder }) => (
   <input
      value={value}
      onChange={onChange}
      placeholder={placeholder}
   />
));
jest.mock('../../services/api', () => ({
   doctors: { getPatientsByDoctor: jest.fn().mockRejectedValue(new Error('not yet available')) },
   prescriptions: {
      getAll: jest.fn().mockResolvedValue(TEST_PRESCRIPTIONS),
      create: jest.fn(),
      update: jest.fn()
   },
}));
jest.mock('lucide-react', () => ({
   Plus: () => <span>PlusIcon</span>,
   Search: () => <span>SearchIcon</span>,
   Filter: () => <span>FilterIcon</span>,
   Pill: () => <span>PillIcon</span>,
}));

// Mock data
jest.mock('../../mocks/records', () => ({
   mockPrescriptions: TEST_PRESCRIPTIONS,
}));

describe('Prescriptions Page', () => {
   test('renders prescriptions list', async () => {
      renderWithProviders(<Prescriptions />);
      await waitFor(() => {
         expect(screen.getByText('Amoxicillin')).toBeInTheDocument();
         expect(screen.getByText('Ibuprofen')).toBeInTheDocument();
      }, { timeout: 3000 });
   });

   test('filters prescriptions by search', async () => {
      renderWithProviders(<Prescriptions />);
      await waitFor(() => {
         expect(screen.getByText('Amoxicillin')).toBeInTheDocument();
      }, { timeout: 3000 });
      const searchInput = screen.getByPlaceholderText('Search prescriptions...');

      fireEvent.change(searchInput, { target: { value: 'Amoxicillin' } });

      expect(screen.getByText('Amoxicillin')).toBeInTheDocument();
      expect(screen.queryByText('Ibuprofen')).not.toBeInTheDocument();
   });

   test('opens new prescription modal', () => {
      renderWithProviders(<Prescriptions />);
      const newButton = screen.getByText(/New Prescription/i);

      fireEvent.click(newButton);

      expect(screen.getByTestId('modal')).toBeInTheDocument();
      // Validate title inside modal specifically to avoid finding the button text
      const modal = screen.getByTestId('modal');
      expect(modal).toHaveTextContent('New Prescription');
   });
});
