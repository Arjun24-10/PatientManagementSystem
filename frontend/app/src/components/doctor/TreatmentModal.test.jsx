import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import TreatmentModal from './TreatmentModal';

// Mock dependencies
jest.mock('../common/Modal', () => ({ children, isOpen, onClose, title }) => (
   isOpen ? (
      <div data-testid="modal">
         <h1>{title}</h1>
         <button onClick={onClose}>Close</button>
         {children}
      </div>
   ) : null
));
jest.mock('../common/Input', () => ({ label, value, onChange, placeholder, type }) => (
   <div>
      <label>{label}</label>
      <input
         type={type || 'text'}
         value={value}
         onChange={onChange}
         placeholder={placeholder}
         data-testid={`input-${label}`}
      />
   </div>
));
jest.mock('../common/Button', () => ({ children, onClick, type }) => (
   <button onClick={onClick} type={type}>
      {children}
   </button>
));

describe('TreatmentModal', () => {
   test('renders nothing when not open', () => {
      render(<TreatmentModal isOpen={false} onClose={() => { }} onAdd={() => { }} />);
      expect(screen.queryByTestId('modal')).not.toBeInTheDocument();
   });

   test('renders modal content when open', () => {
      render(<TreatmentModal isOpen={true} onClose={() => { }} onAdd={() => { }} />);
      expect(screen.getByTestId('modal')).toBeInTheDocument();
      expect(screen.getByText('Add New Treatment Plan')).toBeInTheDocument();
   });

   test('calls onAdd with form data when submitted', () => {
      const handleAdd = jest.fn();
      const handleClose = jest.fn();
      render(<TreatmentModal isOpen={true} onClose={handleClose} onAdd={handleAdd} />);

      // Fill out form
      fireEvent.change(screen.getByTestId('input-Treatment / Therapy Name'), { target: { value: 'Physio' } });
      fireEvent.change(screen.getByTestId('input-Frequency'), { target: { value: 'Daily' } });
      // Note: The clinical notes is a textarea in the component, not an Input component
      const notesArea = screen.getByPlaceholderText('Specific instructions, goals, or precautions...');
      fireEvent.change(notesArea, { target: { value: 'Rest' } });

      // Submit
      fireEvent.click(screen.getByText('Add Treatment'));

      expect(handleAdd).toHaveBeenCalledWith(expect.objectContaining({
         name: 'Physio',
         frequency: 'Daily',
         notes: 'Rest'
      }));
      expect(handleClose).toHaveBeenCalled();
   });
});
