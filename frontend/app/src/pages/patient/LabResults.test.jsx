import React from 'react';
import { render, screen, waitFor } from '../../test-utils';
import LabResults from './LabResults';
import api from '../../services/api';

jest.mock('../../services/api', () => ({
   patients: { getMe: jest.fn().mockResolvedValue({ id: 'P001' }) },
   labResults: { getByPatient: jest.fn().mockResolvedValue([]) }
}));

describe('Lab Results Page', () => {
   beforeEach(() => {
      jest.clearAllMocks();
   });

   test('renders lab results page', async () => {
      const { container } = render(<LabResults />);
      expect(await screen.findByRole('heading', { name: /lab results/i })).toBeInTheDocument();
   });

   test('displays lab results heading', async () => {
      render(<LabResults />);
      expect(await screen.findByRole('heading', { name: /lab results/i })).toBeInTheDocument();
   });
});
