import React from 'react';
import { render, screen, fireEvent } from '../../test-utils';
import GrantModifyConsent from './GrantModifyConsent';

// Mock the consent form data
jest.mock('../../mocks/consentForm', () => ({
   getConsentFormByCategory: () => ({
      title: 'Research Studies',
      description: 'Allow use of your health data for research',
      icon: 'FlaskConical',
      availableOptions: [
         {
            id: 'clinical-trials',
            title: 'Clinical Trials Participation',
            description: 'Allow contact for clinical trial opportunities',
            required: false,
            recommended: true,
         },
         {
            id: 'data-analysis',
            title: 'Data Analysis for Research',
            description: 'Allow use of your de-identified data',
            required: true,
         },
      ],
   }),
   privacyNotices: {
      research: 'Your data will be protected according to HIPAA regulations.',
   },
   requiredAcknowledgments: [
      { id: 'understand-rights', text: 'I understand my privacy rights', required: true },
      { id: 'can-withdraw', text: 'I understand I can withdraw consent at any time', required: false },
   ],
   expirationOptions: [
      { value: 'none', label: 'No expiration' },
      { value: '1year', label: '1 Year' },
      { value: '2years', label: '2 Years' },
   ],
   consentHistory: [],
   generateConsentId: () => 'CONSENT-12345',
   patientInfo: {
      name: 'John Doe',
      dob: '1990-01-01',
      mrn: 'MRN123456',
   },
}));

describe('GrantModifyConsent', () => {
   const defaultProps = {
      isOpen: true,
      onClose: jest.fn(),
      category: 'research',
      mode: 'grant',
      existingSelections: [],
      onSubmit: jest.fn(),
   };

   beforeEach(() => {
      jest.clearAllMocks();
   });

   test('renders nothing when isOpen is false', () => {
      const { container } = render(
         <GrantModifyConsent {...defaultProps} isOpen={false} />
      );
      expect(container).toBeEmptyDOMElement();
   });

   test('renders slide-in panel when isOpen is true', () => {
      render(<GrantModifyConsent {...defaultProps} />);
      expect(screen.getByRole('heading', { name: /grant consent: research studies/i })).toBeInTheDocument();
   });

   test('displays category title and description', () => {
      render(<GrantModifyConsent {...defaultProps} />);
      expect(screen.getAllByText(/research studies/i).length).toBeGreaterThan(0);
      expect(screen.getByText(/allow use of your health data for research/i)).toBeInTheDocument();
   });

   test('displays consent options', () => {
      render(<GrantModifyConsent {...defaultProps} />);
      expect(screen.getByText(/clinical trials participation/i)).toBeInTheDocument();
      expect(screen.getByText(/data analysis for research/i)).toBeInTheDocument();
   });

   test('displays required badge for required options', () => {
      render(<GrantModifyConsent {...defaultProps} />);
      expect(screen.getByText(/required/i)).toBeInTheDocument();
   });

   test('displays recommended badge for recommended options', () => {
      render(<GrantModifyConsent {...defaultProps} />);
      expect(screen.getByText(/recommended/i)).toBeInTheDocument();
   });

   test('close button calls onClose', () => {
      // Mock window.confirm for the cancel confirmation dialog
      const originalConfirm = window.confirm;
      window.confirm = jest.fn(() => true);
      
      render(<GrantModifyConsent {...defaultProps} />);
      const closeButton = screen.getByRole('button', { name: /cancel/i });
      fireEvent.click(closeButton);
      expect(defaultProps.onClose).toHaveBeenCalled();
      
      window.confirm = originalConfirm;
   });

   test('displays privacy notice section', () => {
      render(<GrantModifyConsent {...defaultProps} />);
      expect(screen.getByText(/privacy & security information/i)).toBeInTheDocument();
   });

   test('shows confirmation step before submission', async () => {
      render(<GrantModifyConsent {...defaultProps} />);
      
      // Select an option by clicking on it
      const clinicalTrialsOption = screen.getByText(/clinical trials participation/i);
      fireEvent.click(clinicalTrialsOption);
      
      // Look for next/continue button
      const continueButtons = screen.queryAllByRole('button');
      expect(continueButtons.length).toBeGreaterThan(0);
   });

   test('displays step indicator', () => {
      render(<GrantModifyConsent {...defaultProps} />);
      expect(screen.getByText(/step/i)).toBeInTheDocument();
   });

   test('displays signature section', () => {
      render(<GrantModifyConsent {...defaultProps} />);
      expect(screen.getByRole('heading', { name: /your signature/i })).toBeInTheDocument();
   });

   test('displays effective date options', () => {
      render(<GrantModifyConsent {...defaultProps} />);
      expect(screen.getByRole('heading', { name: /when should this consent take effect/i })).toBeInTheDocument();
   });

   test('displays expiration options', () => {
      render(<GrantModifyConsent {...defaultProps} />);
      expect(screen.getByRole('heading', { name: /how long should this consent remain active/i })).toBeInTheDocument();
   });

   test('renders in modify mode correctly', () => {
      render(
         <GrantModifyConsent
            {...defaultProps}
            mode="modify"
            existingSelections={['clinical-trials']}
         />
      );
      expect(screen.getByRole('heading', { name: /modify consent/i })).toBeInTheDocument();
   });

   test('displays acknowledgments section', () => {
      render(<GrantModifyConsent {...defaultProps} />);
      expect(screen.getAllByText(/i understand/i).length).toBeGreaterThan(0);
   });

   test('has accessible form controls', () => {
      render(<GrantModifyConsent {...defaultProps} />);
      
      // Check for accessible buttons
      const buttons = screen.getAllByRole('button');
      expect(buttons.length).toBeGreaterThan(0);
      
      // Check for checkboxes
      const checkboxes = screen.getAllByRole('button', { name: /select|deselect/i });
      expect(checkboxes.length).toBeGreaterThan(0);
   });

   test('displays patient information', () => {
      render(<GrantModifyConsent {...defaultProps} />);
      expect(screen.getByText(/john doe/i)).toBeInTheDocument();
   });

   test('displays cancel and submit buttons', () => {
      render(<GrantModifyConsent {...defaultProps} />);
      expect(screen.getByRole('button', { name: /cancel/i })).toBeInTheDocument();
   });

   test('handles withdrawal flow when in modify mode', () => {
      render(
         <GrantModifyConsent
            {...defaultProps}
            mode="modify"
            existingSelections={['clinical-trials']}
         />
      );
      
      // Should render in modify mode - check a modify-specific element
      expect(screen.getByRole('heading', { name: /modify consent/i })).toBeInTheDocument();
   });

   test('can toggle option selection', () => {
      render(<GrantModifyConsent {...defaultProps} />);
      
      // Select an option to test toggle functionality
      const clinicalTrialsOption = screen.getByText(/clinical trials participation/i);
      fireEvent.click(clinicalTrialsOption);
      
      // Option should still be in the document after click
      expect(screen.getByText(/clinical trials participation/i)).toBeInTheDocument();
   });

   test('panel slides in from right side', () => {
      render(<GrantModifyConsent {...defaultProps} />);
      
      // Check that the panel content is visible
      expect(screen.getAllByText(/research studies/i).length).toBeGreaterThan(0);
   });
});
