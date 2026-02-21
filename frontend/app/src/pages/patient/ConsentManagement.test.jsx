import React from 'react';
import { render, screen, fireEvent } from '../../test-utils';
import ConsentManagement from './ConsentManagement';

// Mock the GrantModifyConsent component
jest.mock('./GrantModifyConsent', () => {
   return function MockGrantModifyConsent({ isOpen, onClose }) {
      return isOpen ? (
         <div data-testid="grant-modify-consent-modal">
            <button onClick={onClose}>Close</button>
         </div>
      ) : null;
   };
});

describe('ConsentManagement', () => {
   test('renders consent management page', () => {
      const { container } = render(<ConsentManagement />);
      expect(container).toBeInTheDocument();
   });

   test('displays page header with title', () => {
      render(<ConsentManagement />);
      expect(screen.getByText(/privacy & consent/i)).toBeInTheDocument();
   });

   test('displays HIPAA information banner', () => {
      render(<ConsentManagement />);
      expect(screen.getByText(/your healthcare privacy rights under hipaa/i)).toBeInTheDocument();
   });

   test('renders tab navigation with three tabs', () => {
      render(<ConsentManagement />);
      expect(screen.getByText('Consent Overview')).toBeInTheDocument();
      expect(screen.getByText('Modify Consent')).toBeInTheDocument();
      expect(screen.getByText('Data Management')).toBeInTheDocument();
   });

   test('displays summary cards on overview tab', () => {
      render(<ConsentManagement />);
      expect(screen.getAllByText(/active consents/i).length).toBeGreaterThan(0);
      expect(screen.getAllByText(/pending review/i).length).toBeGreaterThan(0);
      expect(screen.getAllByText(/withdrawn/i).length).toBeGreaterThan(0);
   });

   test('switches to Modify Consent tab when clicked', () => {
      render(<ConsentManagement />);
      const modifyTab = screen.getByText('Modify Consent');
      fireEvent.click(modifyTab);
      expect(screen.getByText(/grant or modify your consents/i)).toBeInTheDocument();
   });

   test('switches to Data Management tab when clicked', () => {
      render(<ConsentManagement />);
      const dataTab = screen.getByText('Data Management');
      fireEvent.click(dataTab);
      expect(screen.getByText(/health data management/i)).toBeInTheDocument();
   });

   test('displays consent history section on overview tab', () => {
      render(<ConsentManagement />);
      expect(screen.getByText(/consent history/i)).toBeInTheDocument();
   });

   test('displays help section that can be expanded', () => {
      render(<ConsentManagement />);
      const helpSection = screen.getByText(/understanding your privacy rights/i);
      expect(helpSection).toBeInTheDocument();
      fireEvent.click(helpSection);
      expect(screen.getByText(/what is hipaa/i)).toBeInTheDocument();
   });

   test('displays legal notices footer', () => {
      render(<ConsentManagement />);
      expect(screen.getByText(/notice of privacy practices/i)).toBeInTheDocument();
      expect(screen.getAllByText(/your privacy rights/i).length).toBeGreaterThan(0);
   });

   test('displays consent categories section', () => {
      render(<ConsentManagement />);
      expect(screen.getByText(/consent categories/i)).toBeInTheDocument();
   });

   test('history filter dropdown changes filter value', () => {
      render(<ConsentManagement />);
      const filterSelect = screen.getByRole('combobox');
      expect(filterSelect).toBeInTheDocument();
      fireEvent.change(filterSelect, { target: { value: '30days' } });
      expect(filterSelect.value).toBe('30days');
   });

   test('displays data overview stats on data management tab', () => {
      render(<ConsentManagement />);
      const dataTab = screen.getByText('Data Management');
      fireEvent.click(dataTab);
      expect(screen.getAllByText(/medical records/i).length).toBeGreaterThan(0);
      expect(screen.getAllByText(/connected providers/i).length).toBeGreaterThan(0);
   });

   test('displays data access log on data management tab', () => {
      render(<ConsentManagement />);
      const dataTab = screen.getByText('Data Management');
      fireEvent.click(dataTab);
      expect(screen.getByText(/data access log/i)).toBeInTheDocument();
   });

   test('displays export data section on data management tab', () => {
      render(<ConsentManagement />);
      const dataTab = screen.getByText('Data Management');
      fireEvent.click(dataTab);
      expect(screen.getByText(/export your data/i)).toBeInTheDocument();
   });

   test('displays data deletion section on data management tab', () => {
      render(<ConsentManagement />);
      const dataTab = screen.getByText('Data Management');
      fireEvent.click(dataTab);
      expect(screen.getByText(/data deletion requests/i)).toBeInTheDocument();
   });

   test('displays download consent history button', () => {
      render(<ConsentManagement />);
      const downloadButton = screen.getByTitle('Download Consent History');
      expect(downloadButton).toBeInTheDocument();
   });

   test('displays quick actions on modify consent tab', () => {
      render(<ConsentManagement />);
      const modifyTab = screen.getByText('Modify Consent');
      fireEvent.click(modifyTab);
      expect(screen.getByText(/quick actions/i)).toBeInTheDocument();
      expect(screen.getByText(/review pending/i)).toBeInTheDocument();
      expect(screen.getByText(/review all/i)).toBeInTheDocument();
      expect(screen.getByText(/download summary/i)).toBeInTheDocument();
   });
});
