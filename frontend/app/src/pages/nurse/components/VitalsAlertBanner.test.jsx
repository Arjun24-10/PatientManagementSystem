import React from 'react';
import { render, screen, fireEvent } from '../../../test-utils';

import VitalsAlertBanner from './VitalsAlertBanner';

const mockProps = {
    severity: 'critical',
    toneClasses: {
        text: 'text-red-600',
        border: 'border-red-400',
        bg: 'bg-red-50',
    },
    alerts: [
        'Blood pressure 190/120 is critically high',
        'Heart rate 130 is above normal range',
    ],
    acknowledged: false,
    notified: false,
    onAcknowledge: jest.fn(),
    onNotify: jest.fn(),
};

describe('VitalsAlertBanner', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    test('does not render for normal severity', () => {
        const { container } = render(
            <VitalsAlertBanner {...mockProps} severity="normal" />
        );
        
        expect(container.firstChild).toBeNull();
    });

    test('renders for critical severity', () => {
        render(<VitalsAlertBanner {...mockProps} />);
        
        expect(screen.getByText(/critical values detected/i)).toBeInTheDocument();
    });

    test('renders for abnormal severity', () => {
        render(<VitalsAlertBanner {...mockProps} severity="abnormal" />);
        
        expect(screen.getByText(/abnormal vitals detected/i)).toBeInTheDocument();
    });

    test('displays all alert messages', () => {
        render(<VitalsAlertBanner {...mockProps} />);
        
        expect(screen.getByText(/blood pressure 190\/120/i)).toBeInTheDocument();
        expect(screen.getByText(/heart rate 130/i)).toBeInTheDocument();
    });

    test('renders Acknowledge Alert button', () => {
        render(<VitalsAlertBanner {...mockProps} />);
        
        expect(screen.getByRole('button', { name: /acknowledge alert/i })).toBeInTheDocument();
    });

    test('renders Notify Physician button', () => {
        render(<VitalsAlertBanner {...mockProps} />);
        
        expect(screen.getByRole('button', { name: /notify physician/i })).toBeInTheDocument();
    });

    test('calls onAcknowledge when acknowledge button is clicked', () => {
        render(<VitalsAlertBanner {...mockProps} />);
        
        const acknowledgeButton = screen.getByRole('button', { name: /acknowledge alert/i });
        fireEvent.click(acknowledgeButton);
        
        expect(mockProps.onAcknowledge).toHaveBeenCalled();
    });

    test('calls onNotify when notify button is clicked', () => {
        render(<VitalsAlertBanner {...mockProps} />);
        
        const notifyButton = screen.getByRole('button', { name: /notify physician/i });
        fireEvent.click(notifyButton);
        
        expect(mockProps.onNotify).toHaveBeenCalled();
    });

    test('disables acknowledge button when already acknowledged', () => {
        render(<VitalsAlertBanner {...mockProps} acknowledged={true} />);
        
        const acknowledgeButton = screen.getByRole('button', { name: /acknowledge alert/i });
        expect(acknowledgeButton).toBeDisabled();
    });

    test('displays notification timestamp when notified', () => {
        render(<VitalsAlertBanner {...mockProps} notified={true} />);
        
        expect(screen.getByText(/physician notified at/i)).toBeInTheDocument();
    });

    test('displays Critical badge for critical severity', () => {
        render(<VitalsAlertBanner {...mockProps} />);
        
        expect(screen.getAllByText(/critical/i).length).toBeGreaterThan(0);
    });

    test('displays Warning badge for abnormal severity', () => {
        render(<VitalsAlertBanner {...mockProps} severity="abnormal" />);
        
        expect(screen.getAllByText(/warning/i).length).toBeGreaterThan(0);
    });
});
