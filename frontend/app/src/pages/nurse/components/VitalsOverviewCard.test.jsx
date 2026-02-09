import React from 'react';
import { render, screen } from '../../../test-utils';

import VitalsOverviewCard from './VitalsOverviewCard';

// Mock lucide-react icons
jest.mock('lucide-react', () => ({
    TrendingUp: () => <span data-testid="trending-up" />,
    TrendingDown: () => <span data-testid="trending-down" />,
    Minus: () => <span data-testid="minus" />,
}));

const mockProps = {
    alertSeverity: 'normal',
    vitalsData: {
        current: {
            bp: { systolic: 120, diastolic: 80 },
            heartRate: 72,
            temperature: { value: 98.6, unit: 'F', route: 'oral' },
            respiratoryRate: 16,
            oxygenSaturation: 98,
            painLevel: 2,
        },
    },
    statuses: {
        bp: 'normal',
        heartRate: 'normal',
        temperature: 'normal',
        respiratoryRate: 'normal',
        oxygenSaturation: 'normal',
        painLevel: 'normal',
    },
    trends: {
        bpSystolic: 'stable',
        heartRate: 'up',
        temperature: 'stable',
        respiratoryRate: 'stable',
        oxygenSaturation: 'stable',
        painLevel: 'down',
    },
    normalText: {
        bp: 'Normal: 90-130 / 60-85',
        heartRate: 'Normal: 60-100 bpm',
        temperature: 'Normal: 97-99°F',
        respiratoryRate: 'Normal: 12-20 /min',
        oxygenSaturation: 'Normal: 95-100%',
        painLevel: 'Normal: 0-3',
    },
    currentPainFace: { icon: () => null, label: 'Mild' },
    getStatusClasses: (status) => ({
        text: status === 'normal' ? 'text-green-600' : 'text-red-600',
        bg: status === 'normal' ? 'bg-green-50' : 'bg-red-50',
        border: status === 'normal' ? 'border-green-400' : 'border-red-400',
    }),
    trendIcon: (trend) => {
        if (trend === 'up') return <span data-testid="trend-up">↑</span>;
        if (trend === 'down') return <span data-testid="trend-down">↓</span>;
        return <span data-testid="trend-stable">→</span>;
    },
    lastTimestamp: '10:30 AM',
};

describe('VitalsOverviewCard', () => {
    test('renders card with title', () => {
        render(<VitalsOverviewCard {...mockProps} />);
        
        expect(screen.getByText(/current vitals overview/i)).toBeInTheDocument();
    });

    test('displays last updated timestamp', () => {
        render(<VitalsOverviewCard {...mockProps} />);
        
        expect(screen.getByText(/updated 10:30 am/i)).toBeInTheDocument();
    });

    test('displays Stable badge for normal severity', () => {
        render(<VitalsOverviewCard {...mockProps} />);
        
        expect(screen.getAllByText(/stable/i).length).toBeGreaterThan(0);
    });

    test('displays Critical badge for critical severity', () => {
        render(<VitalsOverviewCard {...mockProps} alertSeverity="critical" />);
        
        expect(screen.getByText(/critical/i)).toBeInTheDocument();
    });

    test('displays Monitoring badge for abnormal severity', () => {
        render(<VitalsOverviewCard {...mockProps} alertSeverity="abnormal" />);
        
        expect(screen.getByText(/monitoring/i)).toBeInTheDocument();
    });

    test('displays blood pressure value', () => {
        render(<VitalsOverviewCard {...mockProps} />);
        
        expect(screen.getByText(/blood pressure/i)).toBeInTheDocument();
        expect(screen.getByText(/120\/80/i)).toBeInTheDocument();
    });

    test('displays heart rate value', () => {
        render(<VitalsOverviewCard {...mockProps} />);
        
        expect(screen.getByText(/heart rate/i)).toBeInTheDocument();
        expect(screen.getByText(/72 bpm/i)).toBeInTheDocument();
    });

    test('displays temperature value', () => {
        render(<VitalsOverviewCard {...mockProps} />);
        
        expect(screen.getByText(/temperature/i)).toBeInTheDocument();
        expect(screen.getByText(/98\.6/i)).toBeInTheDocument();
    });

    test('displays respiratory rate value', () => {
        render(<VitalsOverviewCard {...mockProps} />);
        
        expect(screen.getByText(/respiratory rate/i)).toBeInTheDocument();
        expect(screen.getByText(/16 \/min/i)).toBeInTheDocument();
    });

    test('displays SpO2 value', () => {
        render(<VitalsOverviewCard {...mockProps} />);
        
        expect(screen.getByText(/spo2/i)).toBeInTheDocument();
        expect(screen.getByText(/98 %/i)).toBeInTheDocument();
    });

    test('displays pain level value', () => {
        render(<VitalsOverviewCard {...mockProps} />);
        
        expect(screen.getByText(/pain level/i)).toBeInTheDocument();
        expect(screen.getByText(/2 \/ 10/i)).toBeInTheDocument();
    });

    test('displays temperature unit and route', () => {
        render(<VitalsOverviewCard {...mockProps} />);
        
        expect(screen.getByText(/98\.6 °F \(oral\)/i)).toBeInTheDocument();
    });

    test('renders all vital sign items', () => {
        render(<VitalsOverviewCard {...mockProps} />);
        
        // Should have 6 vital sign cards
        const vitalLabels = [
            'Blood Pressure',
            'Heart Rate',
            'Temperature',
            'Respiratory Rate',
            'SpO2',
            'Pain Level',
        ];
        
        vitalLabels.forEach(label => {
            expect(screen.getByText(new RegExp(label, 'i'))).toBeInTheDocument();
        });
    });
});
