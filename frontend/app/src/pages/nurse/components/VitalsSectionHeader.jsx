import React from 'react';
import { Thermometer, Download, Printer } from 'lucide-react';
import Button from '../../../components/common/Button';

const VitalsSectionHeader = ({ patient, onExportPdf, onPrint }) => (
    <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div className="flex items-start lg:items-center gap-3">
            <Thermometer className="w-6 h-6 text-brand-medium" aria-hidden="true" />
            <div>
                <h2 id="patient-vitals" className="text-xl font-bold text-gray-900 dark:text-slate-100">Patient Vitals</h2>
                <p className="text-sm text-gray-500 dark:text-slate-400">{patient ? `${patient.name} · Room ${patient.room} · Age ${patient.age}` : 'No patient selected'}</p>
            </div>
        </div>
        <div className="flex flex-wrap gap-3">
            <Button
                variant="outline"
                className="flex items-center gap-2"
                onClick={onExportPdf}
            >
                <Download className="w-4 h-4" />
                Export PDF
            </Button>
            <Button
                variant="outline"
                className="flex items-center gap-2"
                onClick={onPrint}
            >
                <Printer className="w-4 h-4" />
                Print
            </Button>
        </div>
    </div>
);

export default VitalsSectionHeader;
