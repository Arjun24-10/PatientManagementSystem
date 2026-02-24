import React from 'react';
import { Thermometer, Download, Printer } from 'lucide-react';
import Button from '../../../components/common/Button';

const VitalsSectionHeader = ({ patient, onExportPdf, onPrint }) => (
    <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-2">
        <div className="flex items-start lg:items-center gap-2">
            <Thermometer className="w-5 h-5 text-brand-medium" aria-hidden="true" />
            <div>
                <h2 id="patient-vitals" className="text-sm font-bold text-gray-900 dark:text-slate-100">Patient Vitals</h2>
                <p className="text-xs text-gray-500 dark:text-slate-400">{patient ? `${patient.name} · Room ${patient.room} · Age ${patient.age}` : 'No patient selected'}</p>
            </div>
        </div>
        <div className="flex flex-wrap gap-2">
            <Button
                variant="outline"
                className="flex items-center gap-1.5 text-xs"
                onClick={onExportPdf}
            >
                <Download className="w-3.5 h-3.5" />
                Export PDF
            </Button>
            <Button
                variant="outline"
                className="flex items-center gap-1.5 text-xs"
                onClick={onPrint}
            >
                <Printer className="w-3.5 h-3.5" />
                Print
            </Button>
        </div>
    </div>
);

export default VitalsSectionHeader;
