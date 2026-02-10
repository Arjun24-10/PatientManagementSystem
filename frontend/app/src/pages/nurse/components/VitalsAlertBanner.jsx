import React from 'react';
import { AlertTriangle, MessageSquare } from 'lucide-react';
import Button from '../../../components/common/Button';

const VitalsAlertBanner = ({
    severity,
    toneClasses,
    alerts,
    acknowledged,
    notified,
    onAcknowledge,
    onNotify,
}) => {
    if (severity === 'normal') {
        return null;
    }

    return (
        <div
            className={`rounded-lg border px-3 py-2.5 flex flex-col md:flex-row md:items-center md:justify-between gap-2 shadow-soft ${toneClasses.bg} ${toneClasses.border} ${!acknowledged && severity === 'critical' ? 'animate-pulse' : ''}`}
            role="alert"
        >
            <div className="flex items-start gap-2">
                <AlertTriangle className={`w-4 h-4 mt-0.5 ${toneClasses.text}`} aria-hidden="true" />
                <div>
                    <p className={`font-semibold text-sm ${toneClasses.text}`}>
                        {severity === 'critical' ? 'Critical values detected' : 'Abnormal vitals detected'}
                    </p>
                    <ul className="mt-2 space-y-1 text-sm text-gray-700 dark:text-slate-300">
                        {alerts.map((alert) => (
                            <li key={alert} className="flex items-center gap-2">
                                <span className={`inline-flex px-2.5 py-0.5 rounded-full text-xs font-semibold ${severity === 'critical' ? 'bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400' : 'bg-amber-100 dark:bg-amber-900/30 text-amber-600 dark:text-amber-400'}`}>
                                    {severity === 'critical' ? 'Critical' : 'Warning'}
                                </span>
                                <span>{alert}</span>
                            </li>
                        ))}
                    </ul>
                    {notified && (
                        <p className="text-xs text-gray-600 dark:text-slate-400 mt-2">Physician notified at {new Date().toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}</p>
                    )}
                </div>
            </div>
            <div className="flex flex-wrap gap-2">
                <Button
                    variant="outline"
                    className={`text-xs font-semibold ${acknowledged ? 'text-gray-500 border-gray-300 bg-white' : ''}`}
                    onClick={onAcknowledge}
                    disabled={acknowledged}
                >
                    Acknowledge Alert
                </Button>
                <Button variant="danger" className="flex items-center gap-1.5 text-xs" onClick={onNotify}>
                    <MessageSquare className="w-3.5 h-3.5" />
                    Notify Physician
                </Button>
            </div>
        </div>
    );
};

export default VitalsAlertBanner;
