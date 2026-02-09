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
            className={`rounded-2xl border px-5 py-4 flex flex-col md:flex-row md:items-center md:justify-between gap-4 shadow-soft ${toneClasses.bg} ${toneClasses.border} ${!acknowledged && severity === 'critical' ? 'animate-pulse' : ''}`}
            role="alert"
        >
            <div className="flex items-start gap-3">
                <AlertTriangle className={`w-5 h-5 mt-0.5 ${toneClasses.text}`} aria-hidden="true" />
                <div>
                    <p className={`font-semibold text-sm ${toneClasses.text}`}>
                        {severity === 'critical' ? 'Critical values detected' : 'Abnormal vitals detected'}
                    </p>
                    <ul className="mt-2 space-y-1 text-sm text-gray-700">
                        {alerts.map((alert) => (
                            <li key={alert} className="flex items-center gap-2">
                                <span className={`inline-flex px-2.5 py-0.5 rounded-full text-xs font-semibold ${severity === 'critical' ? 'bg-red-100 text-red-600' : 'bg-amber-100 text-amber-600'}`}>
                                    {severity === 'critical' ? 'Critical' : 'Warning'}
                                </span>
                                <span>{alert}</span>
                            </li>
                        ))}
                    </ul>
                    {notified && (
                        <p className="text-xs text-gray-600 mt-2">Physician notified at {new Date().toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}</p>
                    )}
                </div>
            </div>
            <div className="flex flex-wrap gap-3">
                <Button
                    variant="outline"
                    className={`text-sm font-semibold ${acknowledged ? 'text-gray-500 border-gray-300 bg-white' : ''}`}
                    onClick={onAcknowledge}
                    disabled={acknowledged}
                >
                    Acknowledge Alert
                </Button>
                <Button variant="danger" className="flex items-center gap-2" onClick={onNotify}>
                    <MessageSquare className="w-4 h-4" />
                    Notify Physician
                </Button>
            </div>
        </div>
    );
};

export default VitalsAlertBanner;
