import React from 'react';
import { Download } from 'lucide-react';
import {
    ResponsiveContainer,
    LineChart,
    CartesianGrid,
    XAxis,
    YAxis,
    Tooltip as RechartsTooltip,
    Legend,
    ReferenceArea,
    Line,
} from 'recharts';
import Card from '../../../components/common/Card';
import Button from '../../../components/common/Button';

const rangeLabels = {
    '24h': 'Last 24 hrs',
    '48h': 'Last 48 hrs',
    '7d': 'Last 7 days',
    custom: 'Custom',
};

const VitalsTrendCard = ({
    timeRange,
    onTimeRangeChange,
    customRange,
    onCustomRangeChange,
    visibleVitals,
    onToggleVital,
    chartData,
    chartDomain,
    vitalLimits,
    onExport,
}) => (
    <Card className="p-6 space-y-6 border border-gray-100 shadow-soft">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
            <div>
                <h3 className="text-lg font-bold text-gray-900">Vitals Trend (Recharts)</h3>
                <p className="text-sm text-gray-500">Multi-parameter view with normal range shading</p>
            </div>
            <div className="flex flex-wrap gap-2">
                {Object.keys(rangeLabels).map((range) => (
                    <button
                        key={range}
                        type="button"
                        className={`px-3 py-1.5 rounded-full text-sm font-semibold border transition ${timeRange === range ? 'bg-brand-medium text-white border-brand-medium' : 'border-gray-200 text-gray-600 hover:bg-gray-50'}`}
                        onClick={() => onTimeRangeChange(range)}
                    >
                        {rangeLabels[range]}
                    </button>
                ))}
            </div>
        </div>

        {timeRange === 'custom' && (
            <div className="flex flex-wrap gap-3">
                <div>
                    <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1">Start</label>
                    <input
                        type="date"
                        className="rounded-lg border border-gray-200 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand-medium"
                        value={customRange.start}
                        onChange={(event) => onCustomRangeChange({ ...customRange, start: event.target.value })}
                    />
                </div>
                <div>
                    <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1">End</label>
                    <input
                        type="date"
                        className="rounded-lg border border-gray-200 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand-medium"
                        value={customRange.end}
                        onChange={(event) => onCustomRangeChange({ ...customRange, end: event.target.value })}
                    />
                </div>
            </div>
        )}

        <div className="flex flex-wrap gap-2 text-xs text-gray-500">
            {[{ key: 'bpSystolic', label: 'Systolic BP' }, { key: 'bpDiastolic', label: 'Diastolic BP' }, { key: 'heartRate', label: 'Heart Rate' }, { key: 'temperature', label: 'Temperature' }, { key: 'respiratoryRate', label: 'Resp Rate' }, { key: 'oxygenSaturation', label: 'SpO2' }].map((item) => (
                <button
                    key={item.key}
                    type="button"
                    className={`px-3 py-1 rounded-full border transition ${visibleVitals[item.key] ? 'bg-brand-light text-brand-deep border-brand-medium/40' : 'border-gray-200 text-gray-500 hover:bg-gray-50'}`}
                    onClick={() => onToggleVital(item.key)}
                >
                    {visibleVitals[item.key] ? 'Hide' : 'Show'} {item.label}
                </button>
            ))}
        </div>

        <div className="h-80">
            {chartData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={chartData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                        <XAxis dataKey="label" stroke="#94a3b8" tick={{ fontSize: 12 }} />
                        <YAxis domain={chartDomain} stroke="#94a3b8" tick={{ fontSize: 12 }} />
                        <RechartsTooltip
                            contentStyle={{ borderRadius: 12, border: '1px solid #e2e8f0', padding: 12 }}
                            labelStyle={{ fontWeight: 600, color: '#0f172a' }}
                        />
                        <Legend />
                        {visibleVitals.bpSystolic && (
                            <ReferenceArea y1={vitalLimits.bp.normal.systolic[0]} y2={vitalLimits.bp.normal.systolic[1]} fill="#E3F2FD" fillOpacity={0.2} />
                        )}
                        {visibleVitals.heartRate && (
                            <ReferenceArea y1={vitalLimits.heartRate.normal[0]} y2={vitalLimits.heartRate.normal[1]} fill="#E8F5E9" fillOpacity={0.15} />
                        )}
                        {visibleVitals.temperature && (
                            <ReferenceArea y1={vitalLimits.temperature.normalF[0]} y2={vitalLimits.temperature.normalF[1]} fill="#FFF8E1" fillOpacity={0.18} />
                        )}
                        {visibleVitals.respiratoryRate && (
                            <ReferenceArea y1={vitalLimits.respiratoryRate.normal[0]} y2={vitalLimits.respiratoryRate.normal[1]} fill="#F1F5F9" fillOpacity={0.18} />
                        )}
                        {visibleVitals.oxygenSaturation && (
                            <ReferenceArea y1={vitalLimits.oxygenSaturation.normal[0]} y2={vitalLimits.oxygenSaturation.normal[1]} fill="#ECFDF5" fillOpacity={0.18} />
                        )}
                        {visibleVitals.bpSystolic && <Line type="monotone" dataKey="bpSystolic" name="Systolic BP" stroke="#1565C0" strokeWidth={2} dot={false} />}
                        {visibleVitals.bpDiastolic && <Line type="monotone" dataKey="bpDiastolic" name="Diastolic BP" stroke="#1E88E5" strokeWidth={2} dot={false} strokeDasharray="5 4" />}
                        {visibleVitals.heartRate && <Line type="monotone" dataKey="heartRate" name="Heart Rate" stroke="#F44336" strokeWidth={2} dot={false} />}
                        {visibleVitals.temperature && <Line type="monotone" dataKey="temperature" name="Temperature" stroke="#FB8C00" strokeWidth={2} dot={false} />}
                        {visibleVitals.respiratoryRate && <Line type="monotone" dataKey="respiratoryRate" name="Respiratory Rate" stroke="#43A047" strokeWidth={2} dot={false} />}
                        {visibleVitals.oxygenSaturation && <Line type="monotone" dataKey="oxygenSaturation" name="SpO2" stroke="#8E24AA" strokeWidth={2} dot={false} />}
                    </LineChart>
                </ResponsiveContainer>
            ) : (
                <div className="h-full flex items-center justify-center text-sm text-gray-500 bg-gray-50 rounded-xl border border-dashed border-gray-200">
                    No vitals data for the selected range.
                </div>
            )}
        </div>

        <div className="flex justify-end">
            <Button variant="outline" className="flex items-center gap-2" onClick={onExport}>
                <Download className="w-4 h-4" />
                Export Trend PDF
            </Button>
        </div>
    </Card>
);

export default VitalsTrendCard;
