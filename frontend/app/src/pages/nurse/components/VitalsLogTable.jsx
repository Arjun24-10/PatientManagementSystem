import React from 'react';
import { Search, Printer, Download, AlertTriangle } from 'lucide-react';
import Card from '../../../components/common/Card';
import Button from '../../../components/common/Button';

const VitalsLogTable = ({
    historySearch,
    onSearch,
    historyRange,
    onHistoryRangeChange,
    filteredVitalsLog,
    formatTimestamp,
    parseBpString,
    classifyBp,
    classifyValue,
    getStatusClasses,
    defaultRecorder,
    onPrint,
    onExport,
}) => (
    <Card className="p-6 space-y-6 border border-gray-100 shadow-soft">
        <div className="flex flex-col xl:flex-row xl:items-center xl:justify-between gap-4">
            <div>
                <h3 className="text-lg font-bold text-gray-900">Time-Stamped Vitals Log</h3>
                <p className="text-sm text-gray-500">Complete record of submissions with color-coded severity</p>
            </div>
            <div className="flex flex-wrap gap-3 items-center">
                <div className="relative">
                    <Search className="w-4 h-4 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" aria-hidden="true" />
                    <input
                        type="text"
                        placeholder="Search vitals..."
                        value={historySearch}
                        onChange={(event) => onSearch(event.target.value)}
                        className="pl-10 pr-4 py-2 rounded-full border border-gray-200 text-sm focus:outline-none focus:ring-2 focus:ring-brand-medium"
                    />
                </div>
                <div className="flex gap-2 text-xs text-gray-500">
                    <div>
                        <label className="block text-[10px] font-semibold uppercase tracking-wide mb-1">Start</label>
                        <input
                            type="date"
                            className="rounded-lg border border-gray-200 px-3 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-brand-medium"
                            value={historyRange.start}
                            onChange={(event) => onHistoryRangeChange({ ...historyRange, start: event.target.value })}
                        />
                    </div>
                    <div>
                        <label className="block text-[10px] font-semibold uppercase tracking-wide mb-1">End</label>
                        <input
                            type="date"
                            className="rounded-lg border border-gray-200 px-3 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-brand-medium"
                            value={historyRange.end}
                            onChange={(event) => onHistoryRangeChange({ ...historyRange, end: event.target.value })}
                        />
                    </div>
                </div>
                <Button variant="outline" className="flex items-center gap-2" onClick={onPrint}>
                    <Printer className="w-4 h-4" />
                    Print
                </Button>
                <Button variant="outline" className="flex items-center gap-2" onClick={onExport}>
                    <Download className="w-4 h-4" />
                    Export
                </Button>
            </div>
        </div>

        <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-100">
                <thead className="bg-gray-50">
                    <tr>
                        <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Timestamp</th>
                        <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">BP</th>
                        <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">HR</th>
                        <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Temp</th>
                        <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">RR</th>
                        <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">SpO2</th>
                        <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Pain</th>
                        <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Recorded By</th>
                    </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-100">
                    {filteredVitalsLog.length > 0 ? (
                        filteredVitalsLog.map((entry) => {
                            const bpParsed = parseBpString(entry.bp);
                            const bpStatus = classifyBp(bpParsed.systolic, bpParsed.diastolic);
                            const hrStatus = classifyValue('heartRate', entry.hr);
                            const tempStatus = classifyValue('temperature', entry.temp);
                            const rrStatus = classifyValue('respiratoryRate', entry.rr);
                            const spo2Status = classifyValue('oxygenSaturation', entry.spo2);
                            const painStatus = classifyValue('painLevel', entry.pain);
                            const badgeClass = (status) => `${getStatusClasses(status).bg} ${getStatusClasses(status).text} px-3 py-1 rounded-full text-xs font-semibold inline-flex items-center gap-1`;

                            return (
                                <tr key={entry.timestamp} className="hover:bg-gray-50/70 transition-colors">
                                    <td className="px-4 py-3 text-sm text-gray-700 whitespace-nowrap">{formatTimestamp(entry.timestamp)}</td>
                                    <td className="px-4 py-3 text-sm">
                                        <span className={badgeClass(bpStatus)}>{entry.bp}</span>
                                    </td>
                                    <td className="px-4 py-3 text-sm">
                                        <span className={badgeClass(hrStatus)}>{entry.hr} bpm</span>
                                    </td>
                                    <td className="px-4 py-3 text-sm">
                                        <span className={badgeClass(tempStatus)}>{entry.temp} °F</span>
                                    </td>
                                    <td className="px-4 py-3 text-sm">
                                        <span className={badgeClass(rrStatus)}>{entry.rr}</span>
                                    </td>
                                    <td className="px-4 py-3 text-sm">
                                        <span className={badgeClass(spo2Status)}>{entry.spo2}%</span>
                                    </td>
                                    <td className="px-4 py-3 text-sm">
                                        <span className={badgeClass(painStatus)}>
                                            {entry.pain}
                                            {painStatus !== 'normal' && <AlertTriangle className="w-3 h-3" aria-hidden="true" />}
                                        </span>
                                    </td>
                                    <td className="px-4 py-3 text-sm text-gray-600 whitespace-nowrap">{entry.recordedBy || defaultRecorder}</td>
                                </tr>
                            );
                        })
                    ) : (
                        <tr>
                            <td colSpan={8} className="px-4 py-10 text-center text-sm text-gray-500">
                                No vitals found for the selected filters.
                            </td>
                        </tr>
                    )}
                </tbody>
            </table>
        </div>

        <p className="text-xs text-gray-400">TODO: Persist log entries and filters via backend APIs when available.</p>
    </Card>
);

export default VitalsLogTable;
