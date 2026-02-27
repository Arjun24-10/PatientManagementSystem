import React from 'react';
import { AlertTriangle, AlertCircle, Activity } from 'lucide-react';
import Button from '../../../components/common/Button';

const VitalsEntryForm = ({
    form,
    formStatuses,
    getStatusClasses,
    getInputStatusClasses,
    normalText,
    temperatureUnit,
    temperatureRoute,
    onUnitToggle,
    onRouteSelect,
    onFieldChange,
    selectedPainFace,
    notes,
    onNotesChange,
    formError,
    onSave,
    onNotify,
    onCancel,
    lastTimestamp,
    recordedBy,
    unit,
}) => {
    const PainIcon = selectedPainFace?.icon;

    const handleSubmit = (event) => {
        event.preventDefault();
        onSave();
    };

    return (
        <form className="space-y-3" onSubmit={handleSubmit}>
            <div className="flex flex-col md:flex-row md:items-start md:justify-between gap-2">
                <div>
                    <p className="text-[10px] font-semibold uppercase tracking-wide text-brand-medium">Vitals Entry</p>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-slate-100 mt-0.5">Shift assessment</h3>
                    <p className="text-xs text-gray-500 dark:text-slate-400">Last entry {lastTimestamp}</p>
                </div>
                <div className="text-xs text-gray-500 dark:text-slate-400">
                    <p>Recorded by {recordedBy}</p>
                    <p className="mt-0.5">Unit: {unit}</p>
                </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div className={`rounded-lg border ${getStatusClasses(formStatuses.bp).border} bg-white dark:bg-slate-700 shadow-sm p-3 space-y-2`}>
                    <div className="flex items-start justify-between gap-2">
                        <div>
                            <p className="text-sm font-semibold text-gray-700 dark:text-slate-200">Blood Pressure</p>
                            <p className="text-xs text-gray-400 dark:text-slate-500">mmHg</p>
                        </div>
                        {formStatuses.bp !== 'normal' && (
                            <span className={`inline-flex items-center gap-1 text-xs font-semibold ${getStatusClasses(formStatuses.bp).text}`}>
                                <AlertTriangle className="w-3.5 h-3.5" />
                                {formStatuses.bp === 'critical' ? 'Critical' : 'Abnormal'}
                            </span>
                        )}
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                        <div>
                            <label className="text-xs font-medium text-gray-500 dark:text-slate-400 mb-0.5 block">Systolic</label>
                            <input
                                type="number"
                                min="40"
                                max="250"
                                className={`w-full h-12 rounded-lg px-3 text-xl font-semibold text-gray-900 dark:text-slate-100 bg-white dark:bg-slate-600 focus:outline-none focus:ring-2 ${getInputStatusClasses(formStatuses.bp)}`}
                                value={form.systolic}
                                onChange={(event) => onFieldChange('systolic', event.target.value)}
                            />
                        </div>
                        <div>
                            <label className="text-xs font-medium text-gray-500 dark:text-slate-400 mb-0.5 block">Diastolic</label>
                            <input
                                type="number"
                                min="20"
                                max="200"
                                className={`w-full h-12 rounded-lg px-3 text-xl font-semibold text-gray-900 dark:text-slate-100 bg-white dark:bg-slate-600 focus:outline-none focus:ring-2 ${getInputStatusClasses(formStatuses.bp)}`}
                                value={form.diastolic}
                                onChange={(event) => onFieldChange('diastolic', event.target.value)}
                            />
                        </div>
                    </div>
                    <p className="text-xs text-gray-500 dark:text-slate-400">{normalText.bp}</p>
                </div>

                <div className={`rounded-lg border ${getStatusClasses(formStatuses.heartRate).border} bg-white dark:bg-slate-700 shadow-sm p-3 space-y-2`}>
                    <div className="flex items-start justify-between gap-2">
                        <div>
                            <p className="text-sm font-semibold text-gray-700 dark:text-slate-200">Heart Rate</p>
                            <p className="text-xs text-gray-400 dark:text-slate-500">beats per minute</p>
                        </div>
                        {formStatuses.heartRate !== 'normal' && (
                            <span className={`inline-flex items-center gap-1 text-xs font-semibold ${getStatusClasses(formStatuses.heartRate).text}`}>
                                <Activity className="w-3.5 h-3.5" />
                                {formStatuses.heartRate === 'critical' ? 'Critical' : 'Outside range'}
                            </span>
                        )}
                    </div>
                    <input
                        type="number"
                        min="30"
                        max="220"
                        className={`w-full h-12 rounded-lg px-3 text-xl font-semibold text-gray-900 dark:text-slate-100 bg-white dark:bg-slate-600 focus:outline-none focus:ring-2 ${getInputStatusClasses(formStatuses.heartRate)}`}
                        value={form.heartRate}
                        onChange={(event) => onFieldChange('heartRate', event.target.value)}
                    />
                    <p className="text-xs text-gray-500 dark:text-slate-400">{normalText.heartRate}</p>
                </div>

                <div className={`rounded-lg border ${getStatusClasses(formStatuses.temperature).border} bg-white dark:bg-slate-700 shadow-sm p-3 space-y-2`}>
                    <div className="flex items-start justify-between gap-2">
                        <div>
                            <p className="text-sm font-semibold text-gray-700 dark:text-slate-200">Temperature</p>
                            <p className="text-xs text-gray-400 dark:text-slate-500">Route: {temperatureRoute.charAt(0).toUpperCase() + temperatureRoute.slice(1)}</p>
                        </div>
                        <div className="inline-flex rounded-full border border-gray-200 dark:border-slate-600 overflow-hidden text-xs font-semibold">
                            <button
                                type="button"
                                className={`px-3 py-1 ${temperatureUnit === 'F' ? 'bg-brand-medium text-white' : 'text-gray-600 dark:text-slate-300 bg-white dark:bg-slate-600'}`}
                                onClick={() => onUnitToggle('F')}
                            >
                                °F
                            </button>
                            <button
                                type="button"
                                className={`px-3 py-1 ${temperatureUnit === 'C' ? 'bg-brand-medium text-white' : 'text-gray-600 dark:text-slate-300 bg-white dark:bg-slate-600'}`}
                                onClick={() => onUnitToggle('C')}
                            >
                                °C
                            </button>
                        </div>
                    </div>
                    <div className="grid grid-cols-1 gap-2">
                        <input
                            type="number"
                            className={`w-full h-12 rounded-lg px-3 text-xl font-semibold text-gray-900 dark:text-slate-100 bg-white dark:bg-slate-600 focus:outline-none focus:ring-2 ${getInputStatusClasses(formStatuses.temperature)}`}
                            value={form.temperature}
                            onChange={(event) => onFieldChange('temperature', event.target.value)}
                            step="0.1"
                        />
                        <div className="flex flex-wrap gap-1.5">
                            {['oral', 'axillary', 'rectal', 'tympanic'].map((route) => (
                                <button
                                    key={route}
                                    type="button"
                                    className={`px-3 py-1 rounded-full text-xs font-semibold border transition ${temperatureRoute === route ? 'bg-brand-medium text-white border-brand-medium' : 'border-gray-200 dark:border-slate-600 text-gray-600 dark:text-slate-300 hover:bg-gray-50 dark:hover:bg-slate-600'}`}
                                    onClick={() => onRouteSelect(route)}
                                >
                                    {route.charAt(0).toUpperCase() + route.slice(1)}
                                </button>
                            ))}
                        </div>
                    </div>
                    <p className="text-xs text-gray-500 dark:text-slate-400">{normalText.temperature}</p>
                </div>

                <div className={`rounded-lg border ${getStatusClasses(formStatuses.respiratoryRate).border} bg-white dark:bg-slate-700 shadow-sm p-3 space-y-2`}>
                    <div className="flex items-start justify-between gap-2">
                        <div>
                            <p className="text-sm font-semibold text-gray-700 dark:text-slate-200">Respiratory Rate</p>
                            <p className="text-xs text-gray-400 dark:text-slate-500">breaths per minute</p>
                        </div>
                        {formStatuses.respiratoryRate !== 'normal' && (
                            <span className={`inline-flex items-center gap-1 text-xs font-semibold ${getStatusClasses(formStatuses.respiratoryRate).text}`}>
                                <AlertCircle className="w-3.5 h-3.5" />
                                {formStatuses.respiratoryRate === 'critical' ? 'Critical' : 'Review'}
                            </span>
                        )}
                    </div>
                    <input
                        type="number"
                        min="6"
                        max="40"
                        className={`w-full h-12 rounded-lg px-3 text-xl font-semibold text-gray-900 dark:text-slate-100 bg-white dark:bg-slate-600 focus:outline-none focus:ring-2 ${getInputStatusClasses(formStatuses.respiratoryRate)}`}
                        value={form.respiratoryRate}
                        onChange={(event) => onFieldChange('respiratoryRate', event.target.value)}
                    />
                    <p className="text-xs text-gray-500 dark:text-slate-400">{normalText.respiratoryRate}</p>
                </div>

                <div className={`rounded-lg border ${getStatusClasses(formStatuses.oxygenSaturation).border} bg-white dark:bg-slate-700 shadow-sm p-3 space-y-2`}>
                    <div className="flex items-start justify-between gap-2">
                        <div>
                            <p className="text-sm font-semibold text-gray-700 dark:text-slate-200">Oxygen Saturation</p>
                                <p className="text-xs text-gray-400 dark:text-slate-500">SpO2 %</p>
                        </div>
                        {formStatuses.oxygenSaturation !== 'normal' && (
                            <span className={`inline-flex items-center gap-1 text-xs font-semibold ${getStatusClasses(formStatuses.oxygenSaturation).text}`}>
                                <AlertTriangle className="w-3.5 h-3.5" />
                                {formStatuses.oxygenSaturation === 'critical' ? 'Critical' : 'Monitor'}
                            </span>
                        )}
                    </div>
                    <input
                        type="number"
                        min="50"
                        max="100"
                        className={`w-full h-12 rounded-lg px-3 text-xl font-semibold text-gray-900 dark:text-slate-100 bg-white dark:bg-slate-600 focus:outline-none focus:ring-2 ${getInputStatusClasses(formStatuses.oxygenSaturation)}`}
                        value={form.oxygenSaturation}
                        onChange={(event) => onFieldChange('oxygenSaturation', event.target.value)}
                    />
                    <p className="text-xs text-gray-500 dark:text-slate-400">{normalText.oxygenSaturation}</p>
                </div>

                <div className={`rounded-lg border ${getStatusClasses(formStatuses.painLevel).border} bg-white dark:bg-slate-700 shadow-sm p-3 space-y-2`}>
                    <div className="flex items-start justify-between gap-2">
                        <div>
                            <p className="text-sm font-semibold text-gray-700 dark:text-slate-200">Pain Level</p>
                                <p className="text-xs text-gray-400 dark:text-slate-500">0 (no pain) - 10 (worst)</p>
                        </div>
                        <span className={`inline-flex items-center gap-1 text-xs font-semibold ${getStatusClasses(formStatuses.painLevel).text}`}>
                            Pain {form.painLevel}
                        </span>
                    </div>
                    <div className="space-y-2">
                        <input
                            type="range"
                            min="0"
                            max="10"
                            step="1"
                            value={form.painLevel}
                            onChange={(event) => onFieldChange('painLevel', Number(event.target.value))}
                            className="w-full accent-brand-medium"
                        />
                        <div className="flex justify-between text-[10px] text-gray-400 dark:text-slate-500 font-semibold">
                            <span>0</span>
                            <span>5</span>
                            <span>10</span>
                        </div>
                        <div className="flex items-center gap-1.5 text-xs text-gray-600 dark:text-slate-400">
                            {PainIcon && <PainIcon className="w-4 h-4 text-brand-medium" aria-hidden="true" />}
                            <span>{selectedPainFace?.label}</span>
                        </div>
                    </div>
                    <p className="text-xs text-gray-500 dark:text-slate-400">{normalText.painLevel}</p>
                </div>
            </div>

            {formError && (
                <div className="rounded-lg border border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400 text-xs px-3 py-2">{formError}</div>
            )}

            <div>
                <label htmlFor="vitals-notes" className="text-xs font-semibold text-gray-700 dark:text-slate-300 block mb-1">Observations &amp; Notes</label>
                <textarea
                    id="vitals-notes"
                    rows={2}
                    className="w-full rounded-lg border border-gray-200 dark:border-slate-600 p-2.5 text-xs focus:outline-none focus:ring-2 focus:ring-brand-medium bg-white dark:bg-slate-700 text-gray-900 dark:text-slate-100 dark:placeholder-slate-400"
                    placeholder="Enter relevant observations, patient feedback, or interventions..."
                    value={notes}
                    onChange={(event) => onNotesChange(event.target.value)}
                />
                <p className="text-xs text-gray-400 dark:text-slate-500 mt-1">Notes are sent with notifications and saved to the handover log. TODO: Persist via saveHandoverNotes API.</p>
            </div>

            <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-2">
                <p className="text-[10px] text-gray-400 dark:text-slate-500">Entries auto-timestamped at submission · Refreshes every 2 minutes</p>
                <div className="flex flex-wrap gap-2">
                    <Button type="submit">Save Vitals</Button>
                    <Button type="button" variant="danger" onClick={onNotify}>
                        Save &amp; Notify MD
                    </Button>
                    <Button type="button" variant="outline" onClick={onCancel}>
                        Cancel
                    </Button>
                </div>
            </div>
        </form>
    );
};

export default VitalsEntryForm;
