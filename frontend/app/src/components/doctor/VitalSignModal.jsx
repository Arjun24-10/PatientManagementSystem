import React, { useState } from 'react';
import Modal from '../common/Modal';
import Input from '../common/Input';
import Button from '../common/Button';
import api from '../../services/api';

const VitalSignModal = ({ isOpen, onClose, patientId, onAdd }) => {
    const [vitals, setVitals] = useState({
        bloodPressureSystolic: '',
        bloodPressureDiastolic: '',
        heartRate: '',
        temperature: '',
        respiratoryRate: '',
        oxygenSaturation: '',
        notes: ''
    });
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [error, setError] = useState(null);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError(null);
        setIsSubmitting(true);

        try {
            // Combine systolic and diastolic into "120/80" format for backend
            const bloodPressure = `${vitals.bloodPressureSystolic}/${vitals.bloodPressureDiastolic}`;
            
            const payload = {
                patientId: patientId,
                bloodPressure: bloodPressure,
                heartRate: parseInt(vitals.heartRate),
                temperature: parseFloat(vitals.temperature),
                respiratoryRate: parseInt(vitals.respiratoryRate),
                oxygenSaturation: parseInt(vitals.oxygenSaturation),
                weight: null,
                height: null
            };

            await api.vitalSigns.create(payload);
            onAdd(payload);
            resetForm();
            onClose();
        } catch (err) {
            console.error('Failed to add vital sign:', err);
            setError(err.message || 'Failed to save vital signs. Please try again.');
        } finally {
            setIsSubmitting(false);
        }
    };

    const resetForm = () => {
        setVitals({
            bloodPressureSystolic: '',
            bloodPressureDiastolic: '',
            heartRate: '',
            temperature: '',
            respiratoryRate: '',
            oxygenSaturation: '',
            notes: ''
        });
    };

    return (
        <Modal
            isOpen={isOpen}
            onClose={() => {
                onClose();
                resetForm();
                setError(null);
            }}
            title="Record Vital Signs"
        >
            <form onSubmit={handleSubmit} className="space-y-4">
                {error && (
                    <div className="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded text-sm text-red-700 dark:text-red-400">
                        {error}
                    </div>
                )}

                <div className="grid grid-cols-2 gap-4">
                    <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-1">
                            Blood Pressure (Systolic)
                        </label>
                        <Input
                            type="number"
                            value={vitals.bloodPressureSystolic}
                            onChange={e => setVitals({ ...vitals, bloodPressureSystolic: e.target.value })}
                            placeholder="e.g. 120"
                            required
                        />
                    </div>
                    <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-1">
                            Blood Pressure (Diastolic)
                        </label>
                        <Input
                            type="number"
                            value={vitals.bloodPressureDiastolic}
                            onChange={e => setVitals({ ...vitals, bloodPressureDiastolic: e.target.value })}
                            placeholder="e.g. 80"
                            required
                        />
                    </div>
                </div>

                <div className="grid grid-cols-2 gap-4">
                    <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-1">
                            Heart Rate (bpm)
                        </label>
                        <Input
                            type="number"
                            value={vitals.heartRate}
                            onChange={e => setVitals({ ...vitals, heartRate: e.target.value })}
                            placeholder="e.g. 72"
                            required
                        />
                    </div>
                    <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-1">
                            Temperature (°C)
                        </label>
                        <Input
                            type="number"
                            step="0.1"
                            value={vitals.temperature}
                            onChange={e => setVitals({ ...vitals, temperature: e.target.value })}
                            placeholder="e.g. 37.0"
                            required
                        />
                    </div>
                </div>

                <div className="grid grid-cols-2 gap-4">
                    <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-1">
                            Respiratory Rate (breaths/min)
                        </label>
                        <Input
                            type="number"
                            value={vitals.respiratoryRate}
                            onChange={e => setVitals({ ...vitals, respiratoryRate: e.target.value })}
                            placeholder="e.g. 16"
                            required
                        />
                    </div>
                    <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-1">
                            Oxygen Saturation (%)
                        </label>
                        <Input
                            type="number"
                            step="0.1"
                            value={vitals.oxygenSaturation}
                            onChange={e => setVitals({ ...vitals, oxygenSaturation: e.target.value })}
                            placeholder="e.g. 98.5"
                            required
                        />
                    </div>
                </div>

                <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-1">
                        Clinical Notes
                    </label>
                    <textarea
                        className="w-full px-4 py-2 border border-gray-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all resize-none h-20 bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100 placeholder-gray-400 dark:placeholder-slate-500"
                        value={vitals.notes}
                        onChange={e => setVitals({ ...vitals, notes: e.target.value })}
                        placeholder="Any observations or concerns..."
                    />
                </div>

                <div className="pt-4 flex justify-end space-x-3 border-t border-gray-100 dark:border-slate-700">
                    <Button type="button" variant="secondary" onClick={() => {
                        onClose();
                        resetForm();
                        setError(null);
                    }} disabled={isSubmitting}>
                        Cancel
                    </Button>
                    <Button type="submit" disabled={isSubmitting}>
                        {isSubmitting ? 'Saving...' : 'Save Vital Signs'}
                    </Button>
                </div>
            </form>
        </Modal>
    );
};

export default VitalSignModal;
