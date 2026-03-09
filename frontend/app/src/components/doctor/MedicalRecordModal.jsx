import React, { useState } from 'react';
import Modal from '../common/Modal';
import Input from '../common/Input';
import Button from '../common/Button';
import api from '../../services/api';

const MedicalRecordModal = ({ isOpen, onClose, patientId, onAdd }) => {
    const [record, setRecord] = useState({
        diagnosis: '',
        symptoms: '',
        treatmentProvided: ''
    });
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [error, setError] = useState(null);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError(null);
        setIsSubmitting(true);

        try {
            const payload = {
                patientId: patientId,
                diagnosis: record.diagnosis,
                symptoms: record.symptoms,
                treatmentProvided: record.treatmentProvided
            };

            await api.medicalRecords.create(payload);
            onAdd(payload);
            resetForm();
            onClose();
        } catch (err) {
            console.error('Failed to add medical record:', err);
            setError(err.message || 'Failed to save medical record. Please try again.');
        } finally {
            setIsSubmitting(false);
        }
    };

    const resetForm = () => {
        setRecord({
            diagnosis: '',
            symptoms: '',
            treatmentProvided: ''
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
            title="Create Medical Record"
        >
            <form onSubmit={handleSubmit} className="space-y-4">
                {error && (
                    <div className="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded text-sm text-red-700 dark:text-red-400">
                        {error}
                    </div>
                )}

                <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-1">
                        Diagnosis
                    </label>
                    <Input
                        value={record.diagnosis}
                        onChange={e => setRecord({ ...record, diagnosis: e.target.value })}
                        placeholder="e.g. Hypertension, Type 2 Diabetes"
                        required
                    />
                </div>

                <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-1">
                        Symptoms
                    </label>
                    <textarea
                        className="w-full px-4 py-2 border border-gray-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all resize-none h-20 bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100 placeholder-gray-400 dark:placeholder-slate-500"
                        value={record.symptoms}
                        onChange={e => setRecord({ ...record, symptoms: e.target.value })}
                        placeholder="Patient reported symptoms, ongoing complaints..."
                        required
                    />
                </div>

                <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-1">
                        Treatment Provided
                    </label>
                    <textarea
                        className="w-full px-4 py-2 border border-gray-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all resize-none h-20 bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100 placeholder-gray-400 dark:placeholder-slate-500"
                        value={record.treatmentProvided}
                        onChange={e => setRecord({ ...record, treatmentProvided: e.target.value })}
                        placeholder="Medications, procedures, therapy, lifestyle modifications..."
                        required
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
                        {isSubmitting ? 'Saving...' : 'Create Record'}
                    </Button>
                </div>
            </form>
        </Modal>
    );
};

export default MedicalRecordModal;
