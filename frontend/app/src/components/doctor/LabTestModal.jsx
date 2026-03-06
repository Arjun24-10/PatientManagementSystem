import React, { useState } from 'react';
import Modal from '../common/Modal';
import Input from '../common/Input';
import Button from '../common/Button';
import api from '../../services/api';

const LabTestModal = ({ isOpen, onClose, patientId, onAdd }) => {
    const [labTest, setLabTest] = useState({
        testName: '',
        testCategory: '',
        resultValue: '',
        unit: '',
        referenceRange: '',
        remarks: ''
    });
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [error, setError] = useState(null);

    const testCategories = [
        'Complete Blood Count',
        'Metabolic Panel',
        'Lipid Panel',
        'Thyroid Function',
        'Liver Function',
        'Kidney Function',
        'Urinalysis',
        'Blood Glucose',
        'Other'
    ];

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError(null);
        setIsSubmitting(true);

        try {
            const payload = {
                patientId: patientId,
                testName: labTest.testName,
                testCategory: labTest.testCategory,
                resultValue: labTest.resultValue,
                unit: labTest.unit,
                referenceRange: labTest.referenceRange,
                remarks: labTest.remarks,
                orderedAt: new Date().toISOString(),
                status: 'COMPLETED'
            };

            await api.labResults.create(payload);
            onAdd(payload);
            resetForm();
            onClose();
        } catch (err) {
            console.error('Failed to add lab test:', err);
            setError(err.message || 'Failed to save lab test. Please try again.');
        } finally {
            setIsSubmitting(false);
        }
    };

    const resetForm = () => {
        setLabTest({
            testName: '',
            testCategory: '',
            resultValue: '',
            unit: '',
            referenceRange: '',
            remarks: ''
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
            title="Add Lab Test Result"
        >
            <form onSubmit={handleSubmit} className="space-y-4">
                {error && (
                    <div className="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded text-sm text-red-700 dark:text-red-400">
                        {error}
                    </div>
                )}

                <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-1">
                        Test Name
                    </label>
                    <Input
                        value={labTest.testName}
                        onChange={e => setLabTest({ ...labTest, testName: e.target.value })}
                        placeholder="e.g. White Blood Cell Count"
                        required
                    />
                </div>

                <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-1">
                        Test Category
                    </label>
                    <select
                        value={labTest.testCategory}
                        onChange={e => setLabTest({ ...labTest, testCategory: e.target.value })}
                        className="w-full px-4 py-2 border border-gray-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100"
                        required
                    >
                        <option value="">Select category</option>
                        {testCategories.map(cat => (
                            <option key={cat} value={cat}>{cat}</option>
                        ))}
                    </select>
                </div>

                <div className="grid grid-cols-2 gap-4">
                    <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-1">
                            Result Value
                        </label>
                        <Input
                            value={labTest.resultValue}
                            onChange={e => setLabTest({ ...labTest, resultValue: e.target.value })}
                            placeholder="e.g. 7.5"
                            required
                        />
                    </div>
                    <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-1">
                            Unit
                        </label>
                        <Input
                            value={labTest.unit}
                            onChange={e => setLabTest({ ...labTest, unit: e.target.value })}
                            placeholder="e.g. K/µL"
                            required
                        />
                    </div>
                </div>

                <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-1">
                        Reference Range
                    </label>
                    <Input
                        value={labTest.referenceRange}
                        onChange={e => setLabTest({ ...labTest, referenceRange: e.target.value })}
                        placeholder="e.g. 4.5-11.0"
                        required
                    />
                </div>

                <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-1">
                        Remarks
                    </label>
                    <textarea
                        className="w-full px-4 py-2 border border-gray-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all resize-none h-20 bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100 placeholder-gray-400 dark:placeholder-slate-500"
                        value={labTest.remarks}
                        onChange={e => setLabTest({ ...labTest, remarks: e.target.value })}
                        placeholder="Any clinical observations or notes..."
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
                        {isSubmitting ? 'Saving...' : 'Add Lab Test'}
                    </Button>
                </div>
            </form>
        </Modal>
    );
};

export default LabTestModal;
