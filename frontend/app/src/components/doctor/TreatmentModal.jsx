import React, { useState } from 'react';
import Modal from '../common/Modal';
import Input from '../common/Input';
import Button from '../common/Button';

const TreatmentModal = ({ isOpen, onClose, onAdd }) => {
    const [treatment, setTreatment] = useState({
        name: '',
        frequency: '',
        notes: '',
        startDate: new Date().toISOString().split('T')[0]
    });

    const handleSubmit = (e) => {
        e.preventDefault();
        onAdd(treatment);
        setTreatment({ name: '', frequency: '', notes: '', startDate: new Date().toISOString().split('T')[0] });
        onClose();
    };

    return (
        <Modal
            isOpen={isOpen}
            onClose={onClose}
            title="Add New Treatment Plan"
        >
            <form onSubmit={handleSubmit} className="space-y-4">
                <Input
                    label="Treatment / Therapy Name"
                    value={treatment.name}
                    onChange={e => setTreatment({ ...treatment, name: e.target.value })}
                    placeholder="e.g. Physical Therapy"
                    required
                />

                <div className="grid grid-cols-2 gap-4">
                    <Input
                        label="Frequency"
                        value={treatment.frequency}
                        onChange={e => setTreatment({ ...treatment, frequency: e.target.value })}
                        placeholder="e.g. 2x Weekly"
                        required
                    />
                    <Input
                        label="Start Date"
                        type="date"
                        value={treatment.startDate}
                        onChange={e => setTreatment({ ...treatment, startDate: e.target.value })}
                        required
                    />
                </div>

                <div className="space-y-1">
                    <label className="block text-sm font-medium text-gray-700">Clinical Notes</label>
                    <textarea
                        className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all resize-none h-24"
                        value={treatment.notes}
                        onChange={e => setTreatment({ ...treatment, notes: e.target.value })}
                        placeholder="Specific instructions, goals, or precautions..."
                    />
                </div>

                <div className="pt-4 flex justify-end space-x-3 border-t border-gray-100">
                    <Button type="button" variant="secondary" onClick={onClose}>Cancel</Button>
                    <Button type="submit">Add Treatment</Button>
                </div>
            </form>
        </Modal>
    );
};

export default TreatmentModal;
