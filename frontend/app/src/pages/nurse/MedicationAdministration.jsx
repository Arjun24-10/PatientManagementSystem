import React, { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Pill, Check, Clock, AlertCircle, ArrowLeft } from 'lucide-react';

import Card from '../../components/common/Card';
import Button from '../../components/common/Button';
import Badge from '../../components/common/Badge';
import Modal from '../../components/common/Modal';
import { mockNursePatients } from '../../mocks/nursePatients';

const MedicationAdministration = () => {
    const { id } = useParams();
    const navigate = useNavigate();
    // eslint-disable-next-line
    const patient = mockNursePatients.find(p => p.id === id) || mockNursePatients[0];

    const [medications, setMedications] = useState([
        { id: 1, name: 'Amoxicillin', dosage: '500mg', route: 'Oral', scheduledTime: '14:00', status: 'due' },
        { id: 2, name: 'Paracetamol', dosage: '1000mg', route: 'Oral', scheduledTime: 'PRN', status: 'ready' },
        { id: 3, name: 'Insulin Glargine', dosage: '10 units', route: 'SubQ', scheduledTime: '20:00', status: 'pending' }
    ]);

    const [selectedMed, setSelectedMed] = useState(null);
    const [isConfirmModalOpen, setIsConfirmModalOpen] = useState(false);

    const handleAdministerClick = (med) => {
        setSelectedMed(med);
        setIsConfirmModalOpen(true);
    };

    const confirmAdministration = () => {
        if (!selectedMed) return;

        const timestamp = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

        setMedications(prev => prev.map(m =>
            m.id === selectedMed.id
                ? { ...m, status: 'administered', administeredTime: timestamp }
                : m
        ));

        setIsConfirmModalOpen(false);
        setSelectedMed(null);
    };

    const getStatusContent = (med) => {
        if (med.status === 'administered') {
            return (
                <div className="flex flex-col items-end text-green-600">
                    <span className="flex items-center text-sm font-medium"><Check className="w-4 h-4 mr-1" /> Administered</span>
                    <span className="text-xs text-gray-500">at {med.administeredTime}</span>
                </div>
            );
        }
        return (
            <Button
                size="sm"
                variant={med.status === 'due' ? 'primary' : 'outline'}
                onClick={() => handleAdministerClick(med)}
            >
                Administer
            </Button>
        );
    };

    return (
        <div className="space-y-6 max-w-4xl mx-auto">
            <Button variant="ghost" onClick={() => navigate(`/dashboard/nurse/patient/${id}`)} className="pl-0 hover:pl-2 transition-all">
                <ArrowLeft className="w-4 h-4 mr-2" /> Back to Patient
            </Button>

            <div>
                <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Medication Administration</h1>
                <p className="text-gray-500">Verify 5 Rights: Patient, Drug, Dose, Route, Time</p>
            </div>

            <div className="space-y-4">
                {medications.map((med) => (
                    <Card key={med.id} className="p-4 flex flex-col sm:flex-row justify-between items-center gap-4">
                        <div className="flex items-start gap-4 w-full">
                            <div className={`p-3 rounded-full ${med.status === 'administered' ? 'bg-green-100 text-green-600' : 'bg-blue-100 text-blue-600'}`}>
                                <Pill className="w-6 h-6" />
                            </div>
                            <div>
                                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">{med.name}</h3>
                                <div className="text-sm text-gray-500 dark:text-slate-400 space-x-4">
                                    <span><span className="font-medium">Dose:</span> {med.dosage}</span>
                                    <span><span className="font-medium">Route:</span> {med.route}</span>
                                </div>
                                <div className="mt-2 flex gap-2">
                                    <Badge type="gray" variant="soft"><Clock className="w-3 h-3 mr-1 inline" /> {med.scheduledTime}</Badge>
                                </div>
                            </div>
                        </div>
                        <div className="flex-shrink-0">
                            {getStatusContent(med)}
                        </div>
                    </Card>
                ))}
            </div>

            <Modal
                isOpen={isConfirmModalOpen}
                onClose={() => setIsConfirmModalOpen(false)}
                title="Confirm Medication Administration"
            >
                {selectedMed && (
                    <div className="space-y-4">
                        <div className="bg-yellow-50 dark:bg-yellow-900/10 p-4 rounded-md border border-yellow-100 dark:border-yellow-900/20 flex gap-3">
                            <AlertCircle className="w-5 h-5 text-yellow-600" />
                            <div className="text-sm text-yellow-800 dark:text-yellow-200">
                                Verify patient identity and allergies before proceeding.
                            </div>
                        </div>

                        <div className="space-y-2 py-4">
                            <div className="grid grid-cols-2 text-sm gap-2">
                                <span className="text-gray-500">Medication:</span>
                                <span className="font-semibold">{selectedMed.name}</span>

                                <span className="text-gray-500">Dosage:</span>
                                <span className="font-semibold">{selectedMed.dosage}</span>

                                <span className="text-gray-500">Route:</span>
                                <span className="font-semibold">{selectedMed.route}</span>
                            </div>
                        </div>

                        <div className="flex justify-end gap-3">
                            <Button variant="ghost" onClick={() => setIsConfirmModalOpen(false)}>Cancel</Button>
                            <Button variant="primary" onClick={confirmAdministration}>Confirm & Sign</Button>
                        </div>
                    </div>
                )}
            </Modal>
        </div>
    );
};

export default MedicationAdministration;
