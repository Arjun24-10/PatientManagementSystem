import React, { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
    ArrowLeft, Clock, Activity, Pill, Plus
} from 'lucide-react';

import Card from '../../components/common/Card';
import Button from '../../components/common/Button';
import IconButton from '../../components/common/IconButton';
import Badge from '../../components/common/Badge';
import Modal from '../../components/common/Modal';
import Input from '../../components/common/Input';

import TreatmentModal from '../../components/doctor/TreatmentModal';
import MedicalHistoryList from '../../components/doctor/MedicalHistoryList';
import LabResultsList from '../../components/doctor/LabResultsList';
import VitalSignModal from '../../components/doctor/VitalSignModal';
import LabTestModal from '../../components/doctor/LabTestModal';
import MedicalRecordModal from '../../components/doctor/MedicalRecordModal';
import PrescriptionModal from '../../components/doctor/PrescriptionModal';

import api from '../../services/api';

const PatientDetail = () => {
    const { id } = useParams();
    const navigate = useNavigate();

    // State
    const [patient, setPatient] = useState(null);
    const [activeTab, setActiveTab] = useState('overview');

    // Data States
    const [prescriptions, setPrescriptions] = useState([]);
    const [treatments, setTreatments] = useState([]);
    const [vitals, setVitals] = useState([]);
    const [medicalHistory, setMedicalHistory] = useState([]);
    const [labs, setLabs] = useState([]);
    const [isLoading, setIsLoading] = useState(true);
    const [isRxModalOpen, setIsRxModalOpen] = useState(false);
    const [isTreatmentModalOpen, setIsTreatmentModalOpen] = useState(false);
    const [isVitalsModalOpen, setIsVitalsModalOpen] = useState(false);
    const [isLabTestModalOpen, setIsLabTestModalOpen] = useState(false);
    const [isMedicalRecordModalOpen, setIsMedicalRecordModalOpen] = useState(false);
    const [isPrescriptionModalOpen, setIsPrescriptionModalOpen] = useState(false);
    const [newRx, setNewRx] = useState({ name: '', dosage: '', frequency: '', duration: '', instructions: '' });

    // Fetch Data
    React.useEffect(() => {
        const fetchData = async () => {
            setIsLoading(true);
            try {
                // 1. Patient Details
                try {
                    const patientData = await api.patients.getById(id);
                    if (patientData && patientData.id) {
                        setPatient(patientData);
                    }
                } catch (e) {
                    console.error('Failed to fetch patient from API', e);
                    // Handle both old and new error messages  
                    if (e.message === 'DOCTOR_ENDPOINT_NOT_IMPLEMENTED' || 
                        e.message.includes('not yet available for doctors')) {
                        console.info('Using mock patient data for patient detail page');
                        setPatient({
                            id: id,
                            name: 'John Doe',
                            firstName: 'John',
                            lastName: 'Doe',
                            email: 'john.doe@email.com',
                            phone: '(555) 123-4567',
                            age: 45,
                            gender: 'Male',
                            condition: 'Hypertension',
                            status: 'Stable',
                            avatar: 'JD',
                            address: '123 Main St, City, State 12345'
                        });
                    }
                }

                // 2. Prescriptions
                try {
                    const rxData = await api.prescriptions.getByPatient(id);
                    if (Array.isArray(rxData)) setPrescriptions(rxData);
                } catch (e) { 
                    console.error('Failed to fetch prescriptions', e);
                    if (e.message === 'DOCTOR_ENDPOINT_NOT_IMPLEMENTED' || 
                        e.message.includes('not yet available for doctors')) {
                        setPrescriptions([
                            { id: 'RX001', name: 'Lisinopril', dosage: '10mg', frequency: 'Once daily', 
                                instructions: 'Take with food', active: true },
                            { id: 'RX002', name: 'Metformin', dosage: '500mg', frequency: 'Twice daily', 
                                instructions: 'Take with meals', active: true }
                        ]);
                    }
                }

                // 3. Medical History
                try {
                    const historyData = await api.medicalRecords.getByPatient(id);
                    if (Array.isArray(historyData)) setMedicalHistory(historyData);
                } catch (e) { 
                    console.error('Failed to fetch history', e);
                    if (e.message === 'DOCTOR_ENDPOINT_NOT_IMPLEMENTED' || 
                        e.message.includes('not yet available for doctors')) {
                        setMedicalHistory([
                            { id: 'MR001', diagnosis: 'Hypertension', date: '2024-01-15', 
                                doctor: 'Dr. Smith', notes: 'Blood pressure well controlled' },
                            { id: 'MR002', diagnosis: 'Routine Check-up', date: '2024-02-28', 
                                doctor: 'Dr. Smith', notes: 'Annual physical examination' }
                        ]);
                    }
                }

                // 4. Lab Results
                try {
                    const labData = await api.labResults.getByPatient(id);
                    if (Array.isArray(labData)) setLabs(labData);
                } catch (e) { 
                    console.error('Failed to fetch labs', e);
                    if (e.message === 'DOCTOR_ENDPOINT_NOT_IMPLEMENTED' || 
                        e.message.includes('not yet available for doctors')) {
                        setLabs([
                            { id: 'LAB001', name: 'Complete Blood Count', date: '2024-02-20', 
                                status: 'Normal', result: 'All values within normal range' },
                            { id: 'LAB002', name: 'Lipid Panel', date: '2024-02-20', 
                                status: 'Abnormal', result: 'Elevated LDL cholesterol' }
                        ]);
                    }
                }
            } catch (error) {
                console.error('Error in fetch data:', error);
            } finally {
                setIsLoading(false);
            }
        };

        if (id) fetchData();
    }, [id]);

    if (isLoading && !patient) return <div className="p-6 dark:text-slate-100">Loading patient details...</div>;
    if (!patient) return <div className="p-6 dark:text-slate-100">Patient not found</div>;

    const handleAddRx = (e) => {
        e.preventDefault();
        const rx = {
            id: Date.now(),
            ...newRx,
            active: true,
            prescribedBy: 'Dr. Smith', // Dynamic in real app
            date: new Date().toISOString().split('T')[0]
        };
        setPrescriptions([rx, ...prescriptions]);
        setIsRxModalOpen(false);
        setNewRx({ name: '', dosage: '', frequency: '', duration: '', instructions: '' });
    };

    const handleRenewRx = (rx) => {
        const renewedRx = {
            ...rx,
            id: Date.now(),
            active: true,
            date: new Date().toISOString().split('T')[0],
            prescribedBy: 'Dr. Smith'
        };
        setPrescriptions([renewedRx, ...prescriptions]);
        alert(`Prescription for ${rx.name} renewed successfully.`);
    };

    const handleDeleteRx = (rxId) => {
        if (window.confirm('Are you sure you want to delete this prescription?')) {
            setPrescriptions(prescriptions.filter(rx => rx.id !== rxId));
        }
    };

    const handleAddTreatment = (treatment) => {
        const newTreatment = {
            id: Date.now(),
            ...treatment,
            active: true
        };
        setTreatments([newTreatment, ...treatments]);
    };

    const handleAddVitals = (vital) => {
        setVitals([vital, ...vitals]);
    };

    const handleAddLabTest = (test) => {
        setLabs([test, ...labs]);
    };

    const handleAddMedicalRecord = (record) => {
        setMedicalHistory([record, ...medicalHistory]);
    };

    const handleAddPrescription = (rx) => {
        setPrescriptions([rx, ...prescriptions]);
    };

    const activePrescriptions = prescriptions.filter(rx => rx.active);
    const historyPrescriptions = prescriptions.filter(rx => !rx.active);

    return (
        <div className="space-y-3">
            {/* Header */}
            <div className="flex items-center space-x-3">
                <Button variant="outline" onClick={() => navigate('/dashboard/doctor')} className="p-1.5">
                    <ArrowLeft size={16} />
                </Button>
                <div>
                    <h2 className="text-lg font-bold text-gray-800 dark:text-slate-100">{patient.name}</h2>
                    <div className="flex items-center space-x-2 text-xs text-gray-500 dark:text-slate-400">
                        <span>ID: {patient.id}</span>
                        <span>•</span>
                        <span>{patient.age} yrs, {patient.gender}</span>
                    </div>
                </div>
                <div className="ml-auto">
                    <Badge type={patient.status === 'Needs Review' ? 'red' : 'green'}>{patient.status}</Badge>
                </div>
            </div>

            {/* Tabs */}
            <div className="border-b border-gray-200 dark:border-slate-700">
                <nav className="-mb-px flex space-x-4">
                    {['overview', 'history', 'labs', 'prescriptions', 'treatments'].map((tab) => (
                        <button
                            key={tab}
                            onClick={() => setActiveTab(tab)}
                            className={`
                whitespace-nowrap py-2 px-1 border-b-2 font-medium text-xs capitalize
                ${activeTab === tab
                                    ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                                    : 'border-transparent text-gray-500 dark:text-slate-400 hover:text-gray-700 dark:hover:text-slate-300 hover:border-gray-300 dark:hover:border-slate-600'}
              `}
                        >
                            {tab}
                        </button>
                    ))}
                </nav>
            </div>

            {/* Content */}
            <div className="min-h-[300px]">
                {activeTab === 'overview' && (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <Card className="p-3 dark:bg-slate-800">
                            <h3 className="text-sm font-bold text-gray-800 dark:text-slate-100 mb-2 flex items-center">
                                <Activity className="w-4 h-4 mr-1.5 text-blue-500" />
                                Vitals & Condition
                            </h3>
                            <div className="space-y-2">
                                <div className="flex justify-between border-b dark:border-slate-700 pb-1 text-sm">
                                    <span className="text-gray-600 dark:text-slate-400">Condition</span>
                                    <span className="font-medium dark:text-slate-100">{patient.condition}</span>
                                </div>
                                <div className="flex justify-between border-b dark:border-slate-700 pb-1 text-sm">
                                    <span className="text-gray-600 dark:text-slate-400">Blood Pressure</span>
                                    <span className="font-medium dark:text-slate-100">120/80</span>
                                </div>
                                <div className="flex justify-between border-b dark:border-slate-700 pb-1 text-sm">
                                    <span className="text-gray-600 dark:text-slate-400">Heart Rate</span>
                                    <span className="font-medium dark:text-slate-100">72 bpm</span>
                                </div>
                                <div className="flex justify-between text-sm">
                                    <span className="text-gray-600 dark:text-slate-400">Weight</span>
                                    <span className="font-medium dark:text-slate-100">70 kg</span>
                                </div>
                            </div>
                        </Card>

                        <Card className="p-3 dark:bg-slate-800">
                            <h3 className="text-sm font-bold text-gray-800 dark:text-slate-100 mb-2 flex items-center">
                                <Clock className="w-4 h-4 mr-1.5 text-blue-500" />
                                Recent Activity
                            </h3>
                            <ul className="space-y-1.5">
                                {medicalHistory.slice(0, 3).map(item => (
                                    <li key={item.id} className="text-xs">
                                        <span className="font-bold text-gray-700 dark:text-slate-300">{item.date}:</span> <span className="dark:text-slate-400">{item.type} - {item.note}</span>
                                    </li>
                                ))}
                            </ul>
                        </Card>
                    </div>
                )}

                {activeTab === 'prescriptions' && (
                    <div className="space-y-4">
                        {/* Active Prescriptions */}
                        <div className="space-y-2">
                            <div className="flex justify-between items-center bg-blue-50 dark:bg-blue-900/20 p-2.5 rounded border border-blue-100 dark:border-blue-800">
                                <div>
                                    <h3 className="font-bold text-sm text-blue-900 dark:text-blue-100">Active Prescriptions</h3>
                                    <p className="text-xs text-blue-700 dark:text-blue-300">Currently being taken by patient</p>
                                </div>
                                <IconButton 
                                   icon={Plus} 
                                   label="Add New" 
                                   variant="primary"
                                   size="sm"
                                   onClick={() => setIsPrescriptionModalOpen(true)}
                                />
                            </div>

                            {activePrescriptions.length > 0 ? (
                                activePrescriptions.map(rx => (
                                    <Card key={rx.id} className="p-3 flex justify-between items-start group hover:border-blue-300 dark:hover:border-blue-600 transition-colors dark:bg-slate-800">
                                        <div className="flex items-start">
                                            <div className="p-2 rounded-lg bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400 mr-2">
                                                <Pill size={16} />
                                            </div>
                                            <div>
                                                <div className="flex items-center gap-1.5">
                                                    <h4 className="font-bold text-gray-800 dark:text-slate-100 text-sm">{rx.name}</h4>
                                                    <Badge type="green">Active</Badge>
                                                </div>
                                                <div className="text-xs text-gray-600 dark:text-slate-400 font-medium">{rx.dosage} • {rx.frequency}</div>
                                                {rx.duration && <div className="text-xs text-gray-500 dark:text-slate-400">Duration: {rx.duration}</div>}
                                                {rx.instructions && <div className="text-xs text-gray-500 dark:text-slate-400 italic">"{rx.instructions}"</div>}
                                                <div className="text-xs text-gray-400 dark:text-slate-500 mt-1">Prescribed by {rx.prescribedBy} on {rx.date}</div>
                                            </div>
                                        </div>
                                        <div className="flex flex-col space-y-1 opacity-0 group-hover:opacity-100 transition-opacity">
                                            <Button variant="outline" className="text-xs py-0.5 h-6">Edit</Button>
                                            <Button variant="danger" className="text-xs py-0.5 h-6 bg-white dark:bg-slate-700 border-red-200 dark:border-red-800 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20" onClick={() => handleDeleteRx(rx.id)}>
                                                Discontinue
                                            </Button>
                                        </div>
                                    </Card>
                                ))
                            ) : (
                                <div className="text-center py-4 text-gray-400 dark:text-slate-500 border border-dashed dark:border-slate-600 rounded text-sm">
                                    <Pill className="w-6 h-6 mx-auto mb-1 opacity-50" />
                                    No active prescriptions.
                                </div>
                            )}
                        </div>

                        {/* Prescription History */}
                        <div className="space-y-2">
                            <div className="flex justify-between items-center px-2">
                                <h3 className="font-bold text-sm text-gray-700 dark:text-slate-300">Prescription History</h3>
                            </div>

                            {historyPrescriptions.length > 0 ? (
                                <div className="bg-gray-50 dark:bg-slate-800 rounded overflow-hidden border border-gray-200 dark:border-slate-700">
                                    {historyPrescriptions.map((rx, idx) => (
                                        <div key={rx.id} className={`p-2.5 flex justify-between items-center ${idx !== historyPrescriptions.length - 1 ? 'border-b border-gray-200 dark:border-slate-700' : ''}`}>
                                            <div className="opacity-70">
                                                <h4 className="font-bold text-sm text-gray-700 dark:text-slate-300">{rx.name}</h4>
                                                <p className="text-xs text-gray-500 dark:text-slate-400">{rx.dosage} • {rx.frequency}</p>
                                                <p className="text-xs text-gray-400 dark:text-slate-500">Ended: {rx.date}</p>
                                            </div>
                                            <div className="flex items-center gap-2">
                                                <Badge type="gray">Discontinued</Badge>
                                                <Button variant="outline" className="text-xs" onClick={() => handleRenewRx(rx)}>Renew</Button>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            ) : (
                                <div className="text-center py-3 text-gray-400 dark:text-slate-500 text-xs">
                                    No prescription history.
                                </div>
                            )}
                        </div>
                    </div>
                )}

                {activeTab === 'treatments' && (
                    <div className="space-y-2">
                        <div className="flex justify-between items-center bg-gray-50 dark:bg-slate-800 p-2.5 rounded">
                            <h3 className="font-bold text-sm text-gray-700 dark:text-slate-300">Active Treatments</h3>
                            <IconButton 
                               icon={Plus} 
                               label="Add Treatment" 
                               variant="primary"
                               size="sm"
                               onClick={() => setIsTreatmentModalOpen(true)}
                            />
                        </div>
                        {treatments.map(item => (
                            <Card key={item.id} className="p-3 flex flex-col md:flex-row justify-between items-start md:items-center dark:bg-slate-800">
                                <div>
                                    <h4 className="font-bold text-sm text-gray-800 dark:text-slate-100">{item.name}</h4>
                                    <p className="text-xs text-gray-600 dark:text-slate-400">{item.notes}</p>
                                    <Badge type="blue" className="mt-1">{item.frequency}</Badge>
                                </div>
                                <div className="mt-2 md:mt-0">
                                    <Button variant="outline" className="text-xs py-0.5">Edit</Button>
                                </div>
                            </Card>
                        ))}
                    </div>
                )}

                {activeTab === 'history' && <MedicalHistoryList history={medicalHistory} />}
                {activeTab === 'labs' && <LabResultsList labs={labs} />}
            </div>

            {/* Add Prescription Modal */}
            <Modal
                isOpen={isRxModalOpen}
                onClose={() => setIsRxModalOpen(false)}
                title="Prescribe Medication"
            >
                <form onSubmit={handleAddRx} className="space-y-4">
                    <Input
                        label="Medication Name"
                        value={newRx.name}
                        onChange={e => setNewRx({ ...newRx, name: e.target.value })}
                        placeholder="e.g. Amoxicillin"
                        required
                    />
                    <div className="grid grid-cols-2 gap-4">
                        <Input
                            label="Dosage"
                            value={newRx.dosage}
                            onChange={e => setNewRx({ ...newRx, dosage: e.target.value })}
                            placeholder="e.g. 500mg"
                            required
                        />
                        <Input
                            label="Frequency"
                            value={newRx.frequency}
                            onChange={e => setNewRx({ ...newRx, frequency: e.target.value })}
                            placeholder="e.g. 3x Daily"
                            required
                        />
                    </div>
                    <Input
                        label="Duration"
                        value={newRx.duration}
                        onChange={e => setNewRx({ ...newRx, duration: e.target.value })}
                        placeholder="e.g. 7 days"
                        required
                    />
                    <div className="space-y-1">
                        <label className="block text-sm font-medium text-gray-700 dark:text-slate-300">Instructions</label>
                        <textarea
                            className="w-full px-4 py-2 border border-gray-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all resize-none h-24 dark:bg-slate-700 dark:text-slate-100 dark:placeholder-slate-400"
                            value={newRx.instructions}
                            onChange={e => setNewRx({ ...newRx, instructions: e.target.value })}
                            placeholder="e.g. Take with food..."
                        />
                    </div>

                    <div className="pt-4 flex justify-end space-x-3 border-t border-gray-100 dark:border-slate-700">
                        <Button type="button" variant="secondary" onClick={() => setIsRxModalOpen(false)}>Cancel</Button>
                        <Button type="submit">Submit Prescription</Button>
                    </div>
                </form>
            </Modal>

            {/* Update Prescription Click Handler - Change to use new PrescriptionModal */}
            {/* Old modal kept for backward compatibility - now clicking shows new API-integrated modal */}
            
            <TreatmentModal
                isOpen={isTreatmentModalOpen}
                onClose={() => setIsTreatmentModalOpen(false)}
                onAdd={handleAddTreatment}
            />

            {/* New Clinical Operations Modals */}
            <VitalSignModal
                isOpen={isVitalsModalOpen}
                onClose={() => setIsVitalsModalOpen(false)}
                patientId={patient?.id}
                onAdd={handleAddVitals}
            />

            <LabTestModal
                isOpen={isLabTestModalOpen}
                onClose={() => setIsLabTestModalOpen(false)}
                patientId={patient?.id}
                onAdd={handleAddLabTest}
            />

            <MedicalRecordModal
                isOpen={isMedicalRecordModalOpen}
                onClose={() => setIsMedicalRecordModalOpen(false)}
                patientId={patient?.id}
                onAdd={handleAddMedicalRecord}
            />

            <PrescriptionModal
                isOpen={isPrescriptionModalOpen}
                onClose={() => setIsPrescriptionModalOpen(false)}
                patientId={patient?.id}
                onAdd={handleAddPrescription}
            />
        </div>
    );
};

export default PatientDetail;
