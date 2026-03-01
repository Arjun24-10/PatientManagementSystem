import React, { useState } from 'react';
import { Plus, Search, Filter, Pill } from 'lucide-react';
import Card from '../../components/common/Card';
import Button from '../../components/common/Button';
import Badge from '../../components/common/Badge';
import Modal from '../../components/common/Modal';
import api from '../../services/api';

const Prescriptions = () => {
    const [searchTerm, setSearchTerm] = useState('');
    const [prescriptions, setPrescriptions] = useState([]);
    const [patients, setPatients] = useState([]);
    const [isNewRxModalOpen, setIsNewRxModalOpen] = useState(false);
    const [isManageModalOpen, setIsManageModalOpen] = useState(false);
    const [selectedRx, setSelectedRx] = useState(null);

    // Form states
    const [newRxData, setNewRxData] = useState({
        patientId: '',
        name: '',
        dosage: '',
        frequency: '',
        notes: ''
    });

    React.useEffect(() => {
        const fetchPatients = async () => {
            try {
                const data = await api.patients.getAll();
                if (Array.isArray(data)) setPatients(data);
            } catch (error) {
                console.error('Failed to fetch patients', error);
            }
        };
        const fetchPrescriptions = async () => {
            try {
                const data = await api.prescriptions.getAll();
                if (Array.isArray(data)) setPrescriptions(data);
            } catch (error) {
                console.error('Failed to fetch prescriptions', error);
            }
        };
        fetchPatients();
        fetchPrescriptions();
    }, []);

    const [editRxData, setEditRxData] = useState({
        dosage: '',
        frequency: '',
        active: true
    });

    const filteredPrescriptions = prescriptions.filter(rx =>
        rx.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        (rx.patientName && rx.patientName.toLowerCase().includes(searchTerm.toLowerCase())) ||
        rx.prescribedBy.toLowerCase().includes(searchTerm.toLowerCase())
    );

    const handleNewRxSubmit = async (e) => {
        e.preventDefault();
        const patient = patients.find(p => p.id === newRxData.patientId);

        const newPrescription = {
            medicationName: newRxData.name,
            dosage: newRxData.dosage,
            frequency: newRxData.frequency,
            status: 'ACTIVE',
            notes: newRxData.notes,
            patientId: newRxData.patientId
        };

        try {
            const created = await api.prescriptions.create(newPrescription);
            // Append mock data to created if backend omits it to ensure UI renders properly
            setPrescriptions([
                { ...created, patientName: patient ? patient.name : 'Unknown', name: created.medicationName || created.name },
                ...prescriptions
            ]);
            setIsNewRxModalOpen(false);
            setNewRxData({ patientId: '', name: '', dosage: '', frequency: '', notes: '' });
        } catch (error) {
            console.error('Failed to create prescription', error);
            alert('Failed to create prescription.');
        }
    };

    const handleManageClick = (rx) => {
        setSelectedRx(rx);
        setEditRxData({
            dosage: rx.dosage,
            frequency: rx.frequency,
            active: rx.active
        });
        setIsManageModalOpen(true);
    };

    const handleUpdateRx = async (e) => {
        e.preventDefault();

        try {
            const updatePayload = {
                ...selectedRx,
                dosage: editRxData.dosage,
                frequency: editRxData.frequency,
                status: editRxData.active ? 'ACTIVE' : 'DISCONTINUED',
            };
            await api.prescriptions.update(selectedRx.id, updatePayload);

            setPrescriptions(prescriptions.map(rx =>
                rx.id === selectedRx.id
                    ? { ...rx, ...editRxData, active: editRxData.active }
                    : rx
            ));
            setIsManageModalOpen(false);
            setSelectedRx(null);
        } catch (error) {
            console.error('Failed to update prescription', error);
            alert('Failed to update prescription.');
        }
    };

    return (
        <div className="space-y-3">
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-2">
                <div>
                    <h2 className="text-lg font-bold text-gray-800 dark:text-slate-100">Prescriptions</h2>
                    <p className="text-xs text-gray-500 dark:text-slate-400">Manage patient medications and refills.</p>
                </div>
                <Button onClick={() => setIsNewRxModalOpen(true)} className="flex items-center text-sm">
                    <Plus className="w-4 h-4 mr-1" /> New Prescription
                </Button>
            </div>

            <Card className="p-3 dark:bg-slate-800">
                <div className="flex items-center gap-2">
                    <div className="relative flex-1">
                        <Search className="absolute left-2.5 top-2 text-gray-400 dark:text-slate-500 w-4 h-4" />
                        <input
                            type="text"
                            placeholder="Search prescriptions..."
                            className="w-full pl-8 pr-3 py-1.5 border border-gray-200 dark:border-slate-600 rounded text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-slate-700 dark:text-slate-100 dark:placeholder-slate-400"
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                        />
                    </div>
                    <Button variant="outline" className="hidden md:flex items-center text-sm">
                        <Filter className="w-3.5 h-3.5 mr-1" /> Filter
                    </Button>
                </div>
            </Card>

            <div className="grid gap-2">
                {filteredPrescriptions.map(rx => (
                    <Card key={rx.id} className="p-3 flex flex-col md:flex-row justify-between items-center hover:shadow-md transition-shadow dark:bg-slate-800">
                        <div className="flex items-center gap-3 w-full md:w-auto">
                            <div className="p-2 bg-purple-50 dark:bg-purple-900/20 text-purple-600 dark:text-purple-400 rounded">
                                <Pill size={16} />
                            </div>
                            <div>
                                <div className="text-xs text-gray-500 dark:text-slate-400 mb-0.5">
                                    Patient: <span className="font-semibold text-gray-700 dark:text-slate-300">{rx.patientName}</span> ({rx.patientId})
                                </div>
                                <h3 className="font-bold text-sm text-gray-800 dark:text-slate-100">{rx.name}</h3>
                                <div className="text-xs text-gray-500 dark:text-slate-400 flex flex-wrap gap-1">
                                    <span>{rx.dosage}</span>
                                    <span>•</span>
                                    <span>{rx.frequency}</span>
                                </div>
                            </div>
                        </div>

                        <div className="flex items-center gap-4 mt-2 md:mt-0 w-full md:w-auto justify-between md:justify-end">
                            <div className="text-right mr-2">
                                <div className="text-xs text-gray-500 dark:text-slate-400">Prescribed By</div>
                                <div className="font-medium text-xs text-gray-800 dark:text-slate-100">{rx.prescribedBy}</div>
                            </div>
                            <Badge type={rx.active ? 'green' : 'gray'}>
                                {rx.active ? 'Active' : 'Discontinued'}
                            </Badge>
                            <Button
                                variant="outline"
                                className="text-xs"
                                onClick={() => handleManageClick(rx)}
                            >
                                Manage
                            </Button>
                        </div>
                    </Card>
                ))}
            </div>

            {/* New Prescription Modal */}
            <Modal
                isOpen={isNewRxModalOpen}
                onClose={() => setIsNewRxModalOpen(false)}
                title="New Prescription"
            >
                <form onSubmit={handleNewRxSubmit} className="space-y-4">
                    <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-1">Select Patient</label>
                        <select
                            required
                            className="w-full p-2 border border-gray-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-sm focus:ring-2 focus:ring-blue-500"
                            value={newRxData.patientId}
                            onChange={(e) => setNewRxData({ ...newRxData, patientId: e.target.value })}
                        >
                            <option value="">-- Select Patient --</option>
                            {patients.map(p => (
                                <option key={p.id} value={p.id}>{p.name} ({p.id})</option>
                            ))}
                        </select>
                    </div>

                    <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-1">Medication Name</label>
                        <input
                            type="text"
                            required
                            placeholder="e.g. Amoxicillin"
                            className="w-full p-2 border border-gray-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-sm focus:ring-2 focus:ring-blue-500"
                            value={newRxData.name}
                            onChange={(e) => setNewRxData({ ...newRxData, name: e.target.value })}
                        />
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                        <div>
                            <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-1">Dosage</label>
                            <input
                                type="text"
                                required
                                placeholder="e.g. 500mg"
                                className="w-full p-2 border border-gray-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-sm focus:ring-2 focus:ring-blue-500"
                                value={newRxData.dosage}
                                onChange={(e) => setNewRxData({ ...newRxData, dosage: e.target.value })}
                            />
                        </div>
                        <div>
                            <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-1">Frequency</label>
                            <input
                                type="text"
                                required
                                placeholder="e.g. 2x Daily"
                                className="w-full p-2 border border-gray-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-sm focus:ring-2 focus:ring-blue-500"
                                value={newRxData.frequency}
                                onChange={(e) => setNewRxData({ ...newRxData, frequency: e.target.value })}
                            />
                        </div>
                    </div>

                    <div className="flex justify-end gap-2 pt-2">
                        <Button type="button" variant="secondary" onClick={() => setIsNewRxModalOpen(false)}>Cancel</Button>
                        <Button type="submit">Create Prescription</Button>
                    </div>
                </form>
            </Modal>

            {/* Manage Prescription Modal */}
            <Modal
                isOpen={isManageModalOpen}
                onClose={() => setIsManageModalOpen(false)}
                title="Manage Prescription"
            >
                {selectedRx && (
                    <form onSubmit={handleUpdateRx} className="space-y-4">
                        <div className="bg-gray-50 dark:bg-slate-700/50 p-3 rounded-lg mb-4">
                            <p className="text-sm font-medium text-gray-800 dark:text-slate-200">{selectedRx.name}</p>
                            <p className="text-xs text-gray-500 dark:text-slate-400">Patient: {selectedRx.patientName}</p>
                        </div>

                        <div className="grid grid-cols-2 gap-4">
                            <div>
                                <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-1">Dosage</label>
                                <input
                                    type="text"
                                    className="w-full p-2 border border-gray-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-sm focus:ring-2 focus:ring-blue-500"
                                    value={editRxData.dosage}
                                    onChange={(e) => setEditRxData({ ...editRxData, dosage: e.target.value })}
                                />
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-1">Frequency</label>
                                <input
                                    type="text"
                                    className="w-full p-2 border border-gray-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-sm focus:ring-2 focus:ring-blue-500"
                                    value={editRxData.frequency}
                                    onChange={(e) => setEditRxData({ ...editRxData, frequency: e.target.value })}
                                />
                            </div>
                        </div>

                        <div>
                            <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-1">Status</label>
                            <select
                                className="w-full p-2 border border-gray-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-sm focus:ring-2 focus:ring-blue-500"
                                value={editRxData.active}
                                onChange={(e) => setEditRxData({ ...editRxData, active: e.target.value === 'true' })}
                            >
                                <option value="true">Active</option>
                                <option value="false">Discontinued</option>
                            </select>
                        </div>

                        <div className="flex justify-end gap-2 pt-2">
                            <Button type="button" variant="secondary" onClick={() => setIsManageModalOpen(false)}>Cancel</Button>
                            <Button type="submit">Update Prescription</Button>
                        </div>
                    </form>
                )}
            </Modal>
        </div>
    );
};

export default Prescriptions;
