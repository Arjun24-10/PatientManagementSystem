import React, { useState } from 'react';
import { Plus, Search, Filter, Pill } from 'lucide-react';
import Card from '../../components/common/Card';
import Button from '../../components/common/Button';
import Badge from '../../components/common/Badge';
import Modal from '../../components/common/Modal';
import { mockPrescriptions } from '../../mocks/records';

const Prescriptions = () => {
    const [searchTerm, setSearchTerm] = useState('');
    const [isFormatModalOpen, setIsFormatModalOpen] = useState(false);

    // In a real app, this would be a list of all prescriptions across patients
    const filteredPrescriptions = mockPrescriptions.filter(rx =>
        rx.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        rx.prescribedBy.toLowerCase().includes(searchTerm.toLowerCase())
    );

    return (
        <div className="space-y-3">
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-2">
                <div>
                    <h2 className="text-lg font-bold text-gray-800 dark:text-slate-100">Prescriptions</h2>
                    <p className="text-xs text-gray-500 dark:text-slate-400">Manage patient medications and refills.</p>
                </div>
                <Button onClick={() => setIsFormatModalOpen(true)} className="flex items-center text-sm">
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
                            <Button variant="outline" className="text-xs">Manage</Button>
                        </div>
                    </Card>
                ))}
            </div>

            {/* Placeholder Modal */}
            <Modal
                isOpen={isFormatModalOpen}
                onClose={() => setIsFormatModalOpen(false)}
                title="New Prescription"
            >
                <div className="p-4 text-center text-gray-500 dark:text-slate-400">
                    <p>Select a patient to maintain context before prescribing.</p>
                    <div className="mt-4">
                        <Button onClick={() => setIsFormatModalOpen(false)}>Close</Button>
                    </div>
                </div>
            </Modal>
        </div>
    );
};

export default Prescriptions;
