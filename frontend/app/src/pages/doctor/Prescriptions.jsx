import React, { useState } from 'react';
import { Plus, Search, Filter, Pill } from 'lucide-react';
import Card from '../../components/common/Card';
import Button from '../../components/common/Button';
import Badge from '../../components/common/Badge';
import Modal from '../../components/common/Modal';
import Input from '../../components/common/Input';
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
        <div className="space-y-6">
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
                <div>
                    <h2 className="text-2xl font-bold text-gray-800">Prescriptions</h2>
                    <p className="text-gray-500">Manage patient medications and refills.</p>
                </div>
                <Button onClick={() => setIsFormatModalOpen(true)} className="flex items-center">
                    <Plus className="w-5 h-5 mr-2" /> New Prescription
                </Button>
            </div>

            <Card className="p-4">
                <div className="flex items-center gap-4">
                    <div className="relative flex-1">
                        <Search className="absolute left-3 top-3 text-gray-400 w-5 h-5" />
                        <input
                            type="text"
                            placeholder="Search prescriptions..."
                            className="w-full pl-10 pr-4 py-2 border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                        />
                    </div>
                    <Button variant="outline" className="hidden md:flex items-center">
                        <Filter className="w-4 h-4 mr-2" /> Filter
                    </Button>
                </div>
            </Card>

            <div className="grid gap-4">
                {filteredPrescriptions.map(rx => (
                    <Card key={rx.id} className="p-4 flex flex-col md:flex-row justify-between items-center hover:shadow-md transition-shadow">
                        <div className="flex items-center gap-4 w-full md:w-auto">
                            <div className="p-3 bg-purple-50 text-purple-600 rounded-lg">
                                <Pill size={24} />
                            </div>
                            <div>
                                <h3 className="font-bold text-gray-800">{rx.name}</h3>
                                <div className="text-sm text-gray-500 flex flex-wrap gap-2">
                                    <span>{rx.dosage}</span>
                                    <span>•</span>
                                    <span>{rx.frequency}</span>
                                </div>
                            </div>
                        </div>

                        <div className="flex items-center gap-6 mt-4 md:mt-0 w-full md:w-auto justify-between md:justify-end">
                            <div className="text-right mr-4">
                                <div className="text-sm text-gray-500">Prescribed By</div>
                                <div className="font-medium text-gray-800">{rx.prescribedBy}</div>
                            </div>
                            <Badge type={rx.active ? 'green' : 'gray'}>
                                {rx.active ? 'Active' : 'Discontinued'}
                            </Badge>
                            <Button variant="outline" className="text-sm">Manage</Button>
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
                <div className="p-4 text-center text-gray-500">
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
