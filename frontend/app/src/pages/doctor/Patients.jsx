import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowRight } from 'lucide-react';
import Card from '../../components/common/Card';
import Badge from '../../components/common/Badge';
import Button from '../../components/common/Button';
import PatientSearch from './components/PatientSearch';
import api from '../../services/api';

const Patients = () => {
    const navigate = useNavigate();
    const [searchTerm, setSearchTerm] = useState('');
    const [patients, setPatients] = useState([]);

    // Fetch Patients
    React.useEffect(() => {
        const fetchPatients = async () => {
            try {
                const data = await api.patients.getAll();
                if (Array.isArray(data)) {
                    setPatients(data);
                }
            } catch (error) {
                console.error('Failed to fetch patients', error);
                // Use mock data for doctors when API is not available
                const mockPatients = [
                    {
                        id: 'P001',
                        name: 'John Smith',
                        email: 'john.smith@example.com',
                        phone: '+1-555-0123',
                        age: 45,
                        gender: 'Male',
                        condition: 'Hypertension',
                        status: 'Stable',
                        lastVisit: '2024-02-15',
                        avatar: 'JS'
                    },
                    {
                        id: 'P002', 
                        name: 'Sarah Johnson',
                        email: 'sarah.j@example.com',
                        phone: '+1-555-0124',
                        age: 32,
                        gender: 'Female', 
                        condition: 'Diabetes',
                        status: 'Needs Review',
                        lastVisit: '2024-02-20',
                        avatar: 'SJ'
                    },
                    {
                        id: 'P003',
                        name: 'Michael Brown',
                        email: 'mike.brown@example.com', 
                        phone: '+1-555-0125',
                        age: 58,
                        gender: 'Male',
                        condition: 'Heart Disease',
                        status: 'Stable',
                        lastVisit: '2024-02-10',
                        avatar: 'MB'
                    }
                ];
                setPatients(mockPatients);
            }
        };
        fetchPatients();
    }, []);

    // Basic filtering
    const filteredPatients = patients.filter(p =>
        p.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        p.id.toLowerCase().includes(searchTerm.toLowerCase())
    );

    return (
        <div className="space-y-3">
            <div className="flex justify-between items-center">
                <h2 className="text-lg font-bold text-gray-800 dark:text-slate-100">My Patients</h2>
                <Button>+ Add Patient</Button>
            </div>

            <PatientSearch
                searchTerm={searchTerm}
                setSearchTerm={setSearchTerm}
                onSearch={() => { }}
            />

            <Card className="overflow-hidden dark:bg-slate-800">
                <div className="px-4 py-2 border-b dark:border-slate-700 flex justify-between items-center bg-gray-50 dark:bg-slate-700/50">
                    <h3 className="text-sm font-bold text-gray-800 dark:text-slate-100">Patient Directory</h3>
                    <span className="text-xs text-gray-500 dark:text-slate-400">{filteredPatients.length} records</span>
                </div>

                {filteredPatients.length > 0 ? (
                    <div className="overflow-x-auto">
                        <table className="min-w-full divide-y divide-gray-200 dark:divide-slate-700">
                            <thead className="bg-gray-50 dark:bg-slate-700/50">
                                <tr>
                                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-slate-300 uppercase tracking-wider">Patient</th>
                                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-slate-300 uppercase tracking-wider">Contact</th>
                                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-slate-300 uppercase tracking-wider">Condition</th>
                                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-slate-300 uppercase tracking-wider">Status</th>
                                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-slate-300 uppercase tracking-wider">Last Visit</th>
                                    <th className="px-4 py-2 text-right text-xs font-medium text-gray-500 dark:text-slate-300 uppercase tracking-wider">Action</th>
                                </tr>
                            </thead>
                            <tbody className="bg-white dark:bg-slate-800 divide-y divide-gray-200 dark:divide-slate-700">
                                {filteredPatients.map((patient) => (
                                    <tr key={patient.id} className="hover:bg-gray-50 dark:hover:bg-slate-700/50 transition">
                                        <td className="px-4 py-2 whitespace-nowrap">
                                            <div className="flex items-center">
                                                <div className="flex-shrink-0 h-8 w-8 rounded-full bg-blue-100 dark:bg-blue-900/30 flex items-center justify-center text-blue-600 dark:text-blue-400 text-xs font-bold">
                                                    {patient.avatar}
                                                </div>
                                                <div className="ml-2">
                                                    <div className="text-xs font-medium text-gray-900 dark:text-slate-100">{patient.name}</div>
                                                    <div className="text-xs text-gray-500 dark:text-slate-400">ID: {patient.id}</div>
                                                    <div className="text-xs text-gray-400 dark:text-slate-500">{patient.age} yrs, {patient.gender}</div>
                                                </div>
                                            </div>
                                        </td>
                                        <td className="px-4 py-2 whitespace-nowrap">
                                            <div className="text-xs text-gray-900 dark:text-slate-100">{patient.email}</div>
                                            <div className="text-xs text-gray-500 dark:text-slate-400">{patient.phone}</div>
                                        </td>
                                        <td className="px-4 py-2 whitespace-nowrap">
                                            <span className="text-xs text-gray-900 dark:text-slate-100">{patient.condition}</span>
                                        </td>
                                        <td className="px-4 py-2 whitespace-nowrap">
                                            <Badge type={patient.status === 'Needs Review' ? 'red' : 'green'}>
                                                {patient.status}
                                            </Badge>
                                        </td>
                                        <td className="px-4 py-2 whitespace-nowrap text-xs text-gray-500 dark:text-slate-400">
                                            {patient.lastVisit}
                                        </td>
                                        <td className="px-4 py-2 whitespace-nowrap text-right text-xs font-medium">
                                            <button
                                                className="text-blue-600 hover:text-blue-900 dark:text-blue-400 dark:hover:text-blue-300 flex items-center justify-end w-full"
                                                onClick={() => navigate(`/dashboard/doctor/patient/${patient.id}`)}
                                            >
                                                Details <ArrowRight className="w-4 h-4 ml-1" />
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                ) : (
                    <div className="p-8 text-center text-gray-500 dark:text-slate-400">
                        No patients found.
                    </div>
                )}
            </Card>
        </div>
    );
};

export default Patients;
