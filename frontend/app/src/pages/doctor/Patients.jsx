import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowRight } from 'lucide-react';
import Card from '../../components/common/Card';
import Badge from '../../components/common/Badge';
import Button from '../../components/common/Button';
import PatientSearch from './components/PatientSearch';
import api from '../../services/api';
import { useAuth } from '../../contexts/AuthContext';

const Patients = () => {
    const navigate = useNavigate();
    const { user } = useAuth();
    const [searchTerm, setSearchTerm] = useState('');
    const [patients, setPatients] = useState([]);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState(null);

    // Fetch Patients
    useEffect(() => {
        const fetchPatients = async () => {
            const doctorId = user?.userId;
            if (!doctorId) return;

            setIsLoading(true);
            setError(null);
            try {
                const data = await api.doctors.getPatients(doctorId);
                setPatients(data || []);
            } catch (err) {
                console.error('Failed to fetch patients:', err);
                setError('Failed to load patients. Please refresh the page.');
            } finally {
                setIsLoading(false);
            }
        };
        fetchPatients();
    }, [user?.userId]);

    // Basic filtering
    const filteredPatients = patients.filter(p => {
        const name = `${p.firstName || ''} ${p.lastName || ''}`.toLowerCase();
        const id = (p.id || '').toString().toLowerCase();
        return name.includes(searchTerm.toLowerCase()) || id.includes(searchTerm.toLowerCase());
    });

    return (
        <div className="space-y-3">
            <div className="flex justify-between items-center">
                <h2 className="text-lg font-bold text-gray-800 dark:text-slate-100">My Patients</h2>
                <Button>+ Add Patient</Button>
            </div>

            {error && (
                <Card className="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
                    <p className="text-sm text-red-700 dark:text-red-300">{error}</p>
                </Card>
            )}

            <PatientSearch
                searchTerm={searchTerm}
                setSearchTerm={setSearchTerm}
                onSearch={() => { }}
            />

            {isLoading ? (
                <Card className="p-6 text-center">
                    <p className="text-gray-500 dark:text-slate-400">Loading patients...</p>
                </Card>
            ) : (
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
                                                    <div className="text-xs font-medium text-gray-900 dark:text-slate-100">{patient.firstName} {patient.lastName}</div>
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
            )}
        </div>
    );
};

export default Patients;
