import React, { useState } from 'react';
import { Search } from 'lucide-react';
import Card from '../../components/common/Card';
import LabResultsList from '../../components/doctor/LabResultsList';
import { mockLabs } from '../../mocks/records';

const LabResults = () => {
    const [searchTerm, setSearchTerm] = useState('');
    const [filter, setFilter] = useState('All');

    const filteredLabs = mockLabs.filter(lab => {
        const matchesSearch = lab.name.toLowerCase().includes(searchTerm.toLowerCase());
        const matchesFilter = filter === 'All' || lab.status === filter;
        return matchesSearch && matchesFilter;
    });

    return (
        <div className="space-y-6">
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
                <div>
                    <h2 className="text-2xl font-bold text-gray-800 dark:text-slate-100">Lab Results</h2>
                    <p className="text-gray-500 dark:text-slate-400">Manage and review patient test results.</p>
                </div>
            </div>

            <Card className="p-4 dark:bg-slate-800">
                <div className="flex flex-col md:flex-row gap-4 justify-between items-center">
                    <div className="relative w-full md:w-96">
                        <Search className="absolute left-3 top-3 text-gray-400 dark:text-slate-500 w-5 h-5" />
                        <input
                            type="text"
                            placeholder="Search by test name..."
                            className="w-full pl-10 pr-4 py-2 border border-gray-200 dark:border-slate-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-slate-700 dark:text-slate-100 dark:placeholder-slate-400"
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                        />
                    </div>

                    <div className="flex gap-2 w-full md:w-auto overflow-x-auto">
                        {['All', 'Completed', 'Pending', 'Abnormal'].map(status => (
                            <button
                                key={status}
                                onClick={() => setFilter(status)}
                                className={`px-4 py-2 rounded-lg text-sm font-medium whitespace-nowrap transition-colors ${filter === status
                                        ? 'bg-blue-600 text-white'
                                        : 'bg-gray-100 dark:bg-slate-700 text-gray-600 dark:text-slate-300 hover:bg-gray-200 dark:hover:bg-slate-600'
                                    }`}
                            >
                                {status}
                            </button>
                        ))}
                    </div>
                </div>
            </Card>

            <LabResultsList labs={filteredLabs} />
        </div>
    );
};

export default LabResults;
