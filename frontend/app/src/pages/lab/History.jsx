import React, { useState } from 'react';
import { Search, Download, Calendar } from 'lucide-react';
import Card from '../../components/common/Card';
import Badge from '../../components/common/Badge';
import { mockLabOrders } from '../../mocks/labOrders';

const LabHistory = () => {
    const [searchTerm, setSearchTerm] = useState('');
    const completedOrders = mockLabOrders.filter(o => o.status === 'Completed');

    const filteredHistory = completedOrders.filter(order =>
        order.patientName.toLowerCase().includes(searchTerm.toLowerCase()) ||
        order.testType.toLowerCase().includes(searchTerm.toLowerCase())
    );

    return (
        <div className="space-y-3">
            <div>
                <h2 className="text-lg font-bold text-gray-800 dark:text-slate-100">Lab History</h2>
                <p className="text-xs text-gray-500 dark:text-slate-400">Archive of all completed lab tests</p>
            </div>

            <Card className="p-3 dark:bg-slate-800">
                <div className="flex flex-col md:flex-row justify-between items-center mb-3 gap-2">
                    <div className="relative w-full md:w-64">
                        <Search className="absolute left-2.5 top-1/2 transform -translate-y-1/2 text-gray-400 dark:text-slate-500 w-3.5 h-3.5" />
                        <input
                            type="text"
                            placeholder="Search by patient or test..."
                            className="w-full pl-8 pr-3 py-1.5 text-xs border border-gray-200 dark:border-slate-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-brand-medium bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100 dark:placeholder-slate-500"
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                        />
                    </div>
                    <div className="flex gap-1.5">
                        <button className="flex items-center px-2.5 py-1.5 text-xs font-medium text-gray-700 dark:text-slate-300 bg-white dark:bg-slate-800 border border-gray-200 dark:border-slate-600 rounded-lg hover:bg-gray-50 dark:hover:bg-slate-700">
                            <Calendar className="w-3.5 h-3.5 mr-1.5" /> Date Range
                        </button>
                    </div>
                </div>

                <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-gray-100 dark:divide-slate-700">
                        <thead className="bg-gray-50 dark:bg-slate-700/50">
                            <tr>
                                <th className="px-3 py-2 text-left text-[10px] font-medium text-gray-500 dark:text-slate-300 uppercase tracking-wider">Order ID</th>
                                <th className="px-3 py-2 text-left text-[10px] font-medium text-gray-500 dark:text-slate-300 uppercase tracking-wider">Patient</th>
                                <th className="px-3 py-2 text-left text-[10px] font-medium text-gray-500 dark:text-slate-300 uppercase tracking-wider">Test</th>
                                <th className="px-3 py-2 text-left text-[10px] font-medium text-gray-500 dark:text-slate-300 uppercase tracking-wider">Completed Date</th>
                                <th className="px-3 py-2 text-left text-[10px] font-medium text-gray-500 dark:text-slate-300 uppercase tracking-wider">Status</th>
                                <th className="px-3 py-2 text-right text-[10px] font-medium text-gray-500 dark:text-slate-300 uppercase tracking-wider">Report</th>
                            </tr>
                        </thead>
                        <tbody className="bg-white dark:bg-slate-800 divide-y divide-gray-100 dark:divide-slate-700">
                            {filteredHistory.map((order) => (
                                <tr key={order.id} className="hover:bg-gray-50 dark:hover:bg-slate-700/50 transition-colors">
                                    <td className="px-3 py-2 whitespace-nowrap text-xs text-gray-500 dark:text-slate-400">{order.id}</td>
                                    <td className="px-3 py-2 whitespace-nowrap text-xs font-medium text-gray-900 dark:text-slate-100">{order.patientName}</td>
                                    <td className="px-3 py-2 whitespace-nowrap text-xs text-gray-700 dark:text-slate-300">{order.testType}</td>
                                    <td className="px-3 py-2 whitespace-nowrap text-xs text-gray-500 dark:text-slate-400">
                                        {new Date(order.completedDate).toLocaleDateString()}
                                    </td>
                                    <td className="px-3 py-2 whitespace-nowrap">
                                        <Badge type="green">Completed</Badge>
                                    </td>
                                    <td className="px-3 py-2 whitespace-nowrap text-right text-xs font-medium">
                                        <button className="text-brand-medium hover:text-brand-deep flex items-center justify-end w-full text-xs">
                                            <Download className="w-3.5 h-3.5 mr-1" /> PDF
                                        </button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </Card>
        </div>
    );
};

export default LabHistory;
