import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, Filter } from 'lucide-react';
import Card from '../../components/common/Card';
import Badge from '../../components/common/Badge';
import Button from '../../components/common/Button';
import { mockLabOrders } from '../../mocks/labOrders';

const LabOrders = () => {
    const navigate = useNavigate();
    const [searchTerm, setSearchTerm] = useState('');
    const [statusFilter, setStatusFilter] = useState('All');

    const filteredOrders = mockLabOrders.filter(order => {
        const matchesSearch = order.patientName.toLowerCase().includes(searchTerm.toLowerCase()) ||
            order.id.toLowerCase().includes(searchTerm.toLowerCase());
        const matchesStatus = statusFilter === 'All' || order.status === statusFilter;
        return matchesSearch && matchesStatus;
    });

    const getStatusType = (status) => {
        switch (status) {
            case 'Pending': return 'yellow';
            case 'Collected': return 'blue';
            case 'Results Pending': return 'indigo';
            case 'Completed': return 'green';
            default: return 'gray';
        }
    };

    return (
        <div className="space-y-3">
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-2">
                <div>
                    <h2 className="text-lg font-bold text-gray-800 dark:text-slate-100">Lab Orders</h2>
                    <p className="text-xs text-gray-500 dark:text-slate-400">Manage and process patient lab tests</p>
                </div>
                <Button onClick={() => navigate('/dashboard/lab/upload')}>
                    Upload Results
                </Button>
            </div>

            <Card className="p-3 dark:bg-slate-800">
                <div className="flex flex-col md:flex-row justify-between items-center mb-3 gap-2">
                    <div className="relative w-full md:w-56">
                        <Search className="absolute left-2.5 top-1/2 transform -translate-y-1/2 text-gray-400 dark:text-slate-500 w-3.5 h-3.5" />
                        <input
                            type="text"
                            placeholder="Search orders..."
                            className="w-full pl-8 pr-3 py-1.5 border border-gray-200 dark:border-slate-600 rounded-lg text-xs focus:outline-none focus:ring-2 focus:ring-brand-medium bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100 dark:placeholder-slate-500"
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                        />
                    </div>
                    <div className="flex items-center gap-1.5 w-full md:w-auto overflow-x-auto">
                        <Filter className="w-3.5 h-3.5 text-gray-500 dark:text-slate-400" />
                        {['All', 'Pending', 'Collected', 'Completed'].map(status => (
                            <button
                                key={status}
                                onClick={() => setStatusFilter(status)}
                                className={`px-2.5 py-1 text-xs rounded-full whitespace-nowrap transition-colors ${statusFilter === status
                                    ? 'bg-brand-medium text-white'
                                    : 'bg-gray-100 dark:bg-slate-700 text-gray-600 dark:text-slate-300 hover:bg-gray-200 dark:hover:bg-slate-600'
                                    }`}
                            >
                                {status}
                            </button>
                        ))}
                    </div>
                </div>

                <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-gray-100 dark:divide-slate-700">
                        <thead className="bg-gray-50 dark:bg-slate-700/50">
                            <tr>
                                <th className="px-3 py-2 text-left text-[10px] font-medium text-gray-500 dark:text-slate-300 uppercase tracking-wider">Order ID</th>
                                <th className="px-3 py-2 text-left text-[10px] font-medium text-gray-500 dark:text-slate-300 uppercase tracking-wider">Patient</th>
                                <th className="px-3 py-2 text-left text-[10px] font-medium text-gray-500 dark:text-slate-300 uppercase tracking-wider">Test Type</th>
                                <th className="px-3 py-2 text-left text-[10px] font-medium text-gray-500 dark:text-slate-300 uppercase tracking-wider">Priority</th>
                                <th className="px-3 py-2 text-left text-[10px] font-medium text-gray-500 dark:text-slate-300 uppercase tracking-wider">Status</th>
                                <th className="px-3 py-2 text-left text-[10px] font-medium text-gray-500 dark:text-slate-300 uppercase tracking-wider">Date</th>
                                <th className="px-3 py-2 text-right text-[10px] font-medium text-gray-500 dark:text-slate-300 uppercase tracking-wider">Action</th>
                            </tr>
                        </thead>
                        <tbody className="bg-white dark:bg-slate-800 divide-y divide-gray-100 dark:divide-slate-700">
                            {filteredOrders.map((order) => (
                                <tr key={order.id} className="hover:bg-gray-50 dark:hover:bg-slate-700/50 transition-colors">
                                    <td className="px-3 py-2 whitespace-nowrap text-xs font-medium text-brand-medium">
                                        {order.id}
                                    </td>
                                    <td className="px-3 py-2 whitespace-nowrap">
                                        <div className="text-xs font-medium text-gray-900 dark:text-slate-100">{order.patientName}</div>
                                        <div className="text-[10px] text-gray-500 dark:text-slate-400">{order.patientId}</div>
                                    </td>
                                    <td className="px-3 py-2 whitespace-nowrap text-xs text-gray-700 dark:text-slate-300">
                                        {order.testType}
                                    </td>
                                    <td className="px-3 py-2 whitespace-nowrap">
                                        <Badge type={order.priority === 'Urgent' || order.priority === 'High' ? 'red' : 'gray'}>
                                            {order.priority}
                                        </Badge>
                                    </td>
                                    <td className="px-3 py-2 whitespace-nowrap">
                                        <Badge type={getStatusType(order.status)}>
                                            {order.status}
                                        </Badge>
                                    </td>
                                    <td className="px-3 py-2 whitespace-nowrap text-xs text-gray-500 dark:text-slate-400">
                                        {new Date(order.orderDate).toLocaleDateString()}
                                    </td>
                                    <td className="px-3 py-2 whitespace-nowrap text-right text-xs font-medium">
                                        <Button
                                            variant="ghost"
                                            size="sm"
                                            onClick={() => navigate(`/dashboard/lab/orders/${order.id}`)}
                                            className="text-brand-medium hover:text-brand-deep"
                                        >
                                            View
                                        </Button>
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

export default LabOrders;
