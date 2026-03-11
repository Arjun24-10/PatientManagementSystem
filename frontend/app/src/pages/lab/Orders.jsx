import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, Filter } from 'lucide-react';
import Card from '../../components/common/Card';
import Badge from '../../components/common/Badge';
import Button from '../../components/common/Button';
import api from '../../services/api';

const LabOrders = () => {
    const navigate = useNavigate();
    const [orders, setOrders] = useState([]);
    const [searchTerm, setSearchTerm] = useState('');
    const [statusFilter, setStatusFilter] = useState('All');
    const [startDate, setStartDate] = useState('');
    const [endDate, setEndDate] = useState('');
    const [isStatusDropdownOpen, setIsStatusDropdownOpen] = useState(false);

    useEffect(() => {
        const fetchOrders = async () => {
            try {
                const status = statusFilter === 'All' ? null : statusFilter;
                const data = await api.labTechnician.getOrders(status);
                if (data && Array.isArray(data)) {
                    setOrders(data);
                } else {
                    setOrders([]);
                }
            } catch (err) {
                console.error('Failed to fetch orders:', err);
                setOrders([]);
            }
        };
        fetchOrders();
    }, [statusFilter]);

    const filteredOrders = orders.filter((order) => {
        const patientName = order.patientName || (order.patient ? `${order.patient.firstName} ${order.patient.lastName}` : 'Unknown');
        const orderId = order.testId || order.id;
        const matchesSearch = patientName.toLowerCase().includes(searchTerm.toLowerCase()) ||
            orderId.toString().toLowerCase().includes(searchTerm.toLowerCase());
        const matchesStatus = statusFilter === 'All' || order.status === statusFilter;

        let matchesDate = true;
        if (startDate && endDate) {
            const orderDate = order.orderedAt ? new Date(order.orderedAt) : null;
            if (orderDate) {
                const start = new Date(startDate);
                const end = new Date(endDate);
                // Set end date to end of day for inclusive comparison
                end.setHours(23, 59, 59, 999);
                matchesDate = orderDate >= start && orderDate <= end;
            }
        }

        return matchesSearch && matchesStatus && matchesDate;
    });

    const toggleStatusDropdown = () => {
        setIsStatusDropdownOpen(!isStatusDropdownOpen);
    };

    const handleStatusSelect = (status) => {
        setStatusFilter(status);
        setIsStatusDropdownOpen(false);
    };

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
                <div className="flex flex-col gap-3 mb-4">
                    {/* Top Row: Search and Status Filter */}
                    <div className="flex flex-col md:flex-row justify-between items-center gap-3">
                        <div className="relative w-full md:w-64">
                            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 dark:text-slate-500 w-4 h-4" />
                            <input
                                type="text"
                                placeholder="Search orders..."
                                className="w-full pl-9 pr-4 py-2 border border-gray-200 dark:border-slate-600 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-brand-medium/50 bg-gray-50 dark:bg-slate-900/50 text-gray-900 dark:text-slate-100"
                                value={searchTerm}
                                onChange={(e) => setSearchTerm(e.target.value)}
                            />
                        </div>

                        <div className="flex items-center gap-2 w-full md:w-auto">
                            {/* Date Range Inputs */}
                            <div className="flex items-center gap-2 bg-gray-50 dark:bg-slate-900/50 p-1 rounded-xl border border-gray-100 dark:border-slate-700">
                                <input
                                    type="date"
                                    value={startDate}
                                    onChange={(e) => setStartDate(e.target.value)}
                                    className="bg-transparent border-none text-xs text-gray-600 dark:text-slate-300 focus:ring-0 px-2 py-1"
                                />
                                <span className="text-gray-400">-</span>
                                <input
                                    type="date"
                                    value={endDate}
                                    onChange={(e) => setEndDate(e.target.value)}
                                    className="bg-transparent border-none text-xs text-gray-600 dark:text-slate-300 focus:ring-0 px-2 py-1"
                                />
                            </div>

                            {/* Status Dropdown */}
                            <div className="relative">
                                <button
                                    onClick={toggleStatusDropdown}
                                    className={`flex items-center gap-2 px-3 py-2 rounded-xl text-sm font-medium transition-colors border ${statusFilter !== 'All'
                                        ? 'bg-blue-50 text-blue-600 border-blue-100 dark:bg-blue-900/20 dark:text-blue-400 dark:border-blue-800'
                                        : 'bg-white text-gray-600 border-gray-200 hover:bg-gray-50 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700'
                                        }`}
                                >
                                    <Filter className="w-4 h-4" />
                                    <span>{statusFilter}</span>
                                </button>

                                {isStatusDropdownOpen && (
                                    <>
                                        <div className="fixed inset-0 z-10" onClick={() => setIsStatusDropdownOpen(false)} />
                                        <div className="absolute right-0 mt-2 w-40 bg-white dark:bg-slate-800 rounded-xl shadow-xl border border-gray-100 dark:border-slate-700 z-20 overflow-hidden">
                                            {['All', 'Pending', 'Collected', 'Results Pending', 'Completed'].map(status => (
                                                <button
                                                    key={status}
                                                    onClick={() => handleStatusSelect(status)}
                                                    className={`w-full text-left px-4 py-2.5 text-sm hover:bg-gray-50 dark:hover:bg-slate-700 transition-colors ${statusFilter === status ? 'text-blue-600 font-medium bg-blue-50/50 dark:text-blue-400' : 'text-gray-600 dark:text-slate-300'
                                                        }`}
                                                >
                                                    {status}
                                                </button>
                                            ))}
                                        </div>
                                    </>
                                )}
                            </div>
                        </div>
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
                            {filteredOrders.map((order) => {
                                const testId = order.testId || order.id;
                                return (
                                <tr key={testId} className="hover:bg-gray-50 dark:hover:bg-slate-700/50 transition-colors">
                                    <td className="px-3 py-2 whitespace-nowrap text-xs font-medium text-brand-medium">
                                        {testId}
                                    </td>
                                    <td className="px-3 py-2 whitespace-nowrap">
                                        <div className="text-xs font-medium text-gray-900 dark:text-slate-100">{order.patientName}</div>
                                        <div className="text-[10px] text-gray-500 dark:text-slate-400">{order.profileId}</div>
                                    </td>
                                    <td className="px-3 py-2 whitespace-nowrap text-xs text-gray-700 dark:text-slate-300">
                                        {order.testName || order.testType}
                                    </td>
                                    <td className="px-3 py-2 whitespace-nowrap">
                                        <Badge type={order.testCategory === 'Urgent' || order.testCategory === 'High' ? 'red' : 'gray'}>
                                            {order.testCategory || 'Standard'}
                                        </Badge>
                                    </td>
                                    <td className="px-3 py-2 whitespace-nowrap">
                                        <Badge type={getStatusType(order.status)}>
                                            {order.status}
                                        </Badge>
                                    </td>
                                    <td className="px-3 py-2 whitespace-nowrap text-xs text-gray-500 dark:text-slate-400">
                                        {order.orderedAt ? new Date(order.orderedAt).toLocaleDateString() : 'N/A'}
                                    </td>
                                    <td className="px-3 py-2 whitespace-nowrap text-right text-xs font-medium">
                                        <Button
                                            variant="ghost"
                                            size="sm"
                                            onClick={() => navigate(`/dashboard/lab/orders/${testId}`)}
                                            className="text-brand-medium hover:text-brand-deep"
                                        >
                                            View
                                        </Button>
                                    </td>
                                </tr>
                            );
                            })}
                        </tbody>
                    </table>
                </div>
            </Card>
        </div>
    );
};

export default LabOrders;
