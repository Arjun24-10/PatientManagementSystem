import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Activity, Clock, FileText, CheckCircle, Upload } from 'lucide-react';
import Card from '../../components/common/Card';
import Button from '../../components/common/Button';
import { mockLabOrders, mockLabActivity } from '../../mocks/labOrders';

const LabDashboard = () => {
    const navigate = useNavigate();

    const pendingCount = mockLabOrders.filter(o => o.status === 'Pending').length;
    const collectedCount = mockLabOrders.filter(o => o.status === 'Collected').length;
    const resultsPendingCount = mockLabOrders.filter(o => o.status === 'Results Pending').length;
    const completedCount = mockLabOrders.filter(o => o.status === 'Completed').length;

    return (
        <div className="space-y-3">
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-2">
                <div>
                    <h2 className="text-lg font-bold text-gray-800 dark:text-slate-100">Lab Technician Dashboard</h2>
                    <p className="text-xs text-gray-500 dark:text-slate-400">Welcome back, Tech Mike. Here's your daily overview.</p>
                </div>
                <div className="flex gap-2">
                    <Button variant="outline" onClick={() => navigate('/dashboard/lab/orders')}>View Orders</Button>
                    <Button onClick={() => navigate('/dashboard/lab/upload')}>Upload Results</Button>
                </div>
            </div>

            {/* Summary Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
                <Card className="p-3 border border-gray-100 dark:border-slate-700 shadow-soft hover:shadow-lg transition-shadow duration-300 flex items-center justify-between group cursor-pointer dark:bg-slate-800" onClick={() => navigate('/dashboard/lab/orders')}>
                    <div>
                        <h3 className="text-gray-500 dark:text-slate-400 text-xs font-medium">Pending Orders</h3>
                        <p className="text-xl font-bold text-gray-800 dark:text-slate-100 mt-1 group-hover:text-brand-medium transition-colors">{pendingCount}</p>
                    </div>
                    <div className="w-8 h-8 bg-yellow-50 dark:bg-yellow-900/20 rounded-full flex items-center justify-center text-yellow-600 dark:text-yellow-400 group-hover:scale-110 transition-transform">
                        <Clock className="w-4 h-4" />
                    </div>
                </Card>

                <Card className="p-3 border border-gray-100 dark:border-slate-700 shadow-soft hover:shadow-lg transition-shadow duration-300 flex items-center justify-between group cursor-pointer dark:bg-slate-800" onClick={() => navigate('/dashboard/lab/orders')}>
                    <div>
                        <h3 className="text-gray-500 dark:text-slate-400 text-xs font-medium">Samples Collected</h3>
                        <p className="text-xl font-bold text-gray-800 dark:text-slate-100 mt-1 group-hover:text-brand-medium transition-colors">{collectedCount}</p>
                    </div>
                    <div className="w-8 h-8 bg-blue-50 dark:bg-blue-900/20 rounded-full flex items-center justify-center text-blue-600 dark:text-blue-400 group-hover:scale-110 transition-transform">
                        <Activity className="w-4 h-4" />
                    </div>
                </Card>

                <Card className="p-3 border border-gray-100 dark:border-slate-700 shadow-soft hover:shadow-lg transition-shadow duration-300 flex items-center justify-between group cursor-pointer dark:bg-slate-800" onClick={() => navigate('/dashboard/lab/upload')}>
                    <div>
                        <h3 className="text-gray-500 dark:text-slate-400 text-xs font-medium">Results Pending</h3>
                        <p className="text-xl font-bold text-gray-800 dark:text-slate-100 mt-1 group-hover:text-brand-medium transition-colors">{resultsPendingCount}</p>
                    </div>
                    <div className="w-8 h-8 bg-indigo-50 dark:bg-indigo-900/20 rounded-full flex items-center justify-center text-indigo-600 dark:text-indigo-400 group-hover:scale-110 transition-transform">
                        <Upload className="w-4 h-4" />
                    </div>
                </Card>

                <Card className="p-3 border border-gray-100 dark:border-slate-700 shadow-soft hover:shadow-lg transition-shadow duration-300 flex items-center justify-between group cursor-pointer dark:bg-slate-800" onClick={() => navigate('/dashboard/lab/history')}>
                    <div>
                        <h3 className="text-gray-500 dark:text-slate-400 text-xs font-medium">Completed Today</h3>
                        <p className="text-xl font-bold text-gray-800 dark:text-slate-100 mt-1 group-hover:text-brand-medium transition-colors">{completedCount}</p>
                    </div>
                    <div className="w-8 h-8 bg-green-50 dark:bg-green-900/20 rounded-full flex items-center justify-center text-green-600 dark:text-green-400 group-hover:scale-110 transition-transform">
                        <CheckCircle className="w-4 h-4" />
                    </div>
                </Card>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                {/* Recent Activity Feed */}
                <div className="lg:col-span-2">
                    <Card className="p-3 dark:bg-slate-800">
                        <h3 className="text-sm font-bold text-gray-800 dark:text-slate-100 mb-3">Recent Lab Activity</h3>
                        <div className="space-y-3">
                            {mockLabActivity.map((activity, index) => (
                                <div key={activity.id} className="flex relative">
                                    {index !== mockLabActivity.length - 1 && (
                                        <div className="absolute left-4 top-8 bottom-0 w-0.5 bg-gray-100 dark:bg-slate-700"></div>
                                    )}
                                    <div className="w-8 h-8 rounded-full bg-gray-50 dark:bg-slate-700 flex items-center justify-center text-gray-500 dark:text-slate-400 z-10 border-2 border-white dark:border-slate-800 shadow-sm">
                                        {activity.action.includes('Upload') ? <Upload size={14} /> :
                                            activity.action.includes('Collected') ? <Activity size={14} /> :
                                                activity.action.includes('Completed') ? <CheckCircle size={14} /> :
                                                    <FileText size={14} />}
                                    </div>
                                    <div className="ml-2.5 flex-1 pt-0.5">
                                        <div className="flex justify-between items-start">
                                            <h4 className="text-xs font-bold text-gray-900 dark:text-slate-100">{activity.action}</h4>
                                            <span className="text-[10px] text-gray-500 dark:text-slate-400 bg-gray-100 dark:bg-slate-700 px-1.5 py-0.5 rounded-full">{activity.time}</span>
                                        </div>
                                        <p className="text-xs text-gray-600 dark:text-slate-300 mt-0.5">{activity.details}</p>
                                        <p className="text-[10px] text-gray-400 dark:text-slate-500 mt-0.5">by {activity.user}</p>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </Card>
                </div>

                {/* Quick Actions / Tips */}
                <div className="space-y-3">
                    <Card className="p-3 bg-gradient-to-br from-brand-deep to-brand-medium text-white">
                        <h3 className="font-bold text-sm mb-1">Priority Attention</h3>
                        <p className="text-blue-100 text-xs mb-2">You have 2 urgent samples that need processing within the next hour.</p>
                        <Button className="w-full bg-white text-brand-deep hover:bg-blue-50 border-none text-xs" onClick={() => navigate('/dashboard/lab/orders')}>
                            View Urgent Orders
                        </Button>
                    </Card>
                </div>
            </div>
        </div>
    );
};

export default LabDashboard;
