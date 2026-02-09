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
        <div className="space-y-6">
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
                <div>
                    <h2 className="text-2xl font-bold text-gray-800">Lab Technician Dashboard</h2>
                    <p className="text-gray-500">Welcome back, Tech Mike. Here's your daily overview.</p>
                </div>
                <div className="flex gap-3">
                    <Button variant="outline" onClick={() => navigate('/dashboard/lab/orders')}>View Orders</Button>
                    <Button onClick={() => navigate('/dashboard/lab/upload')}>Upload Results</Button>
                </div>
            </div>

            {/* Summary Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <Card className="p-6 border border-gray-100 shadow-soft hover:shadow-lg transition-shadow duration-300 flex items-center justify-between group cursor-pointer" onClick={() => navigate('/dashboard/lab/orders')}>
                    <div>
                        <h3 className="text-gray-500 text-sm font-medium">Pending Orders</h3>
                        <p className="text-3xl font-bold text-gray-800 mt-2 group-hover:text-brand-medium transition-colors">{pendingCount}</p>
                    </div>
                    <div className="w-12 h-12 bg-yellow-50 rounded-full flex items-center justify-center text-yellow-600 group-hover:scale-110 transition-transform">
                        <Clock className="w-6 h-6" />
                    </div>
                </Card>

                <Card className="p-6 border border-gray-100 shadow-soft hover:shadow-lg transition-shadow duration-300 flex items-center justify-between group cursor-pointer" onClick={() => navigate('/dashboard/lab/orders')}>
                    <div>
                        <h3 className="text-gray-500 text-sm font-medium">Samples Collected</h3>
                        <p className="text-3xl font-bold text-gray-800 mt-2 group-hover:text-brand-medium transition-colors">{collectedCount}</p>
                    </div>
                    <div className="w-12 h-12 bg-blue-50 rounded-full flex items-center justify-center text-blue-600 group-hover:scale-110 transition-transform">
                        <Activity className="w-6 h-6" />
                    </div>
                </Card>

                <Card className="p-6 border border-gray-100 shadow-soft hover:shadow-lg transition-shadow duration-300 flex items-center justify-between group cursor-pointer" onClick={() => navigate('/dashboard/lab/upload')}>
                    <div>
                        <h3 className="text-gray-500 text-sm font-medium">Results Pending</h3>
                        <p className="text-3xl font-bold text-gray-800 mt-2 group-hover:text-brand-medium transition-colors">{resultsPendingCount}</p>
                    </div>
                    <div className="w-12 h-12 bg-indigo-50 rounded-full flex items-center justify-center text-indigo-600 group-hover:scale-110 transition-transform">
                        <Upload className="w-6 h-6" />
                    </div>
                </Card>

                <Card className="p-6 border border-gray-100 shadow-soft hover:shadow-lg transition-shadow duration-300 flex items-center justify-between group cursor-pointer" onClick={() => navigate('/dashboard/lab/history')}>
                    <div>
                        <h3 className="text-gray-500 text-sm font-medium">Completed Today</h3>
                        <p className="text-3xl font-bold text-gray-800 mt-2 group-hover:text-brand-medium transition-colors">{completedCount}</p>
                    </div>
                    <div className="w-12 h-12 bg-green-50 rounded-full flex items-center justify-center text-green-600 group-hover:scale-110 transition-transform">
                        <CheckCircle className="w-6 h-6" />
                    </div>
                </Card>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                {/* Recent Activity Feed */}
                <div className="lg:col-span-2">
                    <Card className="p-6">
                        <h3 className="text-lg font-bold text-gray-800 mb-6">Recent Lab Activity</h3>
                        <div className="space-y-6">
                            {mockLabActivity.map((activity, index) => (
                                <div key={activity.id} className="flex relative">
                                    {index !== mockLabActivity.length - 1 && (
                                        <div className="absolute left-6 top-10 bottom-0 w-0.5 bg-gray-100"></div>
                                    )}
                                    <div className="w-12 h-12 rounded-full bg-gray-50 flex items-center justify-center text-gray-500 z-10 border-4 border-white shadow-sm">
                                        {activity.action.includes('Upload') ? <Upload size={18} /> :
                                            activity.action.includes('Collected') ? <Activity size={18} /> :
                                                activity.action.includes('Completed') ? <CheckCircle size={18} /> :
                                                    <FileText size={18} />}
                                    </div>
                                    <div className="ml-4 flex-1 pt-1">
                                        <div className="flex justify-between items-start">
                                            <h4 className="text-sm font-bold text-gray-900">{activity.action}</h4>
                                            <span className="text-xs text-gray-500 bg-gray-100 px-2 py-0.5 rounded-full">{activity.time}</span>
                                        </div>
                                        <p className="text-sm text-gray-600 mt-1">{activity.details}</p>
                                        <p className="text-xs text-gray-400 mt-1">by {activity.user}</p>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </Card>
                </div>

                {/* Quick Actions / Tips */}
                <div className="space-y-6">
                    <Card className="p-6 bg-gradient-to-br from-brand-deep to-brand-medium text-white">
                        <h3 className="font-bold text-lg mb-2">Priority Attention</h3>
                        <p className="text-blue-100 text-sm mb-4">You have 2 urgent samples that need processing within the next hour.</p>
                        <Button className="w-full bg-white text-brand-deep hover:bg-blue-50 border-none" onClick={() => navigate('/dashboard/lab/orders')}>
                            View Urgent Orders
                        </Button>
                    </Card>
                </div>
            </div>
        </div>
    );
};

export default LabDashboard;
