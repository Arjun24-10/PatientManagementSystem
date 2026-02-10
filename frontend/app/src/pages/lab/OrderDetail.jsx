import React from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, User, Activity, Calendar, FileText, CheckCircle, Upload } from 'lucide-react';
import Card from '../../components/common/Card';
import Button from '../../components/common/Button';
import Badge from '../../components/common/Badge';
import { mockLabOrders } from '../../mocks/labOrders';

const LabOrderDetail = () => {
    const { id } = useParams();
    const navigate = useNavigate();
    const order = mockLabOrders.find(o => o.id === id);

    if (!order) {
        return <div className="p-6 text-gray-900 dark:text-slate-100">Order not found</div>;
    }

    const handleCollectSample = () => {
        // Mock action
        alert('Sample marked as collected');
    };

    return (
        <div className="max-w-4xl mx-auto space-y-3">
            <Button
                variant="ghost"
                onClick={() => navigate('/dashboard/lab/orders')}
                className="text-gray-500 dark:text-slate-400 hover:text-gray-800 dark:hover:text-slate-200 text-xs"
            >
                <ArrowLeft className="w-3.5 h-3.5 mr-1.5" /> Back to Orders
            </Button>

            <div className="flex justify-between items-start">
                <div>
                    <h1 className="text-lg font-bold text-gray-800 dark:text-slate-100 flex items-center gap-2">
                        Order #{order.id}
                        <Badge type={order.status === 'Completed' ? 'green' : 'yellow'}>{order.status}</Badge>
                    </h1>
                    <p className="text-xs text-gray-500 dark:text-slate-400 mt-0.5">Ordered by {order.doctorName} on {new Date(order.orderDate).toLocaleDateString()}</p>
                </div>
                <div className="flex gap-2">
                    {order.status === 'Pending' && (
                        <Button onClick={handleCollectSample} className="bg-brand-medium">
                            <CheckCircle className="w-4 h-4 mr-2" /> Mark Sample Collected
                        </Button>
                    )}
                    {(order.status === 'Collected' || order.status === 'Results Pending') && (
                        <Button onClick={() => navigate('/dashboard/lab/upload')} className="bg-brand-medium">
                            <Upload className="w-4 h-4 mr-2" /> Upload Results
                        </Button>
                    )}
                </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <div className="md:col-span-2 space-y-3">
                    <Card className="p-3 dark:bg-slate-800">
                        <h3 className="text-sm font-bold text-gray-800 dark:text-slate-100 mb-2 flex items-center">
                            <Activity className="w-4 h-4 mr-1.5 text-brand-medium" /> Test Details
                        </h3>
                        <div className="grid grid-cols-2 gap-3">
                            <div>
                                <label className="text-xs text-gray-500 dark:text-slate-400 block mb-0.5">Test Type</label>
                                <p className="text-sm font-medium text-gray-900 dark:text-slate-100">{order.testType}</p>
                            </div>
                            <div>
                                <label className="text-xs text-gray-500 dark:text-slate-400 block mb-0.5">Priority</label>
                                <Badge type={order.priority === 'High' ? 'red' : 'gray'}>{order.priority}</Badge>
                            </div>
                            <div>
                                <label className="text-xs text-gray-500 dark:text-slate-400 block mb-0.5">Sample Type</label>
                                <p className="text-sm font-medium text-gray-900 dark:text-slate-100">{order.sampleType}</p>
                            </div>
                            <div>
                                <label className="text-xs text-gray-500 dark:text-slate-400 block mb-0.5">Notes</label>
                                <p className="text-xs text-gray-700 dark:text-slate-300">{order.notes || 'No notes provided'}</p>
                            </div>
                        </div>
                    </Card>

                    <Card className="p-3 dark:bg-slate-800">
                        <h3 className="text-sm font-bold text-gray-800 dark:text-slate-100 mb-2 flex items-center">
                            <Calendar className="w-4 h-4 mr-1.5 text-brand-medium" /> Timeline
                        </h3>
                        <div className="space-y-2">
                            <div className="flex gap-2">
                                <div className="flex flex-col items-center">
                                    <div className="w-2.5 h-2.5 rounded-full bg-green-500"></div>
                                    <div className="w-0.5 h-full bg-gray-200 dark:bg-slate-600"></div>
                                </div>
                                <div>
                                    <p className="text-xs font-medium text-gray-900 dark:text-slate-100">Order Placed</p>
                                    <p className="text-[10px] text-gray-500 dark:text-slate-400">{new Date(order.orderDate).toLocaleString()}</p>
                                </div>
                            </div>
                            {order.collectionDate && (
                                <div className="flex gap-2">
                                    <div className="flex flex-col items-center">
                                        <div className="w-2.5 h-2.5 rounded-full bg-blue-500"></div>
                                        <div className="w-0.5 h-full bg-gray-200 dark:bg-slate-600"></div>
                                    </div>
                                    <div>
                                        <p className="text-xs font-medium text-gray-900 dark:text-slate-100">Sample Collected</p>
                                        <p className="text-[10px] text-gray-500 dark:text-slate-400">{new Date(order.collectionDate).toLocaleString()}</p>
                                    </div>
                                </div>
                            )}
                            {order.completedDate && (
                                <div className="flex gap-2">
                                    <div className="flex flex-col items-center">
                                        <div className="w-2.5 h-2.5 rounded-full bg-brand-deep"></div>
                                    </div>
                                    <div>
                                        <p className="text-xs font-medium text-gray-900 dark:text-slate-100">Results Uploaded</p>
                                        <p className="text-[10px] text-gray-500 dark:text-slate-400">{new Date(order.completedDate).toLocaleString()}</p>
                                        <div className="mt-1">
                                            <Button variant="outline" size="sm" className="text-[10px]">
                                                <FileText className="w-3 h-3 mr-1" /> View Report
                                            </Button>
                                        </div>
                                    </div>
                                </div>
                            )}
                        </div>
                    </Card>
                </div>

                <div className="space-y-3">
                    <Card className="p-3 dark:bg-slate-800">
                        <h3 className="text-sm font-bold text-gray-800 dark:text-slate-100 mb-2 flex items-center">
                            <User className="w-4 h-4 mr-1.5 text-brand-medium" /> Patient Info
                        </h3>
                        <div className="space-y-2">
                            <div>
                                <label className="text-[10px] text-gray-500 dark:text-slate-400 uppercase font-semibold">Name</label>
                                <p className="text-sm font-medium text-gray-900 dark:text-slate-100">{order.patientName}</p>
                            </div>
                            <div>
                                <label className="text-[10px] text-gray-500 dark:text-slate-400 uppercase font-semibold">Patient ID</label>
                                <p className="text-sm font-medium text-gray-900 dark:text-slate-100">{order.patientId}</p>
                            </div>
                            <div className="p-2 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg text-[10px] text-yellow-800 dark:text-yellow-200 border border-yellow-200 dark:border-yellow-700">
                                <span className="font-bold block mb-0.5">Restricted Access</span>
                                Full medical history and unrelated diagnosis are hidden.
                            </div>
                        </div>
                    </Card>
                </div>
            </div>
        </div>
    );
};

export default LabOrderDetail;
