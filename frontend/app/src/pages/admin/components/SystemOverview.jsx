import React, { useState, useEffect } from 'react';
import { Users, Shield, Activity, Clock, ArrowUp, ArrowDown } from 'lucide-react';
import Card from '../../../components/common/Card';
import api from '../../../services/api';

const StatCard = ({ title, value, change, icon: Icon, trend }) => (
    <Card className="p-6 border-l-4 border-l-admin-primary bg-white dark:bg-slate-800 hover:shadow-lg transition-all duration-300">
        <div className="flex justify-between items-start">
            <div>
                <p className="text-sm font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">{title}</p>
                <h3 className="text-3xl font-bold text-slate-800 dark:text-white mt-2">{value}</h3>
            </div>
            <div className={`p-3 rounded-xl bg-admin-primary/10 text-admin-primary`}>
                <Icon size={24} />
            </div>
        </div>
        <div className="mt-4 flex items-center text-sm">
            <span className={`flex items-center font-medium ${trend === 'up' ? 'text-admin-success' : 'text-admin-danger'}`}>
                {trend === 'up' ? <ArrowUp size={16} className="mr-1" /> : <ArrowDown size={16} className="mr-1" />}
                {change}
            </span>
            <span className="text-slate-400 ml-2">vs last month</span>
        </div>
    </Card>
);

const SystemOverview = () => {
    const [stats, setStats] = useState({
        totalPatients: 0,
        totalDoctors: 0,
        todaysAppointments: 0,
        pendingApprovals: 0,
    });
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchSystemStats();
    }, []);

    const fetchSystemStats = async () => {
        try {
            setLoading(true);
            const metrics = await api.admin.getMetrics();
            setStats({
                totalPatients: metrics.totalPatients,
                totalDoctors: metrics.totalDoctors,
                todaysAppointments: metrics.todaysAppointments,
                pendingApprovals: metrics.pendingApprovals,
            });
        } catch (err) {
            console.log('Using mock system stats');
            setStats({
                totalPatients: 5,
                totalDoctors: 2,
                todaysAppointments: 3,
                pendingApprovals: 5,
            });
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="space-y-6">


            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <StatCard
                    title="Total Patients"
                    value={loading ? '...' : stats.totalPatients.toLocaleString()}
                    change="12%"
                    trend="up"
                    icon={Users}
                />
                <StatCard
                    title="Total Doctors"
                    value={loading ? '...' : stats.totalDoctors}
                    change="5%"
                    trend="up"
                    icon={Activity}
                />
                <StatCard
                    title="Pending Approvals"
                    value={loading ? '...' : stats.pendingApprovals}
                    change="2%"
                    trend="down"
                    icon={Shield}
                />
                <StatCard
                    title="Today's Appointments"
                    value={loading ? '...' : stats.todaysAppointments}
                    change="0%"
                    trend="up"
                    icon={Clock}
                />
            </div>

            {/* Placeholder for a chart or detailed breakdown can go here */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <Card className="lg:col-span-2 p-6 bg-white dark:bg-slate-800">
                    <h3 className="text-lg font-bold text-slate-800 dark:text-white mb-4">Traffic Overview</h3>
                    <div className="h-64 flex items-center justify-center bg-slate-50 dark:bg-slate-700/50 rounded-lg border border-dashed border-slate-300 dark:border-slate-600">
                        <p className="text-slate-500 dark:text-slate-400">Traffic Chart Placeholder</p>
                    </div>
                </Card>

                <Card className="p-6 bg-white dark:bg-slate-800">
                    <h3 className="text-lg font-bold text-slate-800 dark:text-white mb-4">Device Usage</h3>
                    <div className="space-y-4">
                        <div className="flex justify-between items-center">
                            <span className="text-slate-600 dark:text-slate-300">Desktop</span>
                            <div className="w-2/3 h-2 bg-slate-100 dark:bg-slate-700 rounded-full overflow-hidden">
                                <div className="h-full bg-admin-primary w-[65%]"></div>
                            </div>
                            <span className="text-sm font-medium text-slate-800 dark:text-white">65%</span>
                        </div>
                        <div className="flex justify-between items-center">
                            <span className="text-slate-600 dark:text-slate-300">Mobile</span>
                            <div className="w-2/3 h-2 bg-slate-100 dark:bg-slate-700 rounded-full overflow-hidden">
                                <div className="h-full bg-admin-secondary w-[25%]"></div>
                            </div>
                            <span className="text-sm font-medium text-slate-800 dark:text-white">25%</span>
                        </div>
                        <div className="flex justify-between items-center">
                            <span className="text-slate-600 dark:text-slate-300">Tablet</span>
                            <div className="w-2/3 h-2 bg-slate-100 dark:bg-slate-700 rounded-full overflow-hidden">
                                <div className="h-full bg-admin-success w-[10%]"></div>
                            </div>
                            <span className="text-sm font-medium text-slate-800 dark:text-white">10%</span>
                        </div>
                    </div>
                </Card>
            </div>
        </div>
    );
};

export default SystemOverview;
