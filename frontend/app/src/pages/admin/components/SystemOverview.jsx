import React, { useState, useEffect } from 'react';
import { Users, Shield, Activity, Clock, ArrowUp, ArrowDown } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
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
    const [trafficData] = useState(() => {
        // Deterministic 7-day fallback; overridden by audit log data when available
        const staticRequests = [142, 98, 165, 120, 178, 52, 38];
        return Array.from({ length: 7 }, (_, i) => {
            const d = new Date();
            d.setDate(d.getDate() - (6 - i));
            return {
                day: d.toLocaleDateString('en', { weekday: 'short' }),
                requests: staticRequests[i],
            };
        });
    });
    const [liveTrafficData, setLiveTrafficData] = useState(null);

    useEffect(() => {
        fetchSystemStats();
    }, []);

    const fetchSystemStats = async () => {
        try {
            setLoading(true);
            const [metricsResult, logsResult] = await Promise.allSettled([
                api.admin.getMetrics(),
                api.admin.getAuditLogs(),
            ]);
            if (metricsResult.status === 'fulfilled') {
                const metrics = metricsResult.value;
                setStats({
                    totalPatients: metrics.totalPatients,
                    totalDoctors: metrics.totalDoctors,
                    todaysAppointments: metrics.todaysAppointments,
                    pendingApprovals: metrics.pendingApprovals,
                });
            } else {
                setStats({ totalPatients: 5, totalDoctors: 2, todaysAppointments: 3, pendingApprovals: 5 });
            }
            if (logsResult.status === 'fulfilled' && logsResult.value.length > 0) {
                const now = new Date();
                const counts = Array(7).fill(0);
                logsResult.value.forEach(log => {
                    const daysAgo = Math.floor((now - new Date(log.timestamp)) / (1000 * 60 * 60 * 24));
                    if (daysAgo >= 0 && daysAgo < 7) counts[6 - daysAgo]++;
                });
                if (counts.some(c => c > 0)) {
                    setLiveTrafficData(Array.from({ length: 7 }, (_, i) => {
                        const d = new Date();
                        d.setDate(d.getDate() - (6 - i));
                        return { day: d.toLocaleDateString('en', { weekday: 'short' }), requests: counts[i] };
                    }));
                }
            }
        } catch (err) {
            console.log('Using mock system stats');
            setStats({ totalPatients: 5, totalDoctors: 2, todaysAppointments: 3, pendingApprovals: 5 });
        } finally {
            setLoading(false);
        }
    };

    const chartData = liveTrafficData || trafficData;

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

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <Card className="lg:col-span-2 p-6 bg-white dark:bg-slate-800">
                    <h3 className="text-lg font-bold text-slate-800 dark:text-white mb-4">Traffic Overview (Last 7 Days)</h3>
                    <ResponsiveContainer width="100%" height={240}>
                        <AreaChart data={chartData} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
                            <defs>
                                <linearGradient id="trafficGradient" x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                                </linearGradient>
                            </defs>
                            <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                            <XAxis dataKey="day" tick={{ fontSize: 12, fill: '#94a3b8' }} />
                            <YAxis tick={{ fontSize: 12, fill: '#94a3b8' }} allowDecimals={false} />
                            <Tooltip
                                contentStyle={{ background: '#1e293b', border: 'none', borderRadius: '8px', color: '#f1f5f9', fontSize: '12px' }}
                                formatter={(value) => [value, 'API Requests']}
                            />
                            <Area type="monotone" dataKey="requests" stroke="#3b82f6" strokeWidth={2} fill="url(#trafficGradient)" />
                        </AreaChart>
                    </ResponsiveContainer>
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
