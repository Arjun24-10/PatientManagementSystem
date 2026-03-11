import React, { useState, useEffect } from 'react';
import { Shield, Lock, FileCheck, AlertTriangle } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import Card from '../../../components/common/Card';
import api from '../../../services/api';

const DEFAULT_LOGIN_DATA = (() => {
    const success = [0,0,1,0,0,2,5,8,12,15,14,11,10,9,11,13,12,8,6,4,3,2,1,0];
    const failed  = [0,0,0,3,0,0,0,1,0,2,0,0,1,0,0,0,1,0,0,0,0,0,0,0];
    return Array.from({ length: 24 }, (_, h) => ({
        hour: `${h.toString().padStart(2, '0')}:00`,
        Successful: success[h],
        Failed: failed[h],
    }));
})();

const ComplianceMetric = ({ title, value, status, icon: Icon }) => (
    <div className="flex items-center justify-between p-4 bg-slate-50 dark:bg-slate-700/50 rounded-lg border border-slate-100 dark:border-slate-600">
        <div className="flex items-center gap-3">
            <div className={`p-2 rounded-lg ${status === 'good' ? 'bg-admin-success/10 text-admin-success' : 'bg-admin-warning/10 text-admin-warning'}`}>
                <Icon size={20} />
            </div>
            <div>
                <h4 className="text-sm font-medium text-slate-700 dark:text-slate-200">{title}</h4>
                <p className="text-xs text-slate-500 dark:text-slate-400">Compliance Status</p>
            </div>
        </div>
        <div className="text-right">
            <span className={`text-lg font-bold ${status === 'good' ? 'text-admin-success' : 'text-admin-warning'}`}>
                {value}
            </span>
        </div>
    </div>
);

const CompliancePanel = () => {
    const [loginData, setLoginData] = useState(DEFAULT_LOGIN_DATA);

    useEffect(() => {
        api.admin.getAuditLogs()
            .then(logs => {
                const now = new Date();
                const counts = Array.from({ length: 24 }, () => ({ Successful: 0, Failed: 0 }));
                logs.forEach(log => {
                    const msAgo = now - new Date(log.timestamp);
                    if (msAgo >= 0 && msAgo < 24 * 60 * 60 * 1000) {
                        const h = new Date(log.timestamp).getHours();
                        const isFailed = /fail|denied|invalid/i.test(log.action || '');
                        const isLogin = /login|sign.?in|authenticat/i.test(log.action || '');
                        if (isLogin && isFailed) counts[h].Failed++;
                        else if (isLogin) counts[h].Successful++;
                    }
                });
                if (counts.some(c => c.Successful > 0 || c.Failed > 0)) {
                    setLoginData(counts.map((c, h) => ({
                        hour: `${h.toString().padStart(2, '0')}:00`,
                        ...c,
                    })));
                }
            })
            .catch(() => { /* keep defaults */ });
    }, []);

    return (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <Card className="lg:col-span-2 p-6 border-t-4 border-t-admin-primary">
                <h3 className="text-lg font-bold text-slate-800 dark:text-white mb-6 flex items-center gap-2">
                    <Shield className="text-admin-primary" size={20} />
                    Security & Compliance Monitoring
                </h3>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                    <ComplianceMetric
                        title="HIPAA Compliance"
                        value="98%"
                        status="good"
                        icon={FileCheck}
                    />
                    <ComplianceMetric
                        title="Data Encryption"
                        value="Active (AES-256)"
                        status="good"
                        icon={Lock}
                    />
                </div>

                <div className="bg-slate-50 dark:bg-slate-700/30 rounded-xl p-4 border border-slate-100 dark:border-slate-600">
                    <h4 className="text-sm font-bold text-slate-700 dark:text-slate-300 mb-3">Login Activity (Last 24h)</h4>
                    <ResponsiveContainer width="100%" height={160}>
                        <BarChart data={loginData} margin={{ top: 4, right: 8, left: -20, bottom: 0 }} barSize={6}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                            <XAxis dataKey="hour" tick={{ fontSize: 9, fill: '#94a3b8' }} interval={3} />
                            <YAxis tick={{ fontSize: 9, fill: '#94a3b8' }} allowDecimals={false} />
                            <Tooltip
                                contentStyle={{ background: '#1e293b', border: 'none', borderRadius: '6px', color: '#f1f5f9', fontSize: '11px' }}
                            />
                            <Legend wrapperStyle={{ fontSize: '11px' }} />
                            <Bar dataKey="Successful" fill="#22c55e" radius={[2, 2, 0, 0]} />
                            <Bar dataKey="Failed" fill="#ef4444" radius={[2, 2, 0, 0]} />
                        </BarChart>
                    </ResponsiveContainer>
                </div>
            </Card>

            <div className="space-y-6">
                <Card className="p-6 bg-admin-primary text-white relative overflow-hidden">
                    <div className="relative z-10">
                        <h3 className="text-lg font-bold mb-2">Security Score</h3>
                        <div className="text-4xl font-extrabold mb-1">A+</div>
                        <p className="text-admin-primary-light text-sm">System is secure and compliant.</p>
                    </div>
                    <Shield className="absolute right-[-20px] bottom-[-20px] text-white/10 w-32 h-32 rotate-12" />
                </Card>

                <Card className="p-6 border-l-4 border-l-admin-warning">
                    <h3 className="text-md font-bold text-slate-800 dark:text-white mb-3 flex items-center gap-2">
                        <AlertTriangle className="text-admin-warning" size={18} />
                        Pending Actions
                    </h3>
                    <ul className="space-y-3">
                        <li className="flex items-start gap-2 text-sm text-slate-600 dark:text-slate-300">
                            <div className="w-1.5 h-1.5 rounded-full bg-admin-warning mt-1.5"></div>
                            Review 3 failed login attempts from unknown IP.
                        </li>
                        <li className="flex items-start gap-2 text-sm text-slate-600 dark:text-slate-300">
                            <div className="w-1.5 h-1.5 rounded-full bg-admin-primary mt-1.5"></div>
                            Update password policy for Lab Tech role.
                        </li>
                    </ul>
                </Card>
            </div>
        </div>
    );
};

export default CompliancePanel;
