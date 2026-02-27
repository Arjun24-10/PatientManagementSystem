import React from 'react';
import { Server, Database, Activity, Cpu } from 'lucide-react';
import Card from '../../../components/common/Card';

const HealthMetric = ({ label, value, status, icon: Icon }) => (
    <div className="flex items-center justify-between p-3 bg-slate-50 dark:bg-slate-700/50 rounded-lg">
        <div className="flex items-center gap-3">
            <Icon size={18} className="text-slate-400" />
            <span className="text-sm font-medium text-slate-600 dark:text-slate-300">{label}</span>
        </div>
        <div className="flex items-center gap-2">
            <span className="font-bold text-slate-800 dark:text-white">{value}</span>
            <div className={`w-2 h-2 rounded-full ${status === 'good' ? 'bg-admin-success' : 'bg-admin-warning'}`}></div>
        </div>
    </div>
);

const SystemHealth = () => {
    return (
        <Card className="p-6 border-t-4 border-t-admin-success">
            <div className="flex items-center justify-between mb-6">
                <h3 className="text-lg font-bold text-slate-800 dark:text-white flex items-center gap-2">
                    <Activity className="text-admin-success" size={20} />
                    System Health
                </h3>
                <span className="px-2 py-1 bg-admin-success/10 text-admin-success text-xs font-bold rounded-full">Operational</span>
            </div>

            <div className="space-y-6">
                <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                        <span className="text-slate-500">Server Load</span>
                        <span className="font-medium text-slate-700 dark:text-slate-200">34%</span>
                    </div>
                    <div className="h-2 bg-slate-100 dark:bg-slate-700 rounded-full overflow-hidden">
                        <div className="h-full bg-admin-success w-[34%]"></div>
                    </div>
                </div>

                <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                        <span className="text-slate-500">Memory Usage</span>
                        <span className="font-medium text-slate-700 dark:text-slate-200">62%</span>
                    </div>
                    <div className="h-2 bg-slate-100 dark:bg-slate-700 rounded-full overflow-hidden">
                        <div className="h-full bg-admin-primary w-[62%]"></div>
                    </div>
                </div>

                <div className="space-y-3 pt-4 border-t border-slate-100 dark:border-slate-700">
                    <HealthMetric label="API Response" value="45ms" status="good" icon={Server} />
                    <HealthMetric label="Database" value="Connected" status="good" icon={Database} />
                    <HealthMetric label="CPU Core 1" value="12%" status="good" icon={Cpu} />
                </div>
            </div>
        </Card>
    );
};

export default SystemHealth;
