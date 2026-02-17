import React, { useState } from 'react';
import { AlertCircle, CheckCircle, Clock, MoreHorizontal } from 'lucide-react';
import Card from '../../../components/common/Card';
import Badge from '../../../components/common/Badge';
import { Table, TableHead, TableBody, TableRow, TableHeader, TableCell } from '../../../components/common/Table';

const IncidentManagement = () => {
    const [incidents] = useState([
        { id: 'INC-2024-001', type: 'Failed Login', severity: 'Medium', status: 'Open', assigned: 'Admin', time: '10 mins ago' },
        { id: 'INC-2024-002', type: 'Data Access', severity: 'Critical', status: 'Investigating', assigned: 'Security Team', time: '2 hours ago' },
        { id: 'INC-2024-003', type: 'System Error', severity: 'Low', status: 'Resolved', assigned: 'DevOps', time: '1 day ago' },
    ]);

    const getSeverityColor = (severity) => {
        switch (severity) {
            case 'Critical': return 'bg-admin-danger/20 text-admin-danger border-admin-danger/20';
            case 'High': return 'bg-orange-100 text-orange-700 border-orange-200';
            case 'Medium': return 'bg-yellow-100 text-yellow-700 border-yellow-200';
            case 'Low': return 'bg-blue-100 text-blue-700 border-blue-200';
            default: return 'bg-gray-100 text-gray-700';
        }
    };

    const getStatusBadge = (status) => {
        switch (status) {
            case 'Open': return <Badge type="yellow">Open</Badge>;
            case 'Investigating': return <Badge type="blue">Investigating</Badge>;
            case 'Resolved': return <Badge type="green">Resolved</Badge>;
            default: return <Badge>Unknown</Badge>;
        }
    };

    return (
        <Card className="border-t-4 border-t-admin-danger">
            <div className="p-6 border-b border-gray-100 dark:border-slate-700 flex justify-between items-center">
                <div>
                    <h2 className="text-lg font-bold text-slate-800 dark:text-white">Incident Response</h2>
                    <p className="text-sm text-slate-500 dark:text-slate-400">Track and resolve security incidents</p>
                </div>
                <button className="text-admin-primary text-sm font-medium hover:underline">View All Incidents</button>
            </div>

            <Table>
                <TableHead>
                    <TableRow>
                        <TableHeader>ID</TableHeader>
                        <TableHeader>Type</TableHeader>
                        <TableHeader>Severity</TableHeader>
                        <TableHeader>Status</TableHeader>
                        <TableHeader>Assigned To</TableHeader>
                        <TableHeader>Time</TableHeader>
                        <TableHeader align="right">Actions</TableHeader>
                    </TableRow>
                </TableHead>
                <TableBody>
                    {incidents.map((incident) => (
                        <TableRow key={incident.id} hover>
                            <TableCell>
                                <span className="font-mono text-xs font-semibold text-slate-600 dark:text-slate-300">{incident.id}</span>
                            </TableCell>
                            <TableCell>
                                <span className="font-medium text-slate-800 dark:text-white">{incident.type}</span>
                            </TableCell>
                            <TableCell>
                                <span className={`px-2 py-0.5 rounded text-xs font-bold border ${getSeverityColor(incident.severity)}`}>
                                    {incident.severity}
                                </span>
                            </TableCell>
                            <TableCell>
                                {getStatusBadge(incident.status)}
                            </TableCell>
                            <TableCell>
                                <div className="flex items-center gap-2">
                                    <div className="w-5 h-5 rounded-full bg-slate-200 text-xs flex items-center justify-center text-slate-600 font-bold">
                                        {incident.assigned.charAt(0)}
                                    </div>
                                    <span className="text-sm text-slate-600 dark:text-slate-300">{incident.assigned}</span>
                                </div>
                            </TableCell>
                            <TableCell>
                                <span className="text-xs text-slate-500">{incident.time}</span>
                            </TableCell>
                            <TableCell align="right">
                                <button className="p-1 text-slate-400 hover:text-admin-primary transition-colors">
                                    <MoreHorizontal size={18} />
                                </button>
                            </TableCell>
                        </TableRow>
                    ))}
                </TableBody>
            </Table>
        </Card>
    );
};

export default IncidentManagement;
