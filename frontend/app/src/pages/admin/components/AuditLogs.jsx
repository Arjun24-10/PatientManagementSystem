import React, { useState } from 'react';
import { FileText, Download, Filter } from 'lucide-react';
import Card from '../../../components/common/Card';
import Button from '../../../components/common/Button';
import { Table, TableHead, TableBody, TableRow, TableHeader, TableCell } from '../../../components/common/Table';

const AuditLogs = () => {
    const [logs] = useState([
        { id: 1023, user: 'Dr. Sarah Smith', action: 'Viewed Patient Record (ID: 4521)', ip: '192.168.1.10', time: '2024-02-10 10:45 AM' },
        { id: 1022, user: 'Admin User', action: 'Modified User Role (Nurse Joy)', ip: '192.168.1.5', time: '2024-02-10 10:30 AM' },
        { id: 1021, user: 'System', action: 'Daily Backup Completed', ip: 'localhost', time: '2024-02-10 02:00 AM' },
        { id: 1020, user: 'Nurse Joy', action: 'Updated Vitals (ID: 4521)', ip: '192.168.1.12', time: '2024-02-09 05:15 PM' },
        { id: 1019, user: 'Lab Tech Mike', action: 'Uploaded Lab Results (ID: 4521)', ip: '192.168.1.15', time: '2024-02-09 04:30 PM' },
    ]);

    return (
        <Card className="border-t-4 border-t-slate-500">
            <div className="p-6 border-b border-gray-100 dark:border-slate-700 flex justify-between items-center">
                <div className="flex items-center gap-3">
                    <div className="p-2 bg-slate-100 dark:bg-slate-700 rounded-lg text-slate-600 dark:text-slate-300">
                        <FileText size={20} />
                    </div>
                    <div>
                        <h2 className="text-lg font-bold text-slate-800 dark:text-white">Audit Logs</h2>
                        <p className="text-sm text-slate-500 dark:text-slate-400">Recent system activities</p>
                    </div>
                </div>
                <div className="flex gap-2">
                    <Button variant="outline" className="flex items-center gap-2 text-sm">
                        <Filter size={16} /> Filter
                    </Button>
                    <Button variant="outline" className="flex items-center gap-2 text-sm">
                        <Download size={16} /> Export
                    </Button>
                </div>
            </div>

            <Table>
                <TableHead>
                    <TableRow>
                        <TableHeader>Time</TableHeader>
                        <TableHeader>User</TableHeader>
                        <TableHeader>Action</TableHeader>
                        <TableHeader>IP Address</TableHeader>
                    </TableRow>
                </TableHead>
                <TableBody>
                    {logs.map((log) => (
                        <TableRow key={log.id} hover>
                            <TableCell>
                                <span className="text-sm text-slate-500 whitespace-nowrap">{log.time}</span>
                            </TableCell>
                            <TableCell>
                                <div className="flex items-center gap-2">
                                    <div className="w-6 h-6 rounded-full bg-admin-primary/10 flex items-center justify-center text-xs font-bold text-admin-primary">
                                        {log.user.charAt(0)}
                                    </div>
                                    <span className="font-medium text-slate-800 dark:text-white">{log.user}</span>
                                </div>
                            </TableCell>
                            <TableCell>
                                <span className="text-sm text-slate-600 dark:text-slate-300">{log.action}</span>
                            </TableCell>
                            <TableCell>
                                <span className="font-mono text-xs text-slate-400">{log.ip}</span>
                            </TableCell>
                        </TableRow>
                    ))}
                </TableBody>
            </Table>
        </Card>
    );
};

export default AuditLogs;
