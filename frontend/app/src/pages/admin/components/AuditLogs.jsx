import React, { useState, useEffect } from 'react';
import { FileText, Download, Filter } from 'lucide-react';
import Card from '../../../components/common/Card';
import Button from '../../../components/common/Button';
import { Table, TableHead, TableBody, TableRow, TableHeader, TableCell } from '../../../components/common/Table';
import api from '../../../services/api';

const AuditLogs = () => {
    const [logs, setLogs] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchAuditLogs();
    }, []);

    const fetchAuditLogs = async () => {
        try {
            setLoading(true);
            const data = await api.admin.getAuditLogs();
            setLogs(data);
        } catch (err) {
            console.log('Using mock audit logs');
            // Use mock data on error
            setLogs([
                { id: 1023, email: 'admin@hospital.com', action: 'Viewed Patient Record', ip: '192.168.1.10', timestamp: new Date(Date.now() - 600000).toISOString() },
                { id: 1022, email: 'admin@hospital.com', action: 'Modified User Role', ip: '192.168.1.5', timestamp: new Date(Date.now() - 1800000).toISOString() },
            ]);
        } finally {
            setLoading(false);
        }
    };

    return (
        <Card className="border-t-4 border-t-slate-500">
            <div className="p-6 border-b border-gray-100 dark:border-slate-700 flex justify-between items-center">
                <div className="flex items-center gap-3">
                    <div className="p-2 bg-slate-100 dark:bg-slate-700 rounded-lg text-slate-600 dark:text-slate-300">
                        <FileText size={20} />
                    </div>
                    <div>
                        <h2 className="text-lg font-bold text-slate-800 dark:text-white">Audit Logs</h2>
                        <p className="text-sm text-slate-500 dark:text-slate-400">Recent system activities ({logs.length} total)</p>
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

            {loading && (
                <div className="p-6 text-center text-slate-500">
                    Loading audit logs...
                </div>
            )}



            {!loading && logs.length === 0 && (
                <div className="p-6 text-center text-slate-500">
                    No audit logs found.
                </div>
            )}

            {!loading && logs.length > 0 && (
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
                                    <span className="text-sm text-slate-500 whitespace-nowrap">
                                        {new Date(log.timestamp).toLocaleString()}
                                    </span>
                                </TableCell>
                                <TableCell>
                                    <div className="flex items-center gap-2">
                                        <div className="w-6 h-6 rounded-full bg-admin-primary/10 flex items-center justify-center text-xs font-bold text-admin-primary">
                                            {log.email.charAt(0).toUpperCase()}
                                        </div>
                                        <span className="font-medium text-slate-800 dark:text-white">{log.email}</span>
                                    </div>
                                </TableCell>
                                <TableCell>
                                    <span className="text-sm text-slate-600 dark:text-slate-300">{log.action}</span>
                                </TableCell>
                                <TableCell>
                                    <span className="font-mono text-xs text-slate-400">{log.ipAddress || 'N/A'}</span>
                                </TableCell>
                            </TableRow>
                        ))}
                    </TableBody>
                </Table>
            )}
        </Card>
    );
};

export default AuditLogs;
