import React, { useState } from 'react';
import { Search, Filter, MoreVertical, Edit, Trash2, Shield, UserCheck, UserX, Key } from 'lucide-react';
import Card from '../../../components/common/Card';
import Badge from '../../../components/common/Badge';
import Button from '../../../components/common/Button';
import { Table, TableHead, TableBody, TableRow, TableHeader, TableCell } from '../../../components/common/Table';

const UserManagement = () => {
    const [users] = useState([
        { id: 1, name: 'Dr. Sarah Smith', email: 'sarah.smith@hospital.com', role: 'Doctor', status: 'Active', lastLogin: '2 mins ago' },
        { id: 2, name: 'John Doe', email: 'john.doe@email.com', role: 'Patient', status: 'Active', lastLogin: '1 hour ago' },
        { id: 3, name: 'Nurse Joy', email: 'joy@hospital.com', role: 'Nurse', status: 'Away', lastLogin: '5 hours ago' },
        { id: 4, name: 'Mike Tech', email: 'mike@lab.com', role: 'Lab Tech', status: 'Inactive', lastLogin: '2 days ago' },
        { id: 5, name: 'Admin User', email: 'admin@system.com', role: 'Admin', status: 'Active', lastLogin: 'Just now' },
    ]);

    const getRoleBadgeVariant = (role) => {
        switch (role) {
            case 'Admin': return 'red'; // Red/Danger for high privilege
            case 'Doctor': return 'blue'; // Blue
            case 'Nurse': return 'green'; // Green
            case 'Lab Tech': return 'yellow'; // Orange
            default: return 'gray'; // Gray
        }
    };

    const getStatusColor = (status) => {
        switch (status) {
            case 'Active': return 'text-admin-success bg-admin-success/10';
            case 'Away': return 'text-admin-warning bg-admin-warning/10';
            case 'Inactive': return 'text-slate-500 bg-slate-100 dark:bg-slate-700';
            default: return 'text-slate-500';
        }
    };

    return (
        <Card className="border-t-4 border-t-admin-secondary">
            <div className="p-6 border-b border-gray-100 dark:border-slate-700 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                    <h2 className="text-lg font-bold text-slate-800 dark:text-white">User Management</h2>
                    <p className="text-sm text-slate-500 dark:text-slate-400">Manage access and roles</p>
                </div>

                <div className="flex items-center gap-3">
                    <div className="relative">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" size={18} />
                        <input
                            type="text"
                            placeholder="Search users..."
                            className="pl-10 pr-4 py-2 border border-slate-200 dark:border-slate-700 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-admin-primary dark:bg-slate-800 dark:text-white"
                        />
                    </div>
                    <Button variant="outline" className="flex items-center gap-2">
                        <Filter size={16} /> Filter
                    </Button>
                    <Button className="bg-admin-primary hover:bg-admin-secondary text-white">
                        + Add User
                    </Button>
                </div>
            </div>

            <Table>
                <TableHead>
                    <TableRow>
                        <TableHeader>User</TableHeader>
                        <TableHeader>Role</TableHeader>
                        <TableHeader>Status</TableHeader>
                        <TableHeader>Last Login</TableHeader>
                        <TableHeader align="right">Actions</TableHeader>
                    </TableRow>
                </TableHead>
                <TableBody>
                    {users.map((user) => (
                        <TableRow key={user.id} hover>
                            <TableCell>
                                <div className="flex items-center gap-3">
                                    <div className="w-10 h-10 rounded-full bg-admin-primary/10 flex items-center justify-center text-admin-primary font-bold">
                                        {user.name.charAt(0)}
                                    </div>
                                    <div>
                                        <div className="font-medium text-slate-900 dark:text-white">{user.name}</div>
                                        <div className="text-xs text-slate-500">{user.email}</div>
                                    </div>
                                </div>
                            </TableCell>
                            <TableCell>
                                <Badge type={getRoleBadgeVariant(user.role)}>{user.role}</Badge>
                            </TableCell>
                            <TableCell>
                                <span className={`px-2 py-1 rounded-full text-xs font-semibold ${getStatusColor(user.status)}`}>
                                    {user.status}
                                </span>
                            </TableCell>
                            <TableCell>
                                <span className="text-slate-600 dark:text-slate-300">{user.lastLogin}</span>
                            </TableCell>
                            <TableCell align="right">
                                <div className="flex items-center justify-end gap-2">
                                    <button className="p-2 text-slate-400 hover:text-admin-primary hover:bg-admin-primary/5 rounded-full transition-colors" title="Edit">
                                        <Edit size={16} />
                                    </button>
                                    <button className="p-2 text-slate-400 hover:text-admin-warning hover:bg-admin-warning/5 rounded-full transition-colors" title="Reset Password">
                                        <Key size={16} />
                                    </button>
                                    {user.status === 'Active' ? (
                                        <button className="p-2 text-slate-400 hover:text-admin-danger hover:bg-admin-danger/5 rounded-full transition-colors" title="Deactivate">
                                            <UserX size={16} />
                                        </button>
                                    ) : (
                                        <button className="p-2 text-slate-400 hover:text-admin-success hover:bg-admin-success/5 rounded-full transition-colors" title="Activate">
                                            <UserCheck size={16} />
                                        </button>
                                    )}
                                </div>
                            </TableCell>
                        </TableRow>
                    ))}
                </TableBody>
            </Table>
        </Card>
    );
};

export default UserManagement;
