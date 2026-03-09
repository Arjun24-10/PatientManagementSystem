import React, { useState, useEffect } from 'react';
import { Search, Filter, MoreVertical, Edit } from 'lucide-react';
import Card from '../../../components/common/Card';
import Badge from '../../../components/common/Badge';
import Button from '../../../components/common/Button';
import { Table, TableHead, TableBody, TableRow, TableHeader, TableCell } from '../../../components/common/Table';
import api from '../../../services/api';

const UserManagement = () => {
    const [users, setUsers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [searchTerm, setSearchTerm] = useState('');

    useEffect(() => {
        fetchUsers();
    }, []);

    const fetchUsers = async () => {
        try {
            setLoading(true);
            const data = await api.admin.getAllStaff();
            setUsers(data);
        } catch (err) {
            console.log('Using mock users');
            // Use mock data on error — fields match StaffDTO: userId, email, role
            setUsers([
                { userId: 1, email: 'doctor1@securehealth.com', role: 'DOCTOR' },
                { userId: 2, email: 'nurse1@securehealth.com', role: 'NURSE' },
                { userId: 3, email: 'lab1@securehealth.com', role: 'LAB_TECHNICIAN' },
                { userId: 4, email: 'admin@securehealth.com', role: 'ADMIN' },
            ]);
        } finally {
            setLoading(false);
        }
    };

    const filteredUsers = users.filter(user =>
        user.email?.toLowerCase().includes(searchTerm.toLowerCase())
    );

    const getRoleBadgeVariant = (role) => {
        switch (role) {
            case 'ADMIN': return 'red';
            case 'DOCTOR': return 'blue';
            case 'NURSE': return 'green';
            case 'LAB_TECHNICIAN': return 'yellow';
            case 'PATIENT': return 'gray';
            default: return 'gray';
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
                    <p className="text-sm text-slate-500 dark:text-slate-400">Manage access and roles ({users.length} total users)</p>
                </div>

                <div className="flex items-center gap-3">
                    <div className="relative">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" size={18} />
                        <input
                            type="text"
                            placeholder="Search users..."
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            className="pl-10 pr-4 py-2 border border-slate-200 dark:border-slate-700 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-admin-primary dark:bg-slate-800 dark:text-white"
                        />
                    </div>
                    <Button variant="outline" className="flex items-center gap-2">
                        <Filter size={16} /> Filter
                    </Button>
                </div>
            </div>

            {loading && (
                <div className="p-6 text-center text-slate-500">
                    Loading users...
                </div>
            )}



            {!loading && filteredUsers.length === 0 && (
                <div className="p-6 text-center text-slate-500">
                    {searchTerm ? 'No users found matching your search.' : 'No users found.'}
                </div>
            )}

            {!loading && filteredUsers.length > 0 && (
                <Table>
                    <TableHead>
                        <TableHeader>User</TableHeader>
                        <TableHeader>Role</TableHeader>
                        <TableHeader>Status</TableHeader>
                        <TableHeader>Last Login</TableHeader>
                        <TableHeader align="right">Actions</TableHeader>
                    </TableHead>
                    <TableBody>
                        {filteredUsers.map((user) => (
                            <TableRow key={user.userId} hover>
                                <TableCell>
                                    <div className="flex items-center gap-3">
                                        <div className="w-10 h-10 rounded-full bg-admin-primary/10 flex items-center justify-center text-admin-primary font-bold">
                                            {user.email?.charAt(0)?.toUpperCase()}
                                        </div>
                                        <div>
                                            <h3 className="text-sm font-medium text-slate-800 dark:text-white">{user.email || 'N/A'}</h3>
                                            <p className="text-xs text-slate-500 dark:text-slate-400">ID: {user.userId}</p>
                                        </div>
                                    </div>
                                </TableCell>
                                <TableCell>
                                    <Badge variant={getRoleBadgeVariant(user.role)} label={user.role || 'PATIENT'} />
                                </TableCell>
                                <TableCell>
                                    <span className={`text-xs font-medium px-2 py-1 rounded-full ${getStatusColor('Active')}`}>
                                        Active
                                    </span>
                                </TableCell>
                                <TableCell>
                                    <span className="text-sm text-slate-500">Just now</span>
                                </TableCell>
                                <TableCell align="right">
                                    <div className="flex items-center gap-2 justify-end">
                                        <button className="p-1.5 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg transition-colors" title="Edit">
                                            <Edit size={16} className="text-slate-500" />
                                        </button>
                                        <button className="p-1.5 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg transition-colors" title="More options">
                                            <MoreVertical size={16} className="text-slate-500" />
                                        </button>
                                    </div>
                                </TableCell>
                            </TableRow>
                        ))}
                    </TableBody>
                </Table>
            )}
        </Card>
    );
};

export default UserManagement;
