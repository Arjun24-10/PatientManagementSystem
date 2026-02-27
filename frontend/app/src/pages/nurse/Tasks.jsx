import React, { useState } from 'react';
import {
    Clock,
    MessageSquare,
    Check
} from 'lucide-react';

import Card from '../../components/common/Card';
import Button from '../../components/common/Button';
import Badge from '../../components/common/Badge';
import { Table, TableHead, TableBody, TableRow, TableHeader, TableCell } from '../../components/common/Table';
import Input from '../../components/common/Input';
import Select from '../../components/common/Select';
import { mockNursePatients } from '../../mocks/nursePatients';

const Tasks = () => {
    const [tasks, setTasks] = useState([
        { id: 1, text: 'Administer insulin', patientId: 'P001', priority: 'high', status: 'pending', dueTime: '08:00', type: 'medication' },
        { id: 2, text: 'Wound dressing change', patientId: 'P002', priority: 'medium', status: 'pending', dueTime: '10:00', type: 'procedure' },
        { id: 3, text: 'Check vitals', patientId: 'P003', priority: 'routine', status: 'pending', dueTime: '12:00', type: 'vitals' },
        { id: 4, text: 'Update care plan', patientId: 'P001', priority: 'low', status: 'completed', dueTime: '14:00', type: 'documentation' },
        { id: 5, text: 'Assist with feeding', patientId: 'P004', priority: 'medium', status: 'pending', dueTime: '11:30', type: 'care' },
    ]);

    const [filterPriority, setFilterPriority] = useState('all');
    const [searchTerm, setSearchTerm] = useState('');

    const handleToggleTask = (id) => {
        setTasks(prev => prev.map(t =>
            t.id === id ? { ...t, status: t.status === 'completed' ? 'pending' : 'completed' } : t
        ));
    };

    const getPatientName = (id) => {
        const patient = mockNursePatients.find(p => p.id === id);
        return patient ? `${patient.name} (${patient.room})` : 'Unknown Patient';
    };

    const getPriorityBadge = (priority) => {
        switch (priority) {
            case 'high': return <Badge type="red">High</Badge>;
            case 'medium': return <Badge type="yellow">Medium</Badge>;
            case 'low': return <Badge type="green">Low</Badge>;
            default: return <Badge type="gray">Routine</Badge>;
        }
    };

    const filteredTasks = tasks.filter(task => {
        const matchesSearch = task.text.toLowerCase().includes(searchTerm.toLowerCase());
        const matchesPriority = filterPriority === 'all' || task.priority === filterPriority;
        return matchesSearch && matchesPriority;
    });

    return (
        <div className="space-y-6">
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
                <div>
                    <h1 className="text-2xl font-bold text-gray-900 dark:text-white">My Tasks</h1>
                    <p className="text-gray-500">Manage your daily nursing tasks.</p>
                </div>
                <div className="flex gap-2 w-full sm:w-auto">
                    <div className="relative flex-1 sm:flex-none">
                        <Input
                            placeholder="Search tasks..."
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            className="w-full sm:w-64"
                        />
                    </div>
                    <Select
                        value={filterPriority}
                        onChange={(e) => setFilterPriority(e.target.value)}
                        className="w-32"
                    >
                        <option value="all">Priority</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                    </Select>
                </div>
            </div>

            <Card className="overflow-hidden">
                <Table>
                    <TableHead>
                        <TableHeader className="w-12"></TableHeader>
                        <TableHeader>Task</TableHeader>
                        <TableHeader>Patient</TableHeader>
                        <TableHeader>Priority</TableHeader>
                        <TableHeader>Due Time</TableHeader>
                        <TableHeader align="right">Actions</TableHeader>
                    </TableHead>
                    <TableBody>
                        {filteredTasks.length > 0 ? (
                            filteredTasks.map((task) => (
                                <TableRow key={task.id} className={task.status === 'completed' ? 'opacity-50 bg-gray-50 dark:bg-slate-800/50' : ''}>
                                    <TableCell>
                                        <div
                                            onClick={() => handleToggleTask(task.id)}
                                            className={`w-5 h-5 rounded border flex items-center justify-center cursor-pointer transition-colors ${task.status === 'completed'
                                                ? 'bg-blue-500 border-blue-500 text-white'
                                                : 'border-gray-300 dark:border-slate-600 hover:border-blue-400'
                                                }`}
                                        >
                                            {task.status === 'completed' && <Check className="w-3.5 h-3.5" />}
                                        </div>
                                    </TableCell>
                                    <TableCell>
                                        <div className={`font-medium ${task.status === 'completed' ? 'line-through text-gray-500' : 'text-gray-900 dark:text-white'}`}>
                                            {task.text}
                                        </div>
                                    </TableCell>
                                    <TableCell>{getPatientName(task.patientId)}</TableCell>
                                    <TableCell>{getPriorityBadge(task.priority)}</TableCell>
                                    <TableCell>
                                        <div className="flex items-center text-gray-500">
                                            <Clock className="w-3 h-3 mr-1" />
                                            {task.dueTime}
                                        </div>
                                    </TableCell>
                                    <TableCell align="right">
                                        <Button variant="ghost" size="sm">
                                            <MessageSquare className="w-4 h-4" />
                                        </Button>
                                    </TableCell>
                                </TableRow>
                            ))
                        ) : (
                            <TableRow>
                                <TableCell colSpan={6} className="text-center py-8 text-gray-500">
                                    No tasks found.
                                </TableCell>
                            </TableRow>
                        )}
                    </TableBody>
                </Table>
            </Card>
        </div>
    );
};

export default Tasks;
