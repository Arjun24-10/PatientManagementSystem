import React, { useState, useEffect } from 'react';
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
import api from '../../services/api';

const Tasks = () => {
    const [tasks, setTasks] = useState([]);

    const [filterPriority, setFilterPriority] = useState('all');
    const [searchTerm, setSearchTerm] = useState('');

    useEffect(() => {
        const fetchTasks = async () => {
            try {
                const data = await api.nurse.getTasks();
                if (data && Array.isArray(data)) {
                    setTasks(data);
                } else {
                    setTasks([]);
                }
            } catch (err) {
                console.error('Failed to fetch tasks:', err);
                setTasks([]);
            }
        };
        fetchTasks();
    }, []);

    const handleToggleTask = async (id) => {
        try {
            await api.nurse.toggleTaskStatus(id);
            // Refresh tasks after toggling
            const data = await api.nurse.getTasks();
            if (data && Array.isArray(data)) {
                setTasks(data);
            }
        } catch (err) {
            console.error('Failed to toggle task:', err);
        }
    };

    const getPatientName = (task) => {
        // Build patient name from task data if available
        if (task.patient && task.patient.firstName && task.patient.lastName) {
            return `${task.patient.firstName} ${task.patient.lastName}${task.room ? ' (Room ' + task.room + ')' : ''}`;
        }
        return 'Unknown Patient';
    };

    const getPriorityBadge = (priority) => {
        switch (priority) {
            case 'critical': return <Badge type="red">Critical</Badge>;
            case 'high': return <Badge type="red">High</Badge>;
            case 'medium': return <Badge type="yellow">Medium</Badge>;
            case 'low': return <Badge type="green">Low</Badge>;
            default: return <Badge type="gray">Routine</Badge>;
        }
    };

    const filteredTasks = tasks.filter(task => {
        const matchesSearch = (task.title || '').toLowerCase().includes(searchTerm.toLowerCase());
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
                        className="w-36"
                        placeholder="All Priorities"
                        options={[
                            { value: 'all',      label: 'All Priorities' },
                            { value: 'critical', label: 'Critical' },
                            { value: 'high',     label: 'High' },
                            { value: 'medium',   label: 'Medium' },
                            { value: 'low',      label: 'Low' },
                        ]}
                    />
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
                                            {task.title}
                                        </div>
                                    </TableCell>
                                    <TableCell>{getPatientName(task)}</TableCell>
                                    <TableCell>{getPriorityBadge(task.priority)}</TableCell>
                                    <TableCell>
                                        <div className="flex items-center text-gray-500">
                                            <Clock className="w-3 h-3 mr-1" />
                                            {task.dueTime ? new Date(task.dueTime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'N/A'}
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
