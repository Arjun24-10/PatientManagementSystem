import React, { useState, useEffect } from 'react';
import {
    Clock,
    MessageSquare,
    Check,
    Plus,
    X
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
    const [showModal, setShowModal] = useState(false);
    const [form, setForm] = useState({ title: '', description: '', category: 'general', priority: 'medium', dueTime: '' });
    const [formError, setFormError] = useState('');
    const [submitting, setSubmitting] = useState(false);

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

    const handleCreateTask = async (e) => {
        e.preventDefault();
        setFormError('');
        if (!form.title.trim()) { setFormError('Title is required.'); return; }
        if (!form.dueTime) { setFormError('Due time is required.'); return; }
        setSubmitting(true);
        try {
            // Convert datetime-local value to ISO string without seconds offset
            const dueTimeISO = new Date(form.dueTime).toISOString().slice(0, 19);
            await api.nurse.createTask({ ...form, dueTime: dueTimeISO });
            const data = await api.nurse.getTasks();
            setTasks(Array.isArray(data) ? data : []);
            setShowModal(false);
            setForm({ title: '', description: '', category: 'general', priority: 'medium', dueTime: '' });
        } catch (err) {
            setFormError('Failed to create task. Please try again.');
        } finally {
            setSubmitting(false);
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
                    <Button onClick={() => setShowModal(true)} className="flex items-center gap-1.5 whitespace-nowrap">
                        <Plus className="w-4 h-4" /> Add Task
                    </Button>
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

            {showModal && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
                    <div className="bg-white dark:bg-slate-900 rounded-xl shadow-xl w-full max-w-md">
                        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100 dark:border-slate-700">
                            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Add New Task</h2>
                            <button onClick={() => { setShowModal(false); setFormError(''); }} className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200">
                                <X className="w-5 h-5" />
                            </button>
                        </div>
                        <form onSubmit={handleCreateTask} className="px-6 py-5 space-y-4">
                            {formError && (
                                <p className="text-sm text-red-500">{formError}</p>
                            )}
                            <div>
                                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Title *</label>
                                <Input
                                    placeholder="e.g. Administer medication"
                                    value={form.title}
                                    onChange={(e) => setForm(f => ({ ...f, title: e.target.value }))}
                                    className="w-full"
                                />
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Description</label>
                                <textarea
                                    placeholder="Optional details..."
                                    value={form.description}
                                    onChange={(e) => setForm(f => ({ ...f, description: e.target.value }))}
                                    rows={2}
                                    className="w-full rounded-lg border border-gray-300 dark:border-slate-600 bg-white dark:bg-slate-800 text-gray-900 dark:text-white px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none"
                                />
                            </div>
                            <div className="grid grid-cols-2 gap-3">
                                <div>
                                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Category</label>
                                    <Select
                                        value={form.category}
                                        onChange={(e) => setForm(f => ({ ...f, category: e.target.value }))}
                                        className="w-full"
                                        options={[
                                            { value: 'general',       label: 'General' },
                                            { value: 'medication',    label: 'Medication' },
                                            { value: 'assessment',    label: 'Assessment' },
                                            { value: 'care',          label: 'Care' },
                                            { value: 'documentation', label: 'Documentation' },
                                            { value: 'vitals',        label: 'Vitals' },
                                        ]}
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Priority</label>
                                    <Select
                                        value={form.priority}
                                        onChange={(e) => setForm(f => ({ ...f, priority: e.target.value }))}
                                        className="w-full"
                                        options={[
                                            { value: 'low',      label: 'Low' },
                                            { value: 'medium',   label: 'Medium' },
                                            { value: 'high',     label: 'High' },
                                            { value: 'critical', label: 'Critical' },
                                        ]}
                                    />
                                </div>
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Due Time *</label>
                                <input
                                    type="datetime-local"
                                    value={form.dueTime}
                                    onChange={(e) => setForm(f => ({ ...f, dueTime: e.target.value }))}
                                    className="w-full rounded-lg border border-gray-300 dark:border-slate-600 bg-white dark:bg-slate-800 text-gray-900 dark:text-white px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                                />
                            </div>
                            <div className="flex justify-end gap-2 pt-2">
                                <Button type="button" variant="outline" onClick={() => { setShowModal(false); setFormError(''); }}>
                                    Cancel
                                </Button>
                                <Button type="submit" disabled={submitting}>
                                    {submitting ? 'Saving…' : 'Add Task'}
                                </Button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
};

export default Tasks;
