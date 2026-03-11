import React, { useState, useEffect } from 'react';
import { CheckCircle, XCircle, Clock, User, Calendar, AlertCircle } from 'lucide-react';
import Card from '../common/Card';
import Button from '../common/Button';
import Badge from '../common/Badge';
import Modal from '../common/Modal';
import api from '../../services/api';

const AppointmentApprovalQueue = () => {
    const [pendingAppointments, setPendingAppointments] = useState([]);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState(null);
    const [selectedAppt, setSelectedAppt] = useState(null);
    const [confirmModal, setConfirmModal] = useState({ isOpen: false, action: null });
    const [rejectionReason, setRejectionReason] = useState('');

    useEffect(() => {
        fetchPendingAppointments();
    }, []);

    const fetchPendingAppointments = async () => {
        setIsLoading(true);
        setError(null);
        try {
            const data = await api.appointments.getPending();
            setPendingAppointments(Array.isArray(data) ? data : []);
        } catch (err) {
            console.error('Failed to fetch appointments:', err);
            setError('Failed to load pending appointments');
        } finally {
            setIsLoading(false);
        }
    };

    const handleApprove = async (appointmentId) => {
        try {
            await api.appointments.approve(appointmentId);
            await fetchPendingAppointments();
            setConfirmModal({ isOpen: false, action: null });
            setSelectedAppt(null);
            alert('Appointment approved successfully!');
        } catch (err) {
            console.error('Failed to approve appointment:', err);
            alert('Error approving appointment: ' + err.message);
        }
    };

    const handleReject = async (appointmentId, reason) => {
        try {
            await api.appointments.reject(appointmentId, reason);
            await fetchPendingAppointments();
            setConfirmModal({ isOpen: false, action: null });
            setSelectedAppt(null);
            setRejectionReason('');
            alert('Appointment rejected successfully!');
        } catch (err) {
            console.error('Failed to reject appointment:', err);
            alert('Error rejecting appointment: ' + err.message);
        }
    };

    const formatDateTime = (dateString) => {
        try {
            const date = new Date(dateString);
            return date.toLocaleString('en-US', { 
                month: 'short', 
                day: '2-digit', 
                year: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                hour12: true 
            });
        } catch {
            return dateString;
        }
    };

    if (isLoading) {
        return (
            <Card className="p-6 dark:bg-slate-800">
                <div className="text-center py-8">
                    <Clock className="w-8 h-8 animate-spin mx-auto text-blue-500 mb-3" />
                    <p className="text-gray-600 dark:text-slate-400">Loading pending appointments...</p>
                </div>
            </Card>
        );
    }

    return (
        <>
            <Card className="dark:bg-slate-800">
                <div className="bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-blue-900/20 dark:to-indigo-900/20 p-4 border-b border-blue-200 dark:border-blue-800 rounded-t-lg">
                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                            <Clock className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                            <div>
                                <h2 className="font-bold text-gray-800 dark:text-slate-100">Appointment Approval Queue</h2>
                                <p className="text-xs text-gray-600 dark:text-slate-400">
                                    {pendingAppointments.length} pending review
                                </p>
                            </div>
                        </div>
                        <Badge type={pendingAppointments.length > 0 ? 'yellow' : 'green'}>
                            {pendingAppointments.length > 0 ? 'Action Required' : 'All Clear'}
                        </Badge>
                    </div>
                </div>

                <div className="p-4">
                    {error && (
                        <div className="mb-4 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded text-sm text-red-700 dark:text-red-400 flex items-start gap-2">
                            <AlertCircle className="w-4 h-4 mt-0.5 flex-shrink-0" />
                            {error}
                        </div>
                    )}

                    {pendingAppointments.length === 0 ? (
                        <div className="text-center py-8">
                            <CheckCircle className="w-12 h-12 text-green-400 mx-auto mb-3 opacity-50" />
                            <p className="text-gray-500 dark:text-slate-400">No pending appointments to review</p>
                        </div>
                    ) : (
                        <div className="space-y-3 max-h-96 overflow-y-auto">
                            {pendingAppointments.map((appointment) => (
                                <div 
                                    key={appointment.appointmentId}
                                    className="border border-yellow-200 dark:border-yellow-800/50 bg-yellow-50/50 dark:bg-yellow-900/10 rounded-lg p-3 hover:shadow-md transition-shadow"
                                >
                                    <div className="grid grid-cols-1 md:grid-cols-5 gap-3 mb-3">
                                        <div className="flex items-start gap-2">
                                            <User className="w-4 h-4 text-blue-600 dark:text-blue-400 mt-1 flex-shrink-0" />
                                            <div className="min-w-0">
                                                <p className="text-xs text-gray-500 dark:text-slate-400">Patient</p>
                                                <p className="font-medium text-gray-800 dark:text-slate-100 text-sm truncate">
                                                    {appointment.patientName}
                                                </p>
                                            </div>
                                        </div>

                                        <div className="flex items-start gap-2">
                                            <User className="w-4 h-4 text-green-600 dark:text-green-400 mt-1 flex-shrink-0" />
                                            <div className="min-w-0">
                                                <p className="text-xs text-gray-500 dark:text-slate-400">Doctor</p>
                                                <p className="font-medium text-gray-800 dark:text-slate-100 text-sm truncate">
                                                    {appointment.doctorName}
                                                </p>
                                            </div>
                                        </div>

                                        <div className="flex items-start gap-2">
                                            <Calendar className="w-4 h-4 text-purple-600 dark:text-purple-400 mt-1 flex-shrink-0" />
                                            <div className="min-w-0">
                                                <p className="text-xs text-gray-500 dark:text-slate-400">Time</p>
                                                <p className="font-medium text-gray-800 dark:text-slate-100 text-sm">
                                                    {formatDateTime(appointment.appointmentDate)}
                                                </p>
                                            </div>
                                        </div>

                                        <div className="flex items-start gap-2">
                                            <AlertCircle className="w-4 h-4 text-orange-600 dark:text-orange-400 mt-1 flex-shrink-0" />
                                            <div className="min-w-0">
                                                <p className="text-xs text-gray-500 dark:text-slate-400">Reason</p>
                                                <p className="font-medium text-gray-800 dark:text-slate-100 text-sm truncate">
                                                    {appointment.reasonForVisit}
                                                </p>
                                            </div>
                                        </div>

                                        <div>
                                            <p className="text-xs text-gray-500 dark:text-slate-400 mb-1">Status</p>
                                            <Badge type="yellow">Pending</Badge>
                                        </div>
                                    </div>

                                    <div className="flex gap-2 pt-3 border-t border-yellow-200 dark:border-yellow-800/50">
                                        <Button
                                            variant="success"
                                            size="sm"
                                            className="flex-1 flex items-center justify-center gap-2 text-xs py-1.5"
                                            onClick={() => {
                                                setSelectedAppt(appointment);
                                                setConfirmModal({ isOpen: true, action: 'approve' });
                                            }}
                                        >
                                            <CheckCircle size={14} />
                                            Approve
                                        </Button>
                                        <Button
                                            variant="danger"
                                            size="sm"
                                            className="flex-1 flex items-center justify-center gap-2 text-xs py-1.5"
                                            onClick={() => {
                                                setSelectedAppt(appointment);
                                                setConfirmModal({ isOpen: true, action: 'reject' });
                                            }}
                                        >
                                            <XCircle size={14} />
                                            Reject
                                        </Button>
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            </Card>

            <Modal
                isOpen={confirmModal.isOpen}
                onClose={() => {
                    setConfirmModal({ isOpen: false, action: null });
                    setRejectionReason('');
                    setSelectedAppt(null);
                }}
                title={confirmModal.action === 'approve' ? 'Approve Appointment' : 'Reject Appointment'}
            >
                {selectedAppt && (
                    <form onSubmit={(e) => {
                        e.preventDefault();
                        if (confirmModal.action === 'approve') {
                            handleApprove(selectedAppt.appointmentId);
                        } else {
                            handleReject(selectedAppt.appointmentId, rejectionReason);
                        }
                    }} className="space-y-4">
                        <div className="bg-gray-50 dark:bg-slate-700 p-3 rounded text-sm space-y-2">
                            <p><span className="font-medium text-gray-700 dark:text-slate-300">Patient:</span> <span className="text-gray-600 dark:text-slate-400">{selectedAppt.patientName}</span></p>
                            <p><span className="font-medium text-gray-700 dark:text-slate-300">Doctor:</span> <span className="text-gray-600 dark:text-slate-400">{selectedAppt.doctorName}</span></p>
                            <p><span className="font-medium text-gray-700 dark:text-slate-300">Time:</span> <span className="text-gray-600 dark:text-slate-400">{formatDateTime(selectedAppt.appointmentDate)}</span></p>
                            <p><span className="font-medium text-gray-700 dark:text-slate-300">Reason:</span> <span className="text-gray-600 dark:text-slate-400">{selectedAppt.reasonForVisit}</span></p>
                        </div>

                        {confirmModal.action === 'reject' && (
                            <div>
                                <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-2">
                                    Rejection Reason (Optional)
                                </label>
                                <textarea
                                    value={rejectionReason}
                                    onChange={(e) => setRejectionReason(e.target.value)}
                                    placeholder="Why is this appointment being rejected?"
                                    className="w-full px-3 py-2 border border-gray-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-transparent outline-none resize-none h-20 bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100 placeholder-gray-400 dark:placeholder-slate-500"
                                />
                            </div>
                        )}

                        <div className="pt-4 flex justify-end space-x-3 border-t border-gray-100 dark:border-slate-700">
                            <Button type="button" variant="secondary" onClick={() => {
                                setConfirmModal({ isOpen: false, action: null });
                                setRejectionReason('');
                                setSelectedAppt(null);
                            }}>Cancel</Button>
                            <Button type="submit" variant={confirmModal.action === 'approve' ? 'success' : 'danger'}>
                                {confirmModal.action === 'approve' ? 'Approve' : 'Reject'}
                            </Button>
                        </div>
                    </form>
                )}
            </Modal>
        </>
    );
};

export default AppointmentApprovalQueue;
