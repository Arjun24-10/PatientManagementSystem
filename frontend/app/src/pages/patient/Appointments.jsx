import React, { useState, useMemo } from 'react';
import {
   Calendar, Clock, MapPin, Plus, AlertCircle, User, Building2, Check, ChevronRight, ChevronLeft, Bell, Download, List, LayoutGrid,
   RefreshCw,
} from 'lucide-react';
import Card from '../../components/common/Card';
import Button from '../../components/common/Button';
import Badge from '../../components/common/Badge';
import Modal from '../../components/common/Modal';
import Alert from '../../components/common/Alert';
import Input from '../../components/common/Input';
import { mockAppointments } from '../../mocks/appointments';
import { mockDepartments, mockDoctors, mockTimeSlots, appointmentTypes, cancellationReasons } from '../../mocks/doctors';
import { format, addDays, startOfMonth, endOfMonth, eachDayOfInterval, isSameDay, parseISO, differenceInDays, differenceInHours, differenceInMinutes } from 'date-fns';

const PatientAppointments = () => {
   const patientId = 'P001';
   const [appointments, setAppointments] = useState(
      mockAppointments.filter(a => a.patientId === patientId)
   );
   const [activeTab, setActiveTab] = useState('upcoming');
   const [viewMode, setViewMode] = useState('list'); // 'list' or 'calendar'

   // Request Appointment Modal State
   const [isRequestModalOpen, setIsRequestModalOpen] = useState(false);
   const [requestStep, setRequestStep] = useState(1);
   const [requestForm, setRequestForm] = useState({
      department: '',
      doctor: '',
      date: '',
      time: '',
      type: '',
      reason: '',
      specialRequirements: '',
   });

   // Cancel Appointment Modal State
   const [isCancelModalOpen, setIsCancelModalOpen] = useState(false);
   const [appointmentToCancel, setAppointmentToCancel] = useState(null);
   const [cancellationReason, setCancellationReason] = useState('');

   // Details View Modal State
   const [isDetailsModalOpen, setIsDetailsModalOpen] = useState(false);
   const [selectedAppointment, setSelectedAppointment] = useState(null);

   // Reschedule Modal State
   const [isRescheduleModalOpen, setIsRescheduleModalOpen] = useState(false);
   const [appointmentToReschedule, setAppointmentToReschedule] = useState(null);
   const [rescheduleData, setRescheduleData] = useState({ date: '', time: '' });

   // Calendar Added Events State
   const [calendarAddedEvents, setCalendarAddedEvents] = useState([]);

   // Calendar State
   const [currentMonth, setCurrentMonth] = useState(new Date());

   // Filter appointments by tab
   const filteredAppointments = useMemo(() => {
      return appointments.filter(a => {
         if (activeTab === 'upcoming') {
            return !['Completed', 'Cancelled'].includes(a.status);
         } else if (activeTab === 'past') {
            return a.status === 'Completed';
         } else if (activeTab === 'cancelled') {
            return a.status === 'Cancelled';
         }
         return true;
      });
   }, [appointments, activeTab]);

   // Get next 3 upcoming appointments for reminder sidebar
   const upcomingReminders = useMemo(() => {
      return appointments
         .filter(a => !['Completed', 'Cancelled'].includes(a.status))
         .sort((a, b) => new Date(a.date + ' ' + a.time) - new Date(b.date + ' ' + b.time))
         .slice(0, 3);
   }, [appointments]);

   // Get doctors filtered by selected department
   const filteredDoctors = useMemo(() => {
      if (!requestForm.department) return [];
      return mockDoctors.filter(d => d.department === requestForm.department);
   }, [requestForm.department]);

   // Get available time slots for selected date
   const availableTimeSlots = useMemo(() => {
      if (!requestForm.date) return [];
      // In a real app, this would check doctor's availability
      return [...mockTimeSlots.morning, ...mockTimeSlots.afternoon, ...mockTimeSlots.evening];
   }, [requestForm.date]);

   // Calendar days for current month
   const calendarDays = useMemo(() => {
      const start = startOfMonth(currentMonth);
      const end = endOfMonth(currentMonth);
      return eachDayOfInterval({ start, end });
   }, [currentMonth]);

   // Get appointments for a specific date
   const getAppointmentsForDate = (date) => {
      return appointments.filter(a => isSameDay(parseISO(a.date), date));
   };

   // Calculate countdown for appointment
   const getCountdown = (appointment) => {
      const appointmentDate = new Date(appointment.date + ' ' + appointment.time);
      const now = new Date();
      const days = differenceInDays(appointmentDate, now);
      const hours = differenceInHours(appointmentDate, now) % 24;
      const minutes = differenceInMinutes(appointmentDate, now) % 60;

      if (days > 0) return `${days}d ${hours}h`;
      if (hours > 0) return `${hours}h ${minutes}m`;
      return `${minutes}m`;
   };

   // Handle request appointment submission
   const handleRequestSubmit = (e) => {
      e.preventDefault();
      if (requestStep < 3) {
         setRequestStep(requestStep + 1);
      } else {
         // Submit the request
         const selectedDoctor = mockDoctors.find(d => d.id === requestForm.doctor);
         const newAppointment = {
            id: `A${appointments.length + 1}`.padStart(4, '0'),
            patientId,
            patientName: 'Emily Blunt',
            doctorName: selectedDoctor?.name || 'TBD',
            doctorId: requestForm.doctor,
            department: mockDepartments.find(d => d.id === requestForm.department)?.name,
            date: requestForm.date,
            time: requestForm.time,
            duration: 30,
            type: requestForm.type,
            status: 'Pending',
            room: 'TBD',
            location: 'TBD',
            reason: requestForm.reason,
            cancellationReason: null,
         };

         setAppointments([...appointments, newAppointment]);
         setIsRequestModalOpen(false);
         setRequestStep(1);
         setRequestForm({
            department: '',
            doctor: '',
            date: '',
            time: '',
            type: '',
            reason: '',
            specialRequirements: '',
         });
         alert('✅ Appointment request submitted! We will confirm shortly.');
      }
   };

   // Handle cancel appointment
   const handleCancelAppointment = () => {
      if (!cancellationReason) {
         alert('Please select a cancellation reason');
         return;
      }

      setAppointments(
         appointments.map(a =>
            a.id === appointmentToCancel.id
               ? { ...a, status: 'Cancelled', cancellationReason }
               : a
         )
      );

      setIsCancelModalOpen(false);
      setAppointmentToCancel(null);
      setCancellationReason('');
      alert('📧 Appointment cancelled. Confirmation email sent.');
   };

   // Open cancel modal
   const openCancelModal = (appointment) => {
      setAppointmentToCancel(appointment);
      setIsCancelModalOpen(true);
   };

   // Open details modal
   const openDetailsModal = (appointment) => {
      setSelectedAppointment(appointment);
      setIsDetailsModalOpen(true);
   };

   // Open reschedule modal
   const openRescheduleModal = (appointment) => {
      setAppointmentToReschedule(appointment);
      setRescheduleData({ date: appointment.date, time: appointment.time });
      setIsRescheduleModalOpen(true);
   };

   // Handle reschedule submit
   const handleRescheduleSubmit = (e) => {
      e.preventDefault();
      setAppointments(
         appointments.map(a =>
            a.id === appointmentToReschedule.id
               ? { ...a, date: rescheduleData.date, time: rescheduleData.time, status: 'Pending' }
               : a
         )
      );
      setIsRescheduleModalOpen(false);
      setAppointmentToReschedule(null);
      alert('🔄 Reschedule request submitted successfully!');
   };

   // Handle toggle add to calendar
   const handleToggleCalendar = (appointmentId) => {
      if (calendarAddedEvents.includes(appointmentId)) {
         setCalendarAddedEvents(calendarAddedEvents.filter(id => id !== appointmentId));
      } else {
         setCalendarAddedEvents([...calendarAddedEvents, appointmentId]);
      }
   };

   // Render appointment card - Compact
   const renderAppointmentCard = (appt) => {
      const dateObj = parseISO(appt.date);
      const month = format(dateObj, 'MMM');
      const day = format(dateObj, 'dd');

      return (
         <Card
            key={appt.id}
            className="p-3 flex flex-col md:flex-row justify-between items-start md:items-center hover:border-gray-300 dark:hover:border-slate-600"
         >
            <div className="flex items-start gap-3 w-full md:w-auto">
               {/* Date Badge - Compact */}
               <div className="bg-blue-600 p-2 rounded-md text-white text-center min-w-[48px]">
                  <p className="text-xs font-medium uppercase">{month}</p>
                  <p className="text-lg font-bold leading-tight">{day}</p>
               </div>

               {/* Appointment Details - Compact */}
               <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                     <h4 className="text-sm font-semibold text-gray-800 dark:text-slate-100 truncate">{appt.type}</h4>
                     <Badge
                        size="sm"
                        type={
                           appt.status === 'Confirmed'
                              ? 'green'
                              : appt.status === 'Pending'
                                 ? 'yellow'
                                 : appt.status === 'Completed'
                                    ? 'blue'
                                    : 'red'
                        }
                     >
                        {appt.status}
                     </Badge>
                  </div>

                  <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs text-gray-600 dark:text-slate-300">
                     <div className="flex items-center gap-1">
                        <User className="w-3 h-3 text-gray-400" />
                        <span className="truncate">{appt.doctorName}</span>
                     </div>
                     <div className="flex items-center gap-1">
                        <Clock className="w-3 h-3 text-gray-400" />
                        <span>{appt.time} ({appt.duration}m)</span>
                     </div>
                     <div className="flex items-center gap-1">
                        <Building2 className="w-3 h-3 text-gray-400" />
                        <span className="truncate">{appt.department || 'General'}</span>
                     </div>
                     <div className="flex items-center gap-1">
                        <MapPin className="w-3 h-3 text-gray-400" />
                        <span className="truncate">{appt.location || appt.room || 'Main Clinic'}</span>
                     </div>
                  </div>

                  {appt.cancellationReason && (
                     <div className="mt-1 text-xs text-red-600 dark:text-red-400 flex items-center gap-1">
                        <AlertCircle className="w-3 h-3" />
                        {appt.cancellationReason}
                     </div>
                  )}
               </div>
            </div>

            {/* Action Buttons - Compact */}
            <div className="mt-2 md:mt-0 flex gap-2">
               {activeTab === 'upcoming' && appt.status !== 'Cancelled' && (
                  <>
                     <Button
                        variant="outline"
                        size="sm"
                        onClick={(e) => { e.stopPropagation(); openDetailsModal(appt); }}
                        className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-gray-700 hover:text-blue-600 dark:text-slate-300 dark:hover:text-blue-400 font-medium bg-white dark:bg-slate-800"
                        title="View Details"
                     >
                        <Calendar className="w-3.5 h-3.5" />
                        View
                     </Button>
                     <Button
                        variant="outline"
                        size="sm"
                        onClick={(e) => { e.stopPropagation(); openRescheduleModal(appt); }}
                        className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-gray-700 hover:text-orange-600 dark:text-slate-300 dark:hover:text-orange-400 font-medium bg-white dark:bg-slate-800"
                        title="Reschedule"
                     >
                        <RefreshCw className="w-3.5 h-3.5" />
                        Reschedule
                     </Button>
                     <Button
                        variant="outline"
                        size="sm"
                        onClick={(e) => { e.stopPropagation(); openCancelModal(appt); }}
                        className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-gray-700 hover:text-red-600 border-gray-200 hover:border-red-300 dark:text-slate-300 dark:hover:text-red-400 dark:border-slate-700 dark:hover:border-red-800 font-medium bg-white dark:bg-slate-800"
                        title="Cancel"
                     >
                        <AlertCircle className="w-3.5 h-3.5" />
                        Cancel
                     </Button>
                  </>
               )}
               {activeTab === 'past' && (
                  <>
                     <Button
                        variant="outline"
                        size="sm"
                        className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-gray-700 hover:text-blue-600 dark:text-slate-300 dark:hover:text-blue-400 font-medium bg-white dark:bg-slate-800"
                        title="View Summary"
                     >
                        <Calendar className="w-3.5 h-3.5" />
                        Summary
                     </Button>
                     <Button
                        variant="outline"
                        size="sm"
                        className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-blue-700 hover:text-blue-800 border-blue-200 hover:bg-blue-50 dark:text-blue-400 dark:hover:text-blue-300 dark:border-blue-800 dark:hover:bg-blue-900/30 font-medium bg-white dark:bg-slate-800"
                        title="Book Follow-up"
                     >
                        <Plus className="w-3.5 h-3.5" />
                        Follow-up
                     </Button>
                  </>
               )}
               {activeTab === 'cancelled' && (
                  <Button
                     variant="outline"
                     size="sm"
                     className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-blue-700 hover:text-blue-800 border-blue-200 hover:bg-blue-50 dark:text-blue-400 dark:hover:text-blue-300 dark:border-blue-800 dark:hover:bg-blue-900/30 font-medium bg-white dark:bg-slate-800"
                     title="Rebook"
                  >
                     <RefreshCw className="w-3.5 h-3.5" />
                     Rebook
                  </Button>
               )}
            </div>
         </Card>
      );
   };

   return (
      <div className="space-y-4">
         {/* Header - Compact */}
         <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-3">
            <div>
               <h2 className="text-lg font-semibold text-gray-800 dark:text-slate-100">My Appointments</h2>
               <p className="text-sm text-gray-500 dark:text-slate-400">Manage your healthcare appointments</p>
            </div>
            <div className="flex items-center gap-2">
               <div className="flex bg-gray-100 dark:bg-slate-700 p-0.5 rounded-md">
                  <button
                     onClick={() => setViewMode('list')}
                     className={`p-1.5 rounded transition-all ${viewMode === 'list' ? 'bg-white dark:bg-slate-800 shadow-sm text-blue-600 dark:text-blue-400' : 'text-gray-500 dark:text-slate-400 hover:text-gray-700 dark:hover:text-slate-200'}`}
                     title="List View"
                  >
                     <List size={16} />
                  </button>
                  <button
                     onClick={() => setViewMode('calendar')}
                     className={`p-1.5 rounded transition-all ${viewMode === 'calendar' ? 'bg-white dark:bg-slate-800 shadow-sm text-blue-600 dark:text-blue-400' : 'text-gray-500 dark:text-slate-400 hover:text-gray-700 dark:hover:text-slate-200'}`}
                     title="Calendar View"
                  >
                     <LayoutGrid size={16} />
                  </button>
               </div>
               <Button
                  onClick={() => setIsRequestModalOpen(true)}
                  size="sm"
                  className="flex items-center gap-1.5"
               >
                  <Plus className="w-4 h-4" />
                  New
               </Button>
            </div>
         </div>

         <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
            {/* Main Content */}
            <div className="lg:col-span-3 space-y-4">
               {viewMode === 'list' ? (
                  <>
                     {/* Tabs - Compact */}
                     <div className="border-b border-gray-200 dark:border-slate-700">
                        <nav className="-mb-px flex space-x-6">
                           {[
                              { key: 'upcoming', label: 'Upcoming' },
                              { key: 'past', label: 'Past' },
                              { key: 'cancelled', label: 'Cancelled' },
                           ].map(tab => (
                              <button
                                 key={tab.key}
                                 onClick={() => setActiveTab(tab.key)}
                                 className={`
                        whitespace-nowrap py-2.5 border-b-2 text-sm font-medium transition-colors
                        ${activeTab === tab.key
                                       ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                                       : 'border-transparent text-gray-500 dark:text-slate-400 hover:text-gray-700 dark:hover:text-slate-200 hover:border-gray-300 dark:hover:border-slate-600'
                                    }
                      `}
                              >
                                 {tab.label}
                                 <span className="ml-1.5 bg-gray-100 dark:bg-slate-700 text-gray-600 dark:text-slate-300 py-0.5 px-1.5 rounded text-xs">
                                    {
                                       appointments.filter(a => {
                                          if (tab.key === 'upcoming') return !['Completed', 'Cancelled'].includes(a.status);
                                          if (tab.key === 'past') return a.status === 'Completed';
                                          if (tab.key === 'cancelled') return a.status === 'Cancelled';
                                          return false;
                                       }).length
                                    }
                                 </span>
                              </button>
                           ))}
                        </nav>
                     </div>

                     {/* Appointments List - Compact */}
                     <div className="space-y-2">
                        {filteredAppointments.length > 0 ? (
                           filteredAppointments.map(renderAppointmentCard)
                        ) : (
                           <div className="p-8 text-center text-gray-500 dark:text-slate-400 bg-white dark:bg-slate-800 rounded-md border border-dashed border-gray-200 dark:border-slate-700">
                              <Calendar className="w-8 h-8 mx-auto mb-2 text-gray-300 dark:text-slate-600" />
                              <p className="text-sm">No {activeTab} appointments found.</p>
                           </div>
                        )}
                     </div>
                  </>
               ) : (
                  /* Calendar View - Compact */
                  <Card className="p-4">
                     <div className="flex justify-between items-center mb-4">
                        <h3 className="text-base font-semibold text-gray-800 dark:text-slate-100">
                           {format(currentMonth, 'MMMM yyyy')}
                        </h3>
                        <div className="flex gap-1">
                           <button
                              onClick={() => setCurrentMonth(addDays(currentMonth, -30))}
                              className="w-7 h-7 rounded hover:bg-gray-100 dark:hover:bg-slate-700 flex items-center justify-center"
                           >
                              <ChevronLeft className="w-4 h-4" />
                           </button>
                           <button
                              onClick={() => setCurrentMonth(new Date())}
                              className="px-2 py-1 text-xs rounded hover:bg-gray-100 dark:hover:bg-slate-700"
                           >
                              Today
                           </button>
                           <button
                              onClick={() => setCurrentMonth(addDays(currentMonth, 30))}
                              className="w-7 h-7 rounded hover:bg-gray-100 dark:hover:bg-slate-700 flex items-center justify-center"
                           >
                              <ChevronRight className="w-4 h-4" />
                           </button>
                        </div>
                     </div>

                     {/* Calendar Grid - Compact */}
                     <div className="grid grid-cols-7 gap-1">
                        {['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].map(day => (
                           <div key={day} className="text-center text-xs font-medium text-gray-500 dark:text-slate-400 py-1.5">
                              {day}
                           </div>
                        ))}
                        {calendarDays.map(day => {
                           const dayAppointments = getAppointmentsForDate(day);
                           const isToday = isSameDay(day, new Date());

                           return (
                              <div
                                 key={day.toString()}
                                 className={`
                        min-h-[60px] p-1.5 border rounded cursor-pointer hover:bg-gray-50 dark:hover:bg-slate-700/50 transition-colors text-xs
                        ${isToday ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20' : 'border-gray-200 dark:border-slate-700'}
                      `}
                              >
                                 <div className={`text-xs font-medium ${isToday ? 'text-blue-600 dark:text-blue-400' : 'text-gray-700 dark:text-slate-200'}`}>
                                    {format(day, 'd')}
                                 </div>
                                 <div className="mt-0.5 space-y-0.5">
                                    {dayAppointments.slice(0, 2).map(appt => (
                                       <div
                                          key={appt.id}
                                          onClick={(e) => { e.stopPropagation(); openDetailsModal(appt); }}
                                          className={`text-xs px-1 py-0.5 rounded truncate ${appt.status === 'Confirmed'
                                             ? 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400'
                                             : appt.status === 'Pending'
                                                ? 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-400'
                                                : appt.status === 'Completed'
                                                   ? 'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400'
                                                   : 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400'
                                             }`}
                                       >
                                          {appt.time}
                                       </div>
                                    ))}
                                    {dayAppointments.length > 2 && (
                                       <div className="text-xs text-gray-400 dark:text-slate-500">+{dayAppointments.length - 2}</div>
                                    )}
                                 </div>
                              </div>
                           );
                        })}
                     </div>

                     {/* Legend - Compact */}
                     <div className="mt-4 flex flex-wrap gap-3 text-xs">
                        <div className="flex items-center gap-1">
                           <div className="w-2.5 h-2.5 rounded-sm bg-green-500"></div>
                           <span>Confirmed</span>
                        </div>
                        <div className="flex items-center gap-1">
                           <div className="w-2.5 h-2.5 rounded-sm bg-yellow-500"></div>
                           <span>Pending</span>
                        </div>
                        <div className="flex items-center gap-1">
                           <div className="w-2.5 h-2.5 rounded-sm bg-blue-500"></div>
                           <span>Completed</span>
                        </div>
                        <div className="flex items-center gap-1">
                           <div className="w-2.5 h-2.5 rounded-sm bg-red-500"></div>
                           <span>Cancelled</span>
                        </div>
                     </div>
                  </Card>
               )}
            </div>

            {/* Reminders Sidebar - Compact */}
            <div className="lg:col-span-1">
               <Card className="p-3 sticky top-4">
                  <div className="flex items-center justify-between mb-3">
                     <h3 className="text-sm font-semibold text-gray-800 dark:text-slate-100 flex items-center">
                        <Bell className="w-4 h-4 mr-1.5 text-gray-400" />
                        Reminders
                        {upcomingReminders.length > 0 && (
                           <span className="ml-1.5 bg-red-500 text-white text-xs rounded-full w-4 h-4 flex items-center justify-center">
                              {upcomingReminders.length}
                           </span>
                        )}
                     </h3>
                  </div>

                  <div className="space-y-2">
                     {upcomingReminders.length > 0 ? (
                        upcomingReminders.map(appt => (
                           <div
                              key={appt.id}
                              className="p-2 bg-gray-50 dark:bg-slate-800/50 rounded"
                           >
                              <div className="flex justify-between items-start mb-1">
                                 <p className="text-xs font-medium text-gray-800 dark:text-slate-100">{appt.type}</p>
                                 <Badge size="sm" type="green">
                                    {getCountdown(appt)}
                                 </Badge>
                              </div>
                              <p className="text-xs text-gray-500 dark:text-slate-400">{appt.doctorName}</p>
                              <p className="text-xs text-gray-400 dark:text-slate-500">
                                 {format(parseISO(appt.date), 'MMM dd')} at {appt.time}
                              </p>
                              <button
                                 onClick={() => handleToggleCalendar(appt.id)}
                                 className={`mt-1.5 w-full text-xs py-1.5 px-2 rounded border transition-colors flex items-center justify-center gap-1.5 ${calendarAddedEvents.includes(appt.id)
                                    ? 'bg-blue-50 dark:bg-blue-900/40 border-blue-200 dark:border-blue-700 text-blue-700 dark:text-blue-300'
                                    : 'border-gray-200 dark:border-slate-700 hover:bg-gray-100 dark:hover:bg-slate-700 text-gray-700 dark:text-slate-300'
                                    }`}
                              >
                                 {calendarAddedEvents.includes(appt.id) ? (
                                    <>
                                       <Check className="w-3 h-3" />
                                       Remove from Calendar
                                    </>
                                 ) : (
                                    <>
                                       <Calendar className="w-3 h-3" />
                                       Add to Calendar
                                    </>
                                 )}
                              </button>
                           </div>
                        ))
                     ) : (
                        <p className="text-xs text-gray-500 dark:text-slate-400 text-center py-3">No upcoming appointments</p>
                     )}
                  </div>
               </Card>
            </div>
         </div>

         {/* Request Appointment Modal */}
         <Modal
            isOpen={isRequestModalOpen}
            onClose={() => {
               setIsRequestModalOpen(false);
               setRequestStep(1);
            }}
            title="Request New Appointment"
         >
            <form onSubmit={handleRequestSubmit} className="space-y-4">
               {/* Progress Indicator - Compact */}
               <div className="flex items-center justify-between mb-4">
                  {[1, 2, 3].map(step => (
                     <div key={step} className="flex items-center flex-1">
                        <div
                           className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-medium ${step <= requestStep
                              ? 'bg-blue-600 text-white'
                              : 'bg-gray-200 dark:bg-slate-700 text-gray-500 dark:text-slate-400'
                              }`}
                        >
                           {step < requestStep ? <Check className="w-3 h-3" /> : step}
                        </div>
                        {step < 3 && (
                           <div
                              className={`flex-1 h-0.5 mx-2 ${step < requestStep ? 'bg-blue-600' : 'bg-gray-200 dark:bg-slate-700'
                                 }`}
                           ></div>
                        )}
                     </div>
                  ))}
               </div>

               {/* Step 1: Select Department and Doctor - Compact */}
               {requestStep === 1 && (
                  <div className="space-y-3">
                     <h3 className="text-sm font-semibold text-gray-800 dark:text-slate-100">Select Department & Doctor</h3>

                     <div>
                        <label className="block text-xs font-medium text-gray-700 dark:text-slate-300 mb-1">Department *</label>
                        <select
                           className="w-full px-3 py-1.5 text-sm border border-gray-300 dark:border-slate-600 rounded focus:ring-1 focus:ring-blue-500 outline-none bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100"
                           value={requestForm.department}
                           onChange={e => setRequestForm({ ...requestForm, department: e.target.value, doctor: '' })}
                           required
                        >
                           <option value="">Choose a department</option>
                           {mockDepartments.map(dept => (
                              <option key={dept.id} value={dept.id}>
                                 {dept.icon} {dept.name}
                              </option>
                           ))}
                        </select>
                     </div>

                     {requestForm.department && (
                        <div>
                           <label className="block text-xs font-medium text-gray-700 dark:text-slate-300 mb-1">Doctor *</label>
                           <div className="space-y-2 max-h-48 overflow-y-auto">
                              {filteredDoctors.map(doctor => (
                                 <div
                                    key={doctor.id}
                                    onClick={() => setRequestForm({ ...requestForm, doctor: doctor.id })}
                                    className={`p-2 border rounded cursor-pointer transition-colors ${requestForm.doctor === doctor.id
                                       ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20'
                                       : 'border-gray-200 dark:border-slate-700 hover:border-gray-300 dark:hover:border-slate-600'
                                       }`}
                                 >
                                    <div className="flex items-center justify-between">
                                       <div className="flex items-center gap-2">
                                          <div className="w-7 h-7 rounded-full bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400 flex items-center justify-center text-xs font-medium">
                                             {doctor.avatar}
                                          </div>
                                          <div>
                                             <p className="text-sm font-medium text-gray-800 dark:text-slate-100">{doctor.name}</p>
                                             <p className="text-xs text-gray-500 dark:text-slate-400">{doctor.specialization}</p>
                                          </div>
                                       </div>
                                       <span className="text-xs text-yellow-600">{doctor.rating}⭐</span>
                                    </div>
                                 </div>
                              ))}
                           </div>
                        </div>
                     )}
                  </div>
               )}

               {/* Step 2: Choose Date and Time - Compact */}
               {requestStep === 2 && (
                  <div className="space-y-3">
                     <h3 className="text-sm font-semibold text-gray-800 dark:text-slate-100">Choose Date & Time</h3>

                     <Input
                        type="date"
                        label="Preferred Date *"
                        value={requestForm.date}
                        onChange={e => setRequestForm({ ...requestForm, date: e.target.value, time: '' })}
                        min={format(new Date(), 'yyyy-MM-dd')}
                        required
                     />

                     {requestForm.date && (
                        <div>
                           <label className="block text-xs font-medium text-gray-700 dark:text-slate-300 mb-1">Time Slots *</label>
                           <div className="grid grid-cols-4 gap-1 max-h-48 overflow-y-auto">
                              {availableTimeSlots.map(slot => (
                                 <button
                                    key={slot}
                                    type="button"
                                    onClick={() => setRequestForm({ ...requestForm, time: slot })}
                                    className={`p-1.5 text-xs border rounded transition-colors ${requestForm.time === slot
                                       ? 'border-blue-500 bg-blue-500 text-white'
                                       : 'border-gray-300 dark:border-slate-600 hover:border-blue-300 dark:hover:border-blue-700 bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100'
                                       }`}
                                 >
                                    {slot}
                                 </button>
                              ))}
                           </div>
                        </div>
                     )}
                  </div>
               )}

               {/* Step 3: Enter Details - Compact */}
               {requestStep === 3 && (
                  <div className="space-y-3">
                     <h3 className="text-sm font-semibold text-gray-800 dark:text-slate-100">Appointment Details</h3>

                     <div>
                        <label className="block text-xs font-medium text-gray-700 dark:text-slate-300 mb-1">Type *</label>
                        <select
                           className="w-full px-3 py-1.5 text-sm border border-gray-300 dark:border-slate-600 rounded focus:ring-1 focus:ring-blue-500 outline-none bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100"
                           value={requestForm.type}
                           onChange={e => setRequestForm({ ...requestForm, type: e.target.value })}
                           required
                        >
                           <option value="">Select type</option>
                           {appointmentTypes.map(type => (
                              <option key={type} value={type}>
                                 {type}
                              </option>
                           ))}
                        </select>
                     </div>

                     <div>
                        <label className="block text-xs font-medium text-gray-700 dark:text-slate-300 mb-1">Reason for Visit *</label>
                        <textarea
                           className="w-full px-3 py-1.5 text-sm border border-gray-300 dark:border-slate-600 rounded focus:ring-1 focus:ring-blue-500 outline-none resize-none h-16 bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100"
                           value={requestForm.reason}
                           onChange={e => setRequestForm({ ...requestForm, reason: e.target.value })}
                           placeholder="Briefly describe your symptoms..."
                           required
                        />
                     </div>

                     <div>
                        <label className="block text-xs font-medium text-gray-700 dark:text-slate-300 mb-1">Special Requirements</label>
                        <textarea
                           className="w-full px-3 py-1.5 text-sm border border-gray-300 dark:border-slate-600 rounded focus:ring-1 focus:ring-blue-500 outline-none resize-none h-12 bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100"
                           value={requestForm.specialRequirements}
                           onChange={e => setRequestForm({ ...requestForm, specialRequirements: e.target.value })}
                           placeholder="Wheelchair access, interpreter, etc."
                        />
                     </div>

                     <Alert
                        type="info"
                        message="We'll confirm your request within 24 hours."
                     />
                  </div>
               )}

               {/* Navigation Buttons - Compact */}
               <div className="flex justify-between pt-3 border-t dark:border-slate-700">
                  <Button
                     type="button"
                     variant="secondary"
                     size="sm"
                     onClick={() => {
                        if (requestStep > 1) {
                           setRequestStep(requestStep - 1);
                        } else {
                           setIsRequestModalOpen(false);
                           setRequestStep(1);
                        }
                     }}
                  >
                     {requestStep === 1 ? 'Cancel' : 'Back'}
                  </Button>
                  <Button type="submit" size="sm" disabled={
                     (requestStep === 1 && (!requestForm.department || !requestForm.doctor)) ||
                     (requestStep === 2 && (!requestForm.date || !requestForm.time)) ||
                     (requestStep === 3 && (!requestForm.type || !requestForm.reason))
                  }>
                     {requestStep === 3 ? 'Submit' : 'Next'}
                  </Button>
               </div>
            </form>
         </Modal>

         {/* Cancel Appointment Modal - Compact */}
         <Modal
            isOpen={isCancelModalOpen}
            onClose={() => {
               setIsCancelModalOpen(false);
               setAppointmentToCancel(null);
               setCancellationReason('');
            }}
            title="Cancel Appointment"
         >
            {appointmentToCancel && (
               <div className="space-y-3">
                  <Alert
                     type="warning"
                     message="Please cancel at least 24 hours in advance to avoid charges."
                  />

                  {/* Appointment Details - Compact */}
                  <Card className="p-3 bg-gray-50 dark:bg-slate-800/50">
                     <h4 className="text-xs font-medium text-gray-600 dark:text-slate-400 mb-1">Appointment Details</h4>
                     <div className="space-y-0.5 text-sm text-gray-700 dark:text-slate-300">
                        <p><span className="text-gray-500">Type:</span> {appointmentToCancel.type}</p>
                        <p><span className="text-gray-500">Doctor:</span> {appointmentToCancel.doctorName}</p>
                        <p><span className="text-gray-500">Date:</span> {format(parseISO(appointmentToCancel.date), 'MMM dd, yyyy')} at {appointmentToCancel.time}</p>
                     </div>
                  </Card>

                  {/* Cancellation Reason - Compact */}
                  <div>
                     <label className="block text-xs font-medium text-gray-700 dark:text-slate-300 mb-1">Reason *</label>
                     <select
                        className="w-full px-3 py-1.5 text-sm border border-gray-300 dark:border-slate-600 rounded focus:ring-1 focus:ring-blue-500 outline-none bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100"
                        value={cancellationReason}
                        onChange={e => setCancellationReason(e.target.value)}
                        required
                     >
                        <option value="">Select a reason</option>
                        {cancellationReasons.map(reason => (
                           <option key={reason} value={reason}>
                              {reason}
                           </option>
                        ))}
                     </select>
                  </div>

                  {/* Action Buttons - Compact */}
                  <div className="flex justify-end gap-2 pt-3 border-t dark:border-slate-700">
                     <Button
                        type="button"
                        variant="secondary"
                        size="sm"
                        onClick={() => {
                           setIsCancelModalOpen(false);
                           setAppointmentToCancel(null);
                           setCancellationReason('');
                        }}
                     >
                        Keep
                     </Button>
                     <Button
                        type="button"
                        size="sm"
                        onClick={handleCancelAppointment}
                        className="bg-red-600 hover:bg-red-700"
                     >
                        Confirm Cancel
                     </Button>
                  </div>
               </div>
            )}
         </Modal>

         {/* Details Modal */}
         <Modal
            isOpen={isDetailsModalOpen}
            onClose={() => {
               setIsDetailsModalOpen(false);
               setSelectedAppointment(null);
            }}
            title="Appointment Details"
         >
            {selectedAppointment && (
               <div className="space-y-4 text-sm text-gray-700 dark:text-slate-300">
                  <div className="flex justify-between items-center mb-2">
                     <h4 className="text-base font-semibold text-gray-800 dark:text-slate-100">{selectedAppointment.type}</h4>
                     <Badge type={selectedAppointment.status === 'Confirmed' ? 'green' : selectedAppointment.status === 'Pending' ? 'yellow' : 'blue'}>
                        {selectedAppointment.status}
                     </Badge>
                  </div>

                  <div className="grid grid-cols-2 gap-4 bg-gray-50 dark:bg-slate-800/50 p-3 rounded-lg">
                     <div>
                        <p className="text-xs text-gray-500 mb-1">Doctor</p>
                        <p className="font-medium flex items-center gap-1.5"><User className="w-3.5 h-3.5 text-gray-400" /> {selectedAppointment.doctorName}</p>
                     </div>
                     <div>
                        <p className="text-xs text-gray-500 mb-1">Date & Time</p>
                        <p className="font-medium flex items-center gap-1.5"><Clock className="w-3.5 h-3.5 text-gray-400" /> {format(parseISO(selectedAppointment.date), 'MMM dd, yyyy')} at {selectedAppointment.time}</p>
                     </div>
                     <div>
                        <p className="text-xs text-gray-500 mb-1">Department</p>
                        <p className="font-medium flex items-center gap-1.5"><Building2 className="w-3.5 h-3.5 text-gray-400" /> {selectedAppointment.department}</p>
                     </div>
                     <div>
                        <p className="text-xs text-gray-500 mb-1">Location / Room</p>
                        <p className="font-medium flex items-center gap-1.5"><MapPin className="w-3.5 h-3.5 text-gray-400" /> {selectedAppointment.location || 'Main Clinic'}, Room {selectedAppointment.room || 'TBD'}</p>
                     </div>
                  </div>

                  {selectedAppointment.reason && (
                     <div>
                        <p className="text-xs text-gray-500 mb-1">Reason for Visit</p>
                        <p className="bg-white dark:bg-slate-800 p-2.5 rounded border border-gray-200 dark:border-slate-700">{selectedAppointment.reason}</p>
                     </div>
                  )}

                  <div className="pt-4 border-t dark:border-slate-700 flex justify-end">
                     <Button variant="secondary" onClick={() => setIsDetailsModalOpen(false)}>Close</Button>
                  </div>
               </div>
            )}
         </Modal>

         {/* Reschedule Modal */}
         <Modal
            isOpen={isRescheduleModalOpen}
            onClose={() => {
               setIsRescheduleModalOpen(false);
               setAppointmentToReschedule(null);
            }}
            title="Reschedule Appointment"
         >
            {appointmentToReschedule && (
               <form onSubmit={handleRescheduleSubmit} className="space-y-4">
                  <Alert type="info" message={`Rescheduling ${appointmentToReschedule.type} with ${appointmentToReschedule.doctorName}.`} />

                  <Input
                     type="date"
                     label="New Preferred Date *"
                     value={rescheduleData.date}
                     onChange={e => setRescheduleData({ ...rescheduleData, date: e.target.value, time: '' })}
                     min={format(new Date(), 'yyyy-MM-dd')}
                     required
                  />

                  {rescheduleData.date && (
                     <div>
                        <label className="block text-xs font-medium text-gray-700 dark:text-slate-300 mb-1">Select New Time *</label>
                        <div className="grid grid-cols-4 gap-1 max-h-48 overflow-y-auto">
                           {[...mockTimeSlots.morning, ...mockTimeSlots.afternoon, ...mockTimeSlots.evening].map(slot => (
                              <button
                                 key={slot}
                                 type="button"
                                 onClick={() => setRescheduleData({ ...rescheduleData, time: slot })}
                                 className={`p-1.5 text-xs border rounded transition-colors ${rescheduleData.time === slot
                                    ? 'border-blue-500 bg-blue-500 text-white'
                                    : 'border-gray-300 dark:border-slate-600 hover:border-blue-300 dark:hover:border-blue-700 bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100'
                                    }`}
                              >
                                 {slot}
                              </button>
                           ))}
                        </div>
                     </div>
                  )}

                  <div className="flex justify-end gap-2 pt-3 border-t dark:border-slate-700">
                     <Button type="button" variant="secondary" onClick={() => setIsRescheduleModalOpen(false)}>Cancel</Button>
                     <Button type="submit" disabled={!rescheduleData.date || !rescheduleData.time}>Submit Request</Button>
                  </div>
               </form>
            )}
         </Modal>
      </div>
   );
};

export default PatientAppointments;
