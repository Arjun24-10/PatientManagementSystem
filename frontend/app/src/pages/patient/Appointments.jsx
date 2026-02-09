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

   // Render appointment card
   const renderAppointmentCard = (appt) => {
      const dateObj = parseISO(appt.date);
      const month = format(dateObj, 'MMM');
      const day = format(dateObj, 'dd');

      return (
         <Card
            key={appt.id}
            className="p-5 flex flex-col md:flex-row justify-between items-start md:items-center hover:shadow-lg transition-all duration-200 border border-gray-100 dark:border-slate-700"
         >
            <div className="flex items-start space-x-4 w-full md:w-auto">
               {/* Date Badge */}
               <div className="bg-gradient-to-br from-blue-500 to-blue-600 p-4 rounded-xl text-white text-center min-w-[80px] shadow-md">
                  <p className="text-xs font-bold uppercase tracking-wider">{month}</p>
                  <p className="text-2xl font-bold">{day}</p>
               </div>

               {/* Appointment Details */}
               <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1">
                     <h4 className="font-bold text-gray-800 dark:text-slate-100 text-lg">{appt.type}</h4>
                     <Badge
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

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 mt-2 text-sm text-gray-600 dark:text-slate-300">
                     <div className="flex items-center">
                        <User className="w-4 h-4 mr-2 text-blue-500" />
                        <span>{appt.doctorName}</span>
                     </div>
                     <div className="flex items-center">
                        <Building2 className="w-4 h-4 mr-2 text-purple-500" />
                        <span>{appt.department || 'General'}</span>
                     </div>
                     <div className="flex items-center">
                        <Clock className="w-4 h-4 mr-2 text-green-500" />
                        <span>{appt.time} ({appt.duration} mins)</span>
                     </div>
                     <div className="flex items-center">
                        <MapPin className="w-4 h-4 mr-2 text-red-500" />
                        <span>{appt.location || appt.room || 'Main Clinic'}</span>
                     </div>
                  </div>

                  {appt.cancellationReason && (
                     <div className="mt-2 text-sm text-red-600 dark:text-red-400 flex items-center">
                        <AlertCircle className="w-4 h-4 mr-1" />
                        Reason: {appt.cancellationReason}
                     </div>
                  )}
               </div>
            </div>

            {/* Action Buttons */}
            <div className="mt-4 md:mt-0 flex flex-wrap gap-2">
               {activeTab === 'upcoming' && appt.status !== 'Cancelled' && (
                  <>
                     <Button variant="outline" className="p-2" title="View Details">
                        <Calendar className="w-4 h-4" />
                     </Button>
                     <Button variant="outline" className="p-2" title="Reschedule">
                        <RefreshCw className="w-4 h-4" />
                     </Button>
                     <Button
                        variant="outline"
                        className="p-2 text-red-600 dark:text-red-400 border-red-200 dark:border-red-800 hover:bg-red-50 dark:hover:bg-red-900/20"
                        onClick={() => openCancelModal(appt)}
                        title="Cancel Appointment"
                     >
                        <AlertCircle className="w-4 h-4" />
                     </Button>
                  </>
               )}
               {activeTab === 'past' && (
                  <>
                     <Button variant="outline" className="p-2" title="View Summary">
                        <Calendar className="w-4 h-4" />
                     </Button>
                     <Button variant="primary" className="p-2" title="Book Follow-up">
                        <Plus className="w-4 h-4" />
                     </Button>
                  </>
               )}
               {activeTab === 'cancelled' && (
                  <Button variant="primary" className="p-2" title="Rebook Appointment">
                     <RefreshCw className="w-4 h-4" />
                  </Button>
               )}
            </div>
         </Card>
      );
   };

   return (
      <div className="space-y-6">
         {/* Header */}
         <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
            <div>
               <h2 className="text-2xl font-bold text-gray-800 dark:text-slate-100">My Appointments</h2>
               <p className="text-gray-500 dark:text-slate-400">Manage your healthcare appointments</p>
            </div>
            <div className="flex items-center gap-3">
               <div className="flex bg-gray-100 dark:bg-slate-700 p-1 rounded-lg">
                  <button
                     onClick={() => setViewMode('list')}
                     className={`p-2 rounded-md transition-all ${viewMode === 'list' ? 'bg-white dark:bg-slate-800 shadow-sm text-blue-600 dark:text-blue-400' : 'text-gray-500 dark:text-slate-400 hover:text-gray-700 dark:hover:text-slate-200'}`}
                     title="List View"
                  >
                     <List size={20} />
                  </button>
                  <button
                     onClick={() => setViewMode('calendar')}
                     className={`p-2 rounded-md transition-all ${viewMode === 'calendar' ? 'bg-white dark:bg-slate-800 shadow-sm text-blue-600 dark:text-blue-400' : 'text-gray-500 dark:text-slate-400 hover:text-gray-700 dark:hover:text-slate-200'}`}
                     title="Calendar View"
                  >
                     <LayoutGrid size={20} />
                  </button>
               </div>
               <Button onClick={() => setIsRequestModalOpen(true)} className="whitespace-nowrap inline-flex items-center">
                  <Plus className="w-4 h-4 mr-2" />
                  Request New
               </Button>
            </div>
         </div>

         <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
            {/* Main Content */}
            <div className="lg:col-span-3 space-y-6">
               {viewMode === 'list' ? (
                  <>
                     {/* Tabs */}
                     <div className="border-b border-gray-200 dark:border-slate-700">
                        <nav className="-mb-px flex space-x-8">
                           {[
                              { key: 'upcoming', label: 'Upcoming' },
                              { key: 'past', label: 'Past' },
                              { key: 'cancelled', label: 'Cancelled' },
                           ].map(tab => (
                              <button
                                 key={tab.key}
                                 onClick={() => setActiveTab(tab.key)}
                                 className={`
                        whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm capitalize transition-colors
                        ${activeTab === tab.key
                                       ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                                       : 'border-transparent text-gray-500 dark:text-slate-400 hover:text-gray-700 dark:hover:text-slate-200 hover:border-gray-300 dark:hover:border-slate-600'
                                    }
                      `}
                              >
                                 {tab.label}
                                 <span className="ml-2 bg-gray-100 dark:bg-slate-700 text-gray-600 dark:text-slate-300 py-0.5 px-2 rounded-full text-xs">
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

                     {/* Appointments List */}
                     <div className="space-y-4">
                        {filteredAppointments.length > 0 ? (
                           filteredAppointments.map(renderAppointmentCard)
                        ) : (
                           <div className="p-12 text-center text-gray-500 dark:text-slate-400 bg-white dark:bg-slate-800 rounded-xl border-2 border-dashed border-gray-200 dark:border-slate-700">
                              <Calendar className="w-12 h-12 mx-auto mb-2 text-gray-300 dark:text-slate-600" />
                              <p>No {activeTab} appointments found.</p>
                           </div>
                        )}
                     </div>
                  </>
               ) : (
                  /* Calendar View */
                  <Card className="p-6">
                     <div className="flex justify-between items-center mb-6">
                        <h3 className="text-xl font-bold text-gray-800 dark:text-slate-100">
                           {format(currentMonth, 'MMMM yyyy')}
                        </h3>
                        <div className="flex gap-2">
                           <Button
                              variant="outline"
                              onClick={() => setCurrentMonth(addDays(currentMonth, -30))}
                              className="p-2"
                           >
                              <ChevronLeft className="w-4 h-4" />
                           </Button>
                           <Button
                              variant="outline"
                              onClick={() => setCurrentMonth(new Date())}
                              className="text-sm"
                           >
                              Today
                           </Button>
                           <Button
                              variant="outline"
                              onClick={() => setCurrentMonth(addDays(currentMonth, 30))}
                              className="p-2"
                           >
                              <ChevronRight className="w-4 h-4" />
                           </Button>
                        </div>
                     </div>

                     {/* Calendar Grid */}
                     <div className="grid grid-cols-7 gap-2">
                        {['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].map(day => (
                           <div key={day} className="text-center text-sm font-semibold text-gray-600 dark:text-slate-300 py-2">
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
                        min-h-[80px] p-2 border rounded-lg cursor-pointer hover:bg-gray-50 dark:hover:bg-slate-700/50 transition-colors
                        ${isToday ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20' : 'border-gray-200 dark:border-slate-700'}
                      `}
                              >
                                 <div className={`text-sm font-medium ${isToday ? 'text-blue-600 dark:text-blue-400' : 'text-gray-700 dark:text-slate-200'}`}>
                                    {format(day, 'd')}
                                 </div>
                                 <div className="mt-1 space-y-1">
                                    {dayAppointments.slice(0, 2).map(appt => (
                                       <div
                                          key={appt.id}
                                          className={`text-xs p-1 rounded truncate ${appt.status === 'Confirmed'
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
                                       <div className="text-xs text-gray-500 dark:text-slate-400">+{dayAppointments.length - 2} more</div>
                                    )}
                                 </div>
                              </div>
                           );
                        })}
                     </div>

                     {/* Legend */}
                     <div className="mt-6 flex flex-wrap gap-4 text-sm">
                        <div className="flex items-center gap-2">
                           <div className="w-3 h-3 rounded bg-green-500"></div>
                           <span>Confirmed</span>
                        </div>
                        <div className="flex items-center gap-2">
                           <div className="w-3 h-3 rounded bg-yellow-500"></div>
                           <span>Pending</span>
                        </div>
                        <div className="flex items-center gap-2">
                           <div className="w-3 h-3 rounded bg-blue-500"></div>
                           <span>Completed</span>
                        </div>
                        <div className="flex items-center gap-2">
                           <div className="w-3 h-3 rounded bg-red-500"></div>
                           <span>Cancelled</span>
                        </div>
                     </div>
                  </Card>
               )}
            </div>

            {/* Reminders Sidebar */}
            <div className="lg:col-span-1">
               <Card className="p-5 sticky top-6">
                  <div className="flex items-center justify-between mb-4">
                     <h3 className="font-bold text-gray-800 dark:text-slate-100 flex items-center">
                        <Bell className="w-5 h-5 mr-2 text-blue-500" />
                        Reminders
                        {upcomingReminders.length > 0 && (
                           <span className="ml-2 bg-red-500 text-white text-xs rounded-full w-5 h-5 flex items-center justify-center">
                              {upcomingReminders.length}
                           </span>
                        )}
                     </h3>
                  </div>

                  <div className="space-y-3">
                     {upcomingReminders.length > 0 ? (
                        upcomingReminders.map(appt => (
                           <div
                              key={appt.id}
                              className="p-3 bg-gradient-to-br from-blue-50 to-purple-50 dark:from-blue-900/20 dark:to-purple-900/20 rounded-lg border border-blue-100 dark:border-slate-700"
                           >
                              <div className="flex justify-between items-start mb-2">
                                 <p className="font-semibold text-sm text-gray-800 dark:text-slate-100">{appt.type}</p>
                                 <Badge type="green" className="text-xs">
                                    {getCountdown(appt)}
                                 </Badge>
                              </div>
                              <p className="text-xs text-gray-600 dark:text-slate-300 mb-1">{appt.doctorName}</p>
                              <p className="text-xs text-gray-500 dark:text-slate-400">
                                 {format(parseISO(appt.date), 'MMM dd')} at {appt.time}
                              </p>
                              <Button variant="outline" className="w-full mt-2 text-xs py-1">
                                 <Download className="w-3 h-3 mr-1" />
                                 Add to Calendar
                              </Button>
                           </div>
                        ))
                     ) : (
                        <p className="text-sm text-gray-500 dark:text-slate-400 text-center py-4">No upcoming appointments</p>
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
            <form onSubmit={handleRequestSubmit} className="space-y-6">
               {/* Progress Indicator */}
               <div className="flex items-center justify-between mb-6">
                  {[1, 2, 3].map(step => (
                     <div key={step} className="flex items-center flex-1">
                        <div
                           className={`w-8 h-8 rounded-full flex items-center justify-center font-bold text-sm ${step <= requestStep
                              ? 'bg-blue-600 text-white'
                              : 'bg-gray-200 dark:bg-slate-700 text-gray-500 dark:text-slate-400'
                              }`}
                        >
                           {step < requestStep ? <Check className="w-4 h-4" /> : step}
                        </div>
                        {step < 3 && (
                           <div
                              className={`flex-1 h-1 mx-2 ${step < requestStep ? 'bg-blue-600' : 'bg-gray-200 dark:bg-slate-700'
                                 }`}
                           ></div>
                        )}
                     </div>
                  ))}
               </div>

               {/* Step 1: Select Department and Doctor */}
               {requestStep === 1 && (
                  <div className="space-y-4">
                     <h3 className="font-bold text-lg text-gray-800 dark:text-slate-100">Select Department & Doctor</h3>

                     <div className="space-y-2">
                        <label className="block text-sm font-medium text-gray-700 dark:text-slate-300">Department *</label>
                        <select
                           className="w-full px-4 py-2 border border-gray-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-blue-500 outline-none bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100"
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
                        <div className="space-y-2">
                           <label className="block text-sm font-medium text-gray-700 dark:text-slate-300">Doctor *</label>
                           <div className="grid gap-3">
                              {filteredDoctors.map(doctor => (
                                 <div
                                    key={doctor.id}
                                    onClick={() => setRequestForm({ ...requestForm, doctor: doctor.id })}
                                    className={`p-4 border-2 rounded-lg cursor-pointer transition-all ${requestForm.doctor === doctor.id
                                       ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20'
                                       : 'border-gray-200 dark:border-slate-700 hover:border-gray-300 dark:hover:border-slate-600'
                                       }`}
                                 >
                                    <div className="flex items-center justify-between">
                                       <div className="flex items-center gap-3">
                                          <div className="w-10 h-10 rounded-full bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400 flex items-center justify-center font-bold">
                                             {doctor.avatar}
                                          </div>
                                          <div>
                                             <p className="font-semibold text-gray-800 dark:text-slate-100">{doctor.name}</p>
                                             <p className="text-sm text-gray-500 dark:text-slate-400">{doctor.specialization}</p>
                                             <p className="text-xs text-gray-400 dark:text-slate-500">{doctor.experience}</p>
                                          </div>
                                       </div>
                                       <div className="text-right">
                                          <div className="flex items-center gap-1 text-yellow-500">
                                             <span className="text-sm font-semibold">{doctor.rating}</span>
                                             <span>⭐</span>
                                          </div>
                                       </div>
                                    </div>
                                 </div>
                              ))}
                           </div>
                        </div>
                     )}
                  </div>
               )}

               {/* Step 2: Choose Date and Time */}
               {requestStep === 2 && (
                  <div className="space-y-4">
                     <h3 className="font-bold text-lg text-gray-800 dark:text-slate-100">Choose Date & Time</h3>

                     <Input
                        type="date"
                        label="Preferred Date *"
                        value={requestForm.date}
                        onChange={e => setRequestForm({ ...requestForm, date: e.target.value, time: '' })}
                        min={format(new Date(), 'yyyy-MM-dd')}
                        required
                     />

                     {requestForm.date && (
                        <div className="space-y-2">
                           <label className="block text-sm font-medium text-gray-700 dark:text-slate-300">Available Time Slots *</label>
                           <div className="grid grid-cols-3 gap-2 max-h-64 overflow-y-auto">
                              {availableTimeSlots.map(slot => (
                                 <button
                                    key={slot}
                                    type="button"
                                    onClick={() => setRequestForm({ ...requestForm, time: slot })}
                                    className={`p-2 text-sm border rounded-lg transition-all ${requestForm.time === slot
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

               {/* Step 3: Enter Details */}
               {requestStep === 3 && (
                  <div className="space-y-4">
                     <h3 className="font-bold text-lg text-gray-800 dark:text-slate-100">Appointment Details</h3>

                     <div className="space-y-2">
                        <label className="block text-sm font-medium text-gray-700 dark:text-slate-300">Appointment Type *</label>
                        <select
                           className="w-full px-4 py-2 border border-gray-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-blue-500 outline-none bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100"
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

                     <div className="space-y-2">
                        <label className="block text-sm font-medium text-gray-700 dark:text-slate-300">Reason for Visit *</label>
                        <textarea
                           className="w-full px-4 py-2 border border-gray-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-blue-500 outline-none resize-none h-24 bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100"
                           value={requestForm.reason}
                           onChange={e => setRequestForm({ ...requestForm, reason: e.target.value })}
                           placeholder="Briefly describe your symptoms or reason for visit..."
                           required
                        />
                     </div>

                     <div className="space-y-2">
                        <label className="block text-sm font-medium text-gray-700 dark:text-slate-300">Special Requirements (Optional)</label>
                        <textarea
                           className="w-full px-4 py-2 border border-gray-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-blue-500 outline-none resize-none h-20 bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100"
                           value={requestForm.specialRequirements}
                           onChange={e => setRequestForm({ ...requestForm, specialRequirements: e.target.value })}
                           placeholder="Wheelchair access, interpreter needed, etc."
                        />
                     </div>

                     <Alert
                        type="info"
                        message="Our team will review your request and send you a confirmation email within 24 hours."
                     />
                  </div>
               )}

               {/* Navigation Buttons */}
               <div className="flex justify-between pt-4 border-t dark:border-slate-700">
                  <Button
                     type="button"
                     variant="secondary"
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
                  <Button type="submit" disabled={
                     (requestStep === 1 && (!requestForm.department || !requestForm.doctor)) ||
                     (requestStep === 2 && (!requestForm.date || !requestForm.time)) ||
                     (requestStep === 3 && (!requestForm.type || !requestForm.reason))
                  }>
                     {requestStep === 3 ? 'Submit Request' : 'Next'}
                  </Button>
               </div>
            </form>
         </Modal>

         {/* Cancel Appointment Modal */}
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
               <div className="space-y-4">
                  <Alert
                     type="warning"
                     message="⚠️ Cancellation Policy: Please cancel at least 24 hours in advance to avoid charges."
                  />

                  {/* Appointment Details */}
                  <Card className="p-4 bg-gray-50 dark:bg-slate-800/50">
                     <h4 className="font-semibold text-gray-800 dark:text-slate-100 mb-2">Appointment Details</h4>
                     <div className="space-y-1 text-sm text-gray-600 dark:text-slate-300">
                        <p><strong>Type:</strong> {appointmentToCancel.type}</p>
                        <p><strong>Doctor:</strong> {appointmentToCancel.doctorName}</p>
                        <p><strong>Date:</strong> {format(parseISO(appointmentToCancel.date), 'MMMM dd, yyyy')}</p>
                        <p><strong>Time:</strong> {appointmentToCancel.time}</p>
                     </div>
                  </Card>

                  {/* Cancellation Reason */}
                  <div className="space-y-2">
                     <label className="block text-sm font-medium text-gray-700 dark:text-slate-300">Reason for Cancellation *</label>
                     <select
                        className="w-full px-4 py-2 border border-gray-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-blue-500 outline-none bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100"
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

                  {/* Action Buttons */}
                  <div className="flex justify-end gap-3 pt-4 border-t dark:border-slate-700">
                     <Button
                        type="button"
                        variant="secondary"
                        onClick={() => {
                           setIsCancelModalOpen(false);
                           setAppointmentToCancel(null);
                           setCancellationReason('');
                        }}
                     >
                        Keep Appointment
                     </Button>
                     <Button
                        type="button"
                        variant="danger"
                        onClick={handleCancelAppointment}
                        className="bg-red-600 hover:bg-red-700"
                     >
                        Confirm Cancellation
                     </Button>
                  </div>
               </div>
            )}
         </Modal>
      </div>
   );
};

export default PatientAppointments;
