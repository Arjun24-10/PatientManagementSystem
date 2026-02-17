import React, { useState, useMemo, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
   Activity,
   AlertTriangle,
   Calendar,
   CheckSquare,
   Clock,
   Heart,
   Pill,
   Users,
   ClipboardList,
   TrendingUp,
   Bell,
   RefreshCw,
} from 'lucide-react';

import Card from '../../components/common/Card';
import Button from '../../components/common/Button';
import Badge from '../../components/common/Badge';
import { mockNurseOverview } from '../../mocks/nurseOverview';

const NurseDashboard = () => {
   const navigate = useNavigate();
   const [overview, setOverview] = useState(mockNurseOverview);
   const [currentTime, setCurrentTime] = useState(new Date());
   const [activeFilter, setActiveFilter] = useState('all');

   // Update time every minute
   useEffect(() => {
      const interval = setInterval(() => setCurrentTime(new Date()), 60000);
      return () => clearInterval(interval);
   }, []);

   // Greeting based on time
   const greeting = useMemo(() => {
      const hour = currentTime.getHours();
      if (hour < 12) return 'Good Morning';
      if (hour < 18) return 'Good Afternoon';
      return 'Good Evening';
   }, [currentTime]);

   // Format current date/time
   const formattedDate = useMemo(
      () =>
         currentTime.toLocaleString(undefined, {
            weekday: 'long',
            month: 'long',
            day: 'numeric',
            hour: 'numeric',
            minute: '2-digit',
         }),
      [currentTime]
   );

   // Calculate shift progress
   const shiftProgress = useMemo(() => {
      const shiftDate = overview.shift.date;
      const start = new Date(`${shiftDate}T${overview.shift.startTime}:00`);
      const end = new Date(`${shiftDate}T${overview.shift.endTime}:00`);

      if (end < start) end.setDate(end.getDate() + 1);

      const elapsed = Math.max(0, Math.min(currentTime - start, end - start));
      const total = end - start;
      const percentage = total === 0 ? 0 : Math.min(100, Math.round((elapsed / total) * 100));

      const remainingMs = Math.max(0, end - currentTime);
      const hours = Math.floor(remainingMs / (1000 * 60 * 60));
      const minutes = Math.floor((remainingMs / (1000 * 60)) % 60);

      return {
         percentage,
         remaining: `${hours}h ${minutes}m remaining`,
      };
   }, [currentTime, overview.shift]);

   // Filter patients
   const filteredPatients = useMemo(() => {
      let patients = overview.assignedPatients;

      if (activeFilter === 'critical') {
         patients = patients.filter(p => p.acuityLevel === 'critical');
      } else if (activeFilter === 'needs-attention') {
         patients = patients.filter(
            p => p.acuityLevel === 'high' || p.vitalsStatus === 'overdue' || p.medicationStatus === 'overdue'
         );
      } else if (activeFilter === 'stable') {
         patients = patients.filter(p => p.acuityLevel === 'stable' || p.acuityLevel === 'moderate');
      }

      return patients.sort((a, b) => {
         const priorityOrder = ['critical', 'high', 'moderate', 'stable'];
         return priorityOrder.indexOf(a.acuityLevel) - priorityOrder.indexOf(b.acuityLevel);
      });
   }, [overview.assignedPatients, activeFilter]);

   // Get acuity badge style
   const getAcuityBadge = (level) => {
      const styles = {
         critical: 'red',
         high: 'yellow',
         moderate: 'blue',
         stable: 'green',
      };
      return styles[level] || 'gray';
   };

   // Get status icon
   const getStatusIcon = (status) => {
      if (status === 'overdue') return <AlertTriangle className="w-3.5 h-3.5 text-red-500" />;
      if (status === 'due') return <Clock className="w-3.5 h-3.5 text-yellow-500" />;
      return <CheckSquare className="w-3.5 h-3.5 text-green-500" />;
   };

   const nurseName = overview.nurse.name.split(' ')[0];
   const stats = overview.stats;

   return (
      <div className="space-y-4">
         {/* Header */}
         <Card className="overflow-hidden">
            <div className="p-4 flex flex-col lg:flex-row gap-4 lg:items-center justify-between">
               <div>
                  <p className="text-xs font-medium text-blue-600 dark:text-blue-400 uppercase tracking-wide">
                     {overview.nurse.unit}
                  </p>
                  <h1 className="text-xl font-bold text-gray-900 dark:text-slate-100 mt-1">
                     {greeting}, Nurse {nurseName}
                  </h1>
                  <p className="text-sm text-gray-500 dark:text-slate-400 mt-1 flex items-center gap-1.5">
                     <Clock className="w-3.5 h-3.5" />
                     {formattedDate}
                  </p>
               </div>

               <div className="flex flex-col sm:flex-row gap-3">
                  {/* Shift Info */}
                  <Card className="p-3 bg-blue-50 dark:bg-blue-900/20 border-blue-200 dark:border-blue-800">
                     <div className="flex items-center justify-between mb-2">
                        <div>
                           <Badge type="blue" size="sm">
                              {overview.shift.type === 'day' ? 'Day Shift' : 'Night Shift'}
                           </Badge>
                           <p className="text-sm font-semibold text-gray-900 dark:text-slate-100 mt-1">
                              {overview.shift.startTime} - {overview.shift.endTime}
                           </p>
                        </div>
                        <Calendar className="w-6 h-6 text-blue-600 dark:text-blue-400" />
                     </div>
                     <div className="space-y-1">
                        <div className="h-2 bg-gray-200 dark:bg-slate-700 rounded-full overflow-hidden">
                           <div
                              className="h-full bg-blue-600 dark:bg-blue-500 rounded-full transition-all"
                              style={{ width: `${shiftProgress.percentage}%` }}
                           />
                        </div>
                        <p className="text-xs text-gray-600 dark:text-slate-400">{shiftProgress.remaining}</p>
                     </div>
                  </Card>

                  {/* Emergency Button */}
                  <Button
                     variant="outline"
                     className="border-red-300 dark:border-red-700 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 flex items-center gap-2"
                  >
                     <AlertTriangle className="w-4 h-4" />
                     Call Code Team
                  </Button>
               </div>
            </div>
         </Card>

         {/* Quick Stats */}
         <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            <Card className="p-3 border-l-4 border-blue-500 hover:shadow-md transition-shadow">
               <div className="flex items-start justify-between">
                  <div>
                     <p className="text-xs text-gray-500 dark:text-slate-400 font-medium">Assigned Patients</p>
                     <p className="text-2xl font-bold text-gray-900 dark:text-slate-100 mt-1">{stats.assignedPatients}</p>
                  </div>
                  <div className="w-10 h-10 bg-blue-100 dark:bg-blue-900/30 rounded-lg flex items-center justify-center">
                     <Users className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                  </div>
               </div>
            </Card>

            <Card className="p-3 border-l-4 border-orange-500 hover:shadow-md transition-shadow">
               <div className="flex items-start justify-between">
                  <div>
                     <p className="text-xs text-gray-500 dark:text-slate-400 font-medium">Vitals Due</p>
                     <p className="text-2xl font-bold text-gray-900 dark:text-slate-100 mt-1">{stats.pendingVitals}</p>
                     {stats.overdueVitals > 0 && (
                        <p className="text-xs text-red-600 dark:text-red-400 font-medium mt-1">
                           {stats.overdueVitals} overdue
                        </p>
                     )}
                  </div>
                  <div className="w-10 h-10 bg-orange-100 dark:bg-orange-900/30 rounded-lg flex items-center justify-center">
                     <Activity className="w-5 h-5 text-orange-600 dark:text-orange-400" />
                  </div>
               </div>
            </Card>

            <Card className="p-3 border-l-4 border-purple-500 hover:shadow-md transition-shadow">
               <div className="flex items-start justify-between">
                  <div>
                     <p className="text-xs text-gray-500 dark:text-slate-400 font-medium">Medications Pending</p>
                     <p className="text-2xl font-bold text-gray-900 dark:text-slate-100 mt-1">{stats.medicationsDue}</p>
                     {stats.overdueMedications > 0 && (
                        <p className="text-xs text-red-600 dark:text-red-400 font-medium mt-1">
                           {stats.overdueMedications} overdue
                        </p>
                     )}
                  </div>
                  <div className="w-10 h-10 bg-purple-100 dark:bg-purple-900/30 rounded-lg flex items-center justify-center">
                     <Pill className="w-5 h-5 text-purple-600 dark:text-purple-400" />
                  </div>
               </div>
            </Card>

            <Card className="p-3 border-l-4 border-green-500 hover:shadow-md transition-shadow">
               <div className="flex items-start justify-between">
                  <div>
                     <p className="text-xs text-gray-500 dark:text-slate-400 font-medium">Tasks Remaining</p>
                     <p className="text-2xl font-bold text-gray-900 dark:text-slate-100 mt-1">{stats.pendingTasks}</p>
                     {stats.highPriorityTasks > 0 && (
                        <p className="text-xs text-orange-600 dark:text-orange-400 font-medium mt-1">
                           {stats.highPriorityTasks} high priority
                        </p>
                     )}
                  </div>
                  <div className="w-10 h-10 bg-green-100 dark:bg-green-900/30 rounded-lg flex items-center justify-center">
                     <CheckSquare className="w-5 h-5 text-green-600 dark:text-green-400" />
                  </div>
               </div>
            </Card>
         </div>

         {/* Assigned Patients */}
         <Card>
            <div className="px-4 py-3 border-b border-gray-200 dark:border-slate-700 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
               <div className="flex items-center gap-2">
                  <Users className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                  <h2 className="text-sm font-bold text-gray-900 dark:text-slate-100">Assigned Patients</h2>
                  <Badge size="sm">{filteredPatients.length}</Badge>
               </div>

               <div className="flex gap-2 flex-wrap">
                  {['all', 'critical', 'needs-attention', 'stable'].map((filter) => (
                     <button
                        key={filter}
                        onClick={() => setActiveFilter(filter)}
                        className={`px-3 py-1 text-xs font-medium rounded-md transition-colors ${activeFilter === filter
                           ? 'bg-blue-600 text-white'
                           : 'bg-gray-100 dark:bg-slate-700 text-gray-700 dark:text-slate-300 hover:bg-gray-200 dark:hover:bg-slate-600'
                           }`}
                     >
                        {filter === 'all'
                           ? 'All'
                           : filter === 'needs-attention'
                              ? 'Needs Attention'
                              : filter.charAt(0).toUpperCase() + filter.slice(1)}
                     </button>
                  ))}
               </div>
            </div>

            <div className="divide-y divide-gray-100 dark:divide-slate-700/50">
               {filteredPatients.map((patient) => (
                  <div
                     key={patient.id}
                     className="p-4 hover:bg-gray-50 dark:hover:bg-slate-800/50 transition-colors"
                  >
                     <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
                        <div className="flex items-start gap-3 flex-1">
                           <div className="w-10 h-10 bg-blue-100 dark:bg-blue-900/30 rounded-full flex items-center justify-center flex-shrink-0">
                              <span className="text-sm font-bold text-blue-600 dark:text-blue-400">
                                 {patient.room}
                              </span>
                           </div>

                           <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 flex-wrap">
                                 <h3 className="text-sm font-semibold text-gray-900 dark:text-slate-100">
                                    {patient.name}
                                 </h3>
                                 <Badge type={getAcuityBadge(patient.acuityLevel)} size="sm">
                                    {patient.acuityLevel}
                                 </Badge>
                              </div>
                              <p className="text-xs text-gray-500 dark:text-slate-400 mt-1">
                                 Room {patient.room} • Bed {patient.bed} • {patient.age}y {patient.gender}
                              </p>
                              {patient.diagnosis && (
                                 <p className="text-xs text-gray-600 dark:text-slate-300 mt-1">
                                    Dx: {patient.diagnosis}
                                 </p>
                              )}
                           </div>
                        </div>

                        <div className="flex items-center gap-3 flex-wrap">
                           {/* Vitals Status */}
                           <div className="flex items-center gap-1.5 px-2 py-1 bg-gray-50 dark:bg-slate-800 rounded">
                              {getStatusIcon(patient.vitalsStatus)}
                              <span className="text-xs text-gray-700 dark:text-slate-300">Vitals</span>
                           </div>

                           {/* Medication Status */}
                           <div className="flex items-center gap-1.5 px-2 py-1 bg-gray-50 dark:bg-slate-800 rounded">
                              {getStatusIcon(patient.medicationStatus)}
                              <span className="text-xs text-gray-700 dark:text-slate-300">Meds</span>
                           </div>

                           {/* Quick Actions */}
                           <div className="flex gap-1">
                              <Button size="sm" variant="outline" className="flex items-center gap-1">
                                 <Heart className="w-3.5 h-3.5" />
                                 Vitals
                              </Button>
                              <Button
                                 size="sm"
                                 variant="outline"
                                 className="flex items-center gap-1"
                                 onClick={() => navigate(`/dashboard/nurse/patient/${patient.id}`)}
                              >
                                 <ClipboardList className="w-3.5 h-3.5" />
                                 Chart
                              </Button>
                           </div>
                        </div>
                     </div>
                  </div>
               ))}

               {filteredPatients.length === 0 && (
                  <div className="p-8 text-center text-gray-500 dark:text-slate-400">
                     <Users className="w-12 h-12 mx-auto mb-2 opacity-50" />
                     <p className="text-sm">No patients match the selected filter</p>
                  </div>
               )}
            </div>
         </Card>

         {/* Quick Access Panels */}
         <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Pending Tasks */}
            <Card>
               <div className="px-4 py-3 border-b border-gray-200 dark:border-slate-700 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                     <CheckSquare className="w-5 h-5 text-green-600 dark:text-green-400" />
                     <h2 className="text-sm font-bold text-gray-900 dark:text-slate-100">Pending Tasks</h2>
                  </div>
                  <Badge size="sm">{overview.tasks.filter((t) => !t.completed).length}</Badge>
               </div>
               <div className="p-4 space-y-2 max-h-80 overflow-y-auto">
                  {overview.tasks
                     .filter((t) => !t.completed)
                     .slice(0, 5)
                     .map((task) => (
                        <div
                           key={task.id}
                           className="flex items-start gap-3 p-2 rounded hover:bg-gray-50 dark:hover:bg-slate-800/50"
                        >
                           <input
                              type="checkbox"
                              className="mt-1 w-4 h-4 text-blue-600 rounded"
                              onChange={() => {
                                 setOverview((prev) => ({
                                    ...prev,
                                    tasks: prev.tasks.map((t) =>
                                       t.id === task.id ? { ...t, completed: !t.completed } : t
                                    ),
                                 }));
                              }}
                           />
                           <div className="flex-1">
                              <p className="text-sm text-gray-900 dark:text-slate-100">{task.description}</p>
                              <p className="text-xs text-gray-500 dark:text-slate-400 mt-0.5">
                                 {task.patient?.name || task.patient} • {task.category}
                              </p>
                           </div>
                           <Badge
                              type={
                                 task.priority === 'critical'
                                    ? 'red'
                                    : task.priority === 'high'
                                       ? 'yellow'
                                       : 'gray'
                              }
                              size="sm"
                           >
                              {task.priority}
                           </Badge>
                        </div>
                     ))}
               </div>
            </Card>

            {/* Notifications */}
            <Card>
               <div className="px-4 py-3 border-b border-gray-200 dark:border-slate-700 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                     <Bell className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                     <h2 className="text-sm font-bold text-gray-900 dark:text-slate-100">Notifications</h2>
                  </div>
                  <Button variant="link" size="sm">
                     Mark all read
                  </Button>
               </div>
               <div className="p-4 space-y-3 max-h-80 overflow-y-auto">
                  {overview.handoverNotes.fromPreviousShift.slice(0, 5).map((note) => (
                     <div
                        key={note.id}
                        className={`p-3 rounded-lg border ${note.read
                           ? 'bg-gray-50 dark:bg-slate-800/30 border-gray-200 dark:border-slate-700'
                           : 'bg-blue-50 dark:bg-blue-900/20 border-blue-200 dark:border-blue-800'
                           }`}
                     >
                        <div className="flex items-start justify-between gap-2">
                           <div className="flex-1">
                              <p className="text-sm font-medium text-gray-900 dark:text-slate-100">
                                 {note.patient?.name || 'General Note'}
                              </p>
                              <p className="text-xs text-gray-600 dark:text-slate-300 mt-1">{note.content}</p>
                              <p className="text-xs text-gray-500 dark:text-slate-400 mt-1">
                                 From: {note.author} • {new Date(note.timestamp).toLocaleTimeString()}
                              </p>
                           </div>
                           {note.priority === 'urgent' && (
                              <Badge type="red" size="sm">
                                 Urgent
                              </Badge>
                           )}
                        </div>
                     </div>
                  ))}
               </div>
            </Card>
         </div>
      </div>
   );
};

export default NurseDashboard;