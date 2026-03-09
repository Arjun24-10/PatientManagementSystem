import React, { useEffect, useMemo, useState } from 'react';
import {
   Activity,
   AlertTriangle,
   Calendar,
   Check,
   CheckSquare,
   ChevronRight,
   ClipboardList,
   Clock,
   Edit3,
   Info,
   MessageSquare,
   Pill,
   Plus,
   Trash2,
   Users,
   X,
} from 'lucide-react';

import Card from '../../components/common/Card';
import Button from '../../components/common/Button';
import Badge from '../../components/common/Badge';
import { useAuth } from '../../contexts/AuthContext';
import api from '../../services/api';


const shiftTypeStyles = {
   day: {
      label: 'Day Shift',
      classes: 'bg-brand-light text-brand-medium border border-brand-medium/20',
   },
   night: {
      label: 'Night Shift',
      classes: 'bg-brand-medium/10 text-brand-deep border border-brand-deep/30',
   },
};



const taskPriorityMap = {
   critical: { dot: 'bg-red-500', label: 'Critical' },
   high: { dot: 'bg-orange-500', label: 'High' },
   medium: { dot: 'bg-blue-500', label: 'Medium' },
   low: { dot: 'bg-gray-400', label: 'Low' },
};

const taskCategoryMap = {
   medication: 'Medication',
   assessment: 'Assessment',
   care: 'Care',
   documentation: 'Documentation',
};



const quickStatConfig = (stats) => [
   {
      id: 'assigned',
      label: 'patients assigned today',
      value: stats.assignedPatients,
      icon: Users,
      border: 'border-brand-medium',
      badge: null,
      onClick: () => { },
      description: null,
   },
   {
      id: 'vitals',
      label: 'vitals checks due',
      value: stats.pendingVitals,
      icon: Activity,
      border: stats.overdueVitals > 0 ? 'border-orange-500' : 'border-brand-medium',
      badge:
         stats.overdueVitals > 0
            ? { text: `${stats.overdueVitals} overdue`, classes: 'text-red-600 font-medium' }
            : null,
      onClick: () => { },
      description: null,
   },
   {
      id: 'medications',
      label: 'medications pending',
      value: stats.medicationsDue,
      icon: Pill,
      border:
         stats.overdueMedications > 0
            ? 'border-red-500'
            : stats.nextMedicationIn <= 30
               ? 'border-yellow-400'
               : 'border-brand-medium',
      badge:
         stats.overdueMedications > 0
            ? { text: `${stats.overdueMedications} overdue`, classes: 'text-red-600 font-medium' }
            : { text: `Next in ${stats.nextMedicationIn} min`, classes: 'text-amber-600 font-medium' },
      onClick: () => { },
      description: null,
   },
   {
      id: 'tasks',
      label: 'tasks remaining',
      value: stats.pendingTasks,
      icon: CheckSquare,
      border: 'border-green-500',
      badge: { text: `${stats.highPriorityTasks} high priority`, classes: 'text-orange-500 font-medium' },
      onClick: () => { },
      description: null,
   },
];

const toastColors = {
   success: 'bg-green-600 text-white',
   error: 'bg-red-600 text-white',
   info: 'bg-brand-medium text-white',
};

const NurseDashboard = () => {
   const { user } = useAuth();
   const [overview, setOverview] = useState({
      scientist: {
         date: new Date().toISOString().split('T')[0]
      },
      stats: {
         assignedPatients: 0,
         pendingVitals: 0,
         overdueVitals: 0,
         medicationsDue: 0,
         overdueMedications: 0,
         nextMedicationIn: 0,
         pendingTasks: 0,
         highPriorityTasks: 0,
      },
      nurse: {
         unit: 'ICU'
      },
      shift: {
         date: new Date().toISOString().split('T')[0],
         startTime: '07:00',
         endTime: '19:00'
      },
      handover: {
         from: '',
         to: ''
      },
      handoverNotes: {
         fromPreviousShift: [],
         forNextShift: {
            generalNotes: '',
            patientNotes: [],
            lastSaved: null
         }
      },
      tasks: []
   });
   const [currentTime, setCurrentTime] = useState(new Date());

   const nurseName = user?.fullName || user?.full_name || 'Nurse';
   const nurseUnit = user?.department || overview.nurse?.unit || 'ICU';

   const [handoverTab, setHandoverTab] = useState('from');
   const [expandedCompleted, setExpandedCompleted] = useState(false);
   const [toast, setToast] = useState(null);


   useEffect(() => {
      const interval = setInterval(() => setCurrentTime(new Date()), 60_000);
      return () => clearInterval(interval);
   }, []);

   useEffect(() => {
      const fetchDashboard = async () => {
         try {
            const data = await api.nurse.getDashboardOverview();
            if (data) {
               // Backend returns flat stats map: {assignedPatients, pendingVitals, overdueVitals, ...}
               setOverview(prev => ({
                  ...prev,
                  stats: data || prev.stats,
               }));
            }
         } catch (err) {
            console.error('Failed to load dashboard overview', err);
         }
      };
      
      fetchDashboard();
      
      const refreshInterval = setInterval(() => {
         fetchDashboard();
      }, 120_000);

      return () => clearInterval(refreshInterval);
   }, []);

   useEffect(() => {
      if (!toast) return undefined;
      const timer = setTimeout(() => setToast(null), 4000);
      return () => clearTimeout(timer);
   }, [toast]);

   const stats = useMemo(() => quickStatConfig(overview.stats), [overview.stats]);

   const greeting = useMemo(() => {
      const hour = currentTime.getHours();
      if (hour < 12) return 'Good Morning';
      if (hour < 18) return 'Good Afternoon';
      return 'Good Evening';
   }, [currentTime]);

   const formattedDate = useMemo(() =>
      currentTime.toLocaleString(undefined, {
         weekday: 'long',
         month: 'long',
         day: 'numeric',
         year: 'numeric',
         hour: 'numeric',
         minute: '2-digit',
      }),
      [currentTime]);

   const shiftProgress = useMemo(() => {
      const shiftDate = overview.shift.date;
      const start = new Date(`${shiftDate}T${overview.shift.startTime}:00`);
      const end = new Date(`${shiftDate}T${overview.shift.endTime}:00`);

      if (end < start) {
         end.setDate(end.getDate() + 1);
      }

      const elapsed = Math.max(0, Math.min(currentTime.getTime() - start.getTime(), end.getTime() - start.getTime()));
      const total = end.getTime() - start.getTime();
      const remainingMs = Math.max(0, end.getTime() - currentTime.getTime());

      const percentage = total === 0 ? 0 : Math.min(100, Math.round((elapsed / total) * 100));
      const remainingHours = Math.floor(remainingMs / (1000 * 60 * 60));
      const remainingMinutes = Math.floor((remainingMs / (1000 * 60)) % 60);

      return {
         percentage,
         remainingLabel: `${remainingHours} hours, ${remainingMinutes.toString().padStart(2, '0')} minutes remaining`,
      };
   }, [currentTime, overview.shift.date, overview.shift.endTime, overview.shift.startTime]);



   const overdueTasks = overview.tasks.filter((task) => task.status === 'overdue');
   const completedTasks = overview.tasks.filter((task) => task.completed);
   const visibleTasks = overview.tasks.filter((task) => !task.completed).sort((a, b) => {
      const priorityOrder = ['critical', 'high', 'medium', 'low'];
      return priorityOrder.indexOf(a.priority) - priorityOrder.indexOf(b.priority);
   });





   const handleTaskToggle = (taskId) => {
      setOverview((prev) => ({
         ...prev,
         tasks: prev.tasks.map((task) =>
            task.id === taskId
               ? {
                  ...task,
                  completed: !task.completed,
                  previousStatus: !task.completed ? task.status : task.previousStatus,
                  status: !task.completed ? 'completed' : task.previousStatus || task.status,
               }
               : task,
         ),
      }));
      // TODO updateTaskStatus(taskId)
   };

   const handleMarkNoteRead = (noteId) => {
      setOverview((prev) => ({
         ...prev,
         handoverNotes: {
            ...prev.handoverNotes,
            fromPreviousShift: prev.handoverNotes.fromPreviousShift.map((note) =>
               note.id === noteId ? { ...note, read: !note.read } : note,
            ),
         },
      }));
      // TODO markNoteAsRead(noteId)
   };

   const handleAddPatientNote = () => {
      setOverview((prev) => ({
         ...prev,
         handoverNotes: {
            ...prev.handoverNotes,
            forNextShift: {
               ...prev.handoverNotes.forNextShift,
               patientNotes: [
                  ...prev.handoverNotes.forNextShift.patientNotes,
                  {
                     id: Date.now(),
                     patientId: '',
                     note: '',
                     priority: 'normal',
                  },
               ],
            },
         },
      }));
   };

   const handleUpdatePatientNote = (id, payload) => {
      setOverview((prev) => ({
         ...prev,
         handoverNotes: {
            ...prev.handoverNotes,
            forNextShift: {
               ...prev.handoverNotes.forNextShift,
               patientNotes: prev.handoverNotes.forNextShift.patientNotes.map((note) =>
                  note.id === id ? { ...note, ...payload } : note,
               ),
            },
         },
      }));
   };

   const handleDeletePatientNote = (id) => {
      setOverview((prev) => ({
         ...prev,
         handoverNotes: {
            ...prev.handoverNotes,
            forNextShift: {
               ...prev.handoverNotes.forNextShift,
               patientNotes: prev.handoverNotes.forNextShift.patientNotes.filter((note) => note.id !== id),
            },
         },
      }));
   };

   const handleSaveHandover = () => {
      setOverview((prev) => ({
         ...prev,
         handoverNotes: {
            ...prev.handoverNotes,
            forNextShift: {
               ...prev.handoverNotes.forNextShift,
               lastSaved: new Date().toISOString(),
            },
         },
      }));
      // TODO saveHandoverNotes
   };

   const handleMarkAllNotesRead = () => {
      setOverview((prev) => ({
         ...prev,
         handoverNotes: {
            ...prev.handoverNotes,
            fromPreviousShift: prev.handoverNotes.fromPreviousShift.map((note) => ({
               ...note,
               read: true,
            })),
         },
      }));
      // TODO mark all as read
   };

   const shiftStyles = shiftTypeStyles[overview.shift.type] || shiftTypeStyles.day;

   return (
      <div className="space-y-4" aria-label="Nurse dashboard overview">
         <header className="bg-white dark:bg-slate-800 rounded-lg shadow-soft border border-gray-100 dark:border-slate-700 overflow-hidden">
            <div className="p-4 sm:p-5 flex flex-col lg:flex-row gap-3 lg:gap-4 lg:items-center justify-between">
               <div>
                  <p className="text-xs font-medium text-brand-medium uppercase tracking-wide">{nurseUnit}</p>
                  <h1 className="text-xl font-bold text-gray-900 dark:text-slate-100 mt-1">
                     {`${greeting}, Nurse ${nurseName}`}
                  </h1>
                  <p className="text-gray-500 dark:text-slate-400 mt-1.5 flex items-center gap-1.5 text-sm" aria-live="polite">
                     <Clock className="w-3.5 h-3.5 text-brand-medium" aria-hidden="true" />
                     <span>{formattedDate}</span>
                  </p>
               </div>

               <div className="flex flex-col md:flex-row gap-2 w-full lg:w-auto">
                  <Card className="p-3 border border-gray-100 dark:border-slate-700 shadow-soft flex-1 dark:bg-slate-800">
                     <div className="flex items-center justify-between">
                        <div>
                           <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold ${shiftStyles.classes}`}>
                              {shiftStyles.label}
                           </span>
                           <p className="text-sm font-semibold text-gray-900 dark:text-slate-100 mt-1.5">{overview.shift.startTime} - {overview.shift.endTime}</p>
                        </div>
                        <Calendar className="w-8 h-8 text-brand-medium bg-brand-light rounded-lg p-1.5" aria-hidden="true" />
                     </div>
                     <div className="mt-3 space-y-1" aria-hidden="true">
                        <div className="relative h-2 bg-gray-100 dark:bg-slate-700 rounded-full overflow-hidden">
                           <div
                              className="absolute inset-y-0 left-0 bg-gradient-to-r from-brand-medium to-brand-deep rounded-full transition-all duration-700"
                              style={{ width: `${shiftProgress.percentage}%` }}
                           />
                        </div>
                        <p className="text-sm text-gray-500 dark:text-slate-400">{shiftProgress.percentage}% of shift completed</p>
                        <p className="text-sm font-medium text-gray-700 dark:text-slate-300" aria-live="polite">{shiftProgress.remainingLabel}</p>
                     </div>
                  </Card>

                  <button
                     type="button"
                     className="min-w-[160px] md:min-w-[180px] rounded-lg border-2 border-red-200 bg-red-50 text-red-600 font-semibold shadow-soft hover:shadow-md hover:bg-red-100 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-400 transition-all duration-200 flex items-center justify-center gap-1.5 px-3 py-2.5 text-sm"
                     aria-label="Call code team"
                     onClick={() => alert('Escalation protocol initiated. (placeholder)')}
                  >
                     <AlertTriangle className="w-4 h-4" aria-hidden="true" />
                     Call Code Team
                  </button>
               </div>
            </div>
         </header>

         {toast && (
            <div
               className={`fixed top-6 right-6 z-50 shadow-xl rounded-xl px-5 py-4 flex items-start gap-3 ${toastColors[toast.type] || toastColors.info}`}
               role="status"
               aria-live="assertive"
            >
               <div className="flex-1">
                  <p className="font-semibold text-white text-sm">{toast.type === 'error' ? 'Action required' : toast.type === 'success' ? 'Success' : 'Notification'}</p>
                  <p className="text-white/90 text-sm mt-1">{toast.message}</p>
               </div>
               <button
                  type="button"
                  className="text-white/80 hover:text-white"
                  aria-label="Dismiss notification"
                  onClick={() => setToast(null)}
               >
                  <X className="w-4 h-4" />
               </button>
            </div>
         )}

         <section aria-labelledby="quick-stats" className="space-y-2">
            <div className="flex items-center justify-between">
               <h2 id="quick-stats" className="text-sm font-bold text-gray-900 dark:text-slate-100">Shift Snapshot</h2>
               <Button variant="link" className="text-brand-medium text-xs font-semibold" aria-label="Refresh dashboard snapshot">
                  Refresh Data
               </Button>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3">
               {stats.map((stat) => {
                  const Icon = stat.icon;
                  return (
                     <Card
                        key={stat.id}
                        className={`p-3 border-l-4 ${stat.border} shadow-soft hover:shadow-lg transition-shadow cursor-pointer focus-within:ring-2 focus-within:ring-brand-medium focus-within:ring-offset-2 dark:bg-slate-800`}
                        hover
                        role="button"
                        tabIndex={0}
                        onClick={stat.onClick}
                        onKeyDown={(event) => {
                           if (event.key === 'Enter' || event.key === ' ') {
                              event.preventDefault();
                              stat.onClick();
                           }
                        }}
                        aria-label={`${stat.value} ${stat.label}`}
                     >
                        <div className="flex items-start justify-between">
                           <div>
                              <p className="text-xs text-gray-500 dark:text-slate-400 font-medium">{stat.label}</p>
                              <p className="text-xl font-bold text-gray-900 dark:text-slate-100 mt-1">{stat.value}</p>
                              {stat.badge && <p className={`text-xs mt-1.5 ${stat.badge.classes}`}>{stat.badge.text}</p>}
                           </div>
                           <div className="w-8 h-8 bg-brand-light rounded-lg flex items-center justify-center text-brand-medium">
                              <Icon className="w-4 h-4" aria-hidden="true" />
                           </div>
                        </div>
                     </Card>
                  );
               })}
            </div>
         </section>



         <section aria-labelledby="tasks-reminders" className="space-y-3">
            <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-2">
               <div className="flex items-center gap-2">
                  <ClipboardList className="w-5 h-5 text-brand-medium" aria-hidden="true" />
                  <h2 id="tasks-reminders" className="text-sm font-bold text-gray-900 dark:text-slate-100">Tasks &amp; Reminders</h2>
                  <span className="text-xs text-gray-500 dark:text-slate-400">{overview.stats.pendingTasks} active</span>
               </div>
               <div className="flex items-center gap-2">
                  <div className="flex gap-1.5 text-xs text-gray-500 dark:text-slate-400">
                     <span className="flex items-center gap-0.5"><span className="w-1.5 h-1.5 rounded-full bg-red-500" /> Critical</span>
                     <span className="flex items-center gap-0.5"><span className="w-1.5 h-1.5 rounded-full bg-orange-500" /> High</span>
                     <span className="flex items-center gap-0.5"><span className="w-1.5 h-1.5 rounded-full bg-blue-500" /> Medium</span>
                     <span className="flex items-center gap-0.5"><span className="w-1.5 h-1.5 rounded-full bg-gray-400" /> Low</span>
                  </div>
                  <Button className="flex items-center gap-1.5 text-xs font-semibold" onClick={() => alert('Add task modal (placeholder)')}>
                     <Plus className="w-3.5 h-3.5" />
                     Add Task
                  </Button>
               </div>
            </div>

            {overdueTasks.length > 0 && (
               <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-400 px-3 py-2 rounded-lg flex items-center justify-between">
                  <div className="flex items-center gap-2">
                     <AlertTriangle className="w-4 h-4" aria-hidden="true" />
                     <p className="text-xs font-semibold">{overdueTasks.length} overdue task(s) need immediate attention</p>
                  </div>

               </div>
            )}

            <div className="space-y-2">
               {visibleTasks.slice(0, 6).map((task) => {
                  const priority = taskPriorityMap[task.priority] || taskPriorityMap.medium;
                  const categoryLabel = taskCategoryMap[task.category] || 'Task';
                  const isOverdue = task.status === 'overdue';
                  const statusColor =
                     task.status === 'completed'
                        ? 'text-green-600'
                        : task.status === 'due-soon'
                           ? 'text-amber-600'
                           : task.status === 'upcoming'
                              ? 'text-brand-medium'
                              : 'text-red-600';

                  return (
                     <Card key={task.id} className={`p-3 shadow-soft border ${isOverdue ? 'border-red-200 dark:border-red-800 bg-red-50/40 dark:bg-red-900/10' : 'border-gray-100 dark:border-slate-700'} dark:bg-slate-800`}>
                        <div className="flex flex-col md:flex-row md:items-center gap-2 md:gap-3">
                           <label className="flex items-center gap-2 cursor-pointer select-none">
                              <input
                                 type="checkbox"
                                 className="form-checkbox w-4 h-4 rounded border-gray-300 dark:border-slate-600 text-brand-medium focus:ring-brand-medium dark:bg-slate-700"
                                 checked={task.completed}
                                 onChange={() => handleTaskToggle(task.id)}
                                 aria-label={`Mark task ${task.title} as complete`}
                              />
                              <span className={`w-2 h-2 rounded-full ${priority.dot}`} aria-hidden="true" />
                           </label>

                           <div className="flex-1 space-y-1">
                              <div className="flex flex-wrap items-center gap-1.5">
                                 <h3 className="text-sm font-semibold text-gray-900 dark:text-slate-100">{task.title}</h3>
                                 <Badge type={isOverdue ? 'red' : 'blue'}>{categoryLabel}</Badge>
                                 {isOverdue && <span className="text-xs font-semibold uppercase text-red-600 dark:text-red-400 bg-red-100 dark:bg-red-900/30 px-1.5 py-0.5 rounded-full">Overdue</span>}
                              </div>
                              {task.patient && (
                                 <p className="text-xs text-gray-600 dark:text-slate-400">for {task.patient.name}, Room {task.patient.room}</p>
                              )}
                              <p className={`text-xs font-semibold ${statusColor}`}>
                                 Due: {new Date(task.dueTime).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}
                                 {task.status === 'overdue' && task.overdueBy ? ` • Overdue ${task.overdueBy} min` : ''}
                              </p>
                           </div>

                           <div className="flex items-center gap-1.5 self-start">
                              <button type="button" className="p-1.5 rounded-full hover:bg-gray-100 dark:hover:bg-slate-700 text-gray-500 dark:text-slate-400" aria-label="View task info">
                                 <Info className="w-3.5 h-3.5" />
                              </button>
                              <button type="button" className="p-1.5 rounded-full hover:bg-gray-100 dark:hover:bg-slate-700 text-gray-500 dark:text-slate-400" aria-label="Edit task">
                                 <Edit3 className="w-3.5 h-3.5" />
                              </button>
                              <button type="button" className="p-1.5 rounded-full hover:bg-gray-100 dark:hover:bg-slate-700 text-gray-500 dark:text-slate-400" aria-label="Delete task">
                                 <Trash2 className="w-3.5 h-3.5" />
                              </button>
                           </div>
                        </div>
                     </Card>
                  );
               })}

               {visibleTasks.length > 6 && (
                  <Button variant="outline" className="w-full text-xs" onClick={() => alert('Navigate to full task list (placeholder)')}>
                     View All Tasks
                  </Button>
               )}
            </div>

            <div className="bg-white dark:bg-slate-800 border border-gray-100 dark:border-slate-700 rounded-lg p-3 shadow-soft">
               <h3 className="text-xs font-semibold text-gray-700 dark:text-slate-300 uppercase tracking-wide">Task Categories</h3>
               <dl className="grid grid-cols-2 sm:grid-cols-4 gap-2 mt-2 text-xs text-gray-600 dark:text-slate-400">
                  <div>
                     <dt className="font-semibold text-gray-800 dark:text-slate-200">Medication</dt>
                     <dd>3</dd>
                  </div>
                  <div>
                     <dt className="font-semibold text-gray-800 dark:text-slate-200">Assessments</dt>
                     <dd>2</dd>
                  </div>
                  <div>
                     <dt className="font-semibold text-gray-800 dark:text-slate-200">Care Activities</dt>
                     <dd>1</dd>
                  </div>
                  <div>
                     <dt className="font-semibold text-gray-800 dark:text-slate-200">Documentation</dt>
                     <dd>1</dd>
                  </div>
               </dl>

               <div className="mt-3">
                  <button
                     type="button"
                     className="text-xs text-brand-medium font-semibold flex items-center gap-1.5"
                     onClick={() => setExpandedCompleted((prev) => !prev)}
                     aria-expanded={expandedCompleted}
                  >
                     {expandedCompleted ? 'Hide Completed (12)' : 'Show Completed (12)'}
                     <ChevronRight className={`w-3.5 h-3.5 transition-transform ${expandedCompleted ? 'rotate-90' : ''}`} aria-hidden="true" />
                  </button>
                  {expandedCompleted && (
                     <ul className="mt-2 space-y-1 text-xs text-gray-500 dark:text-slate-400">
                        {(completedTasks.length > 0 ? completedTasks : [{ id: 'stub', title: 'Example completed task' }]).map((task) => (
                           <li key={task.id} className="flex items-center gap-1.5">
                              <Check className="w-3.5 h-3.5 text-green-500" aria-hidden="true" />
                              <span className="line-through">{task.title || 'Task completed'}</span>
                           </li>
                        ))}
                     </ul>
                  )}
               </div>
            </div>
         </section>

         <section aria-labelledby="shift-handover" className="space-y-3">
            <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-2">
               <div className="flex items-center gap-2">
                  <MessageSquare className="w-5 h-5 text-brand-medium" aria-hidden="true" />
                  <h2 id="shift-handover" className="text-sm font-bold text-gray-900 dark:text-slate-100">Shift Handover</h2>
               </div>
               <div className="inline-flex rounded-full border border-gray-200 dark:border-slate-600 overflow-hidden" role="tablist">
                  <button
                     type="button"
                     role="tab"
                     className={`px-3 py-1.5 text-xs font-semibold transition ${handoverTab === 'from' ? 'bg-brand-medium text-white' : 'text-gray-600 dark:text-slate-400 hover:bg-gray-50 dark:hover:bg-slate-700'}`}
                     onClick={() => setHandoverTab('from')}
                     aria-selected={handoverTab === 'from'}
                  >
                     From Previous Shift
                  </button>
                  <button
                     type="button"
                     role="tab"
                     className={`px-3 py-1.5 text-xs font-semibold transition ${handoverTab === 'to' ? 'bg-brand-medium text-white' : 'text-gray-600 dark:text-slate-400 hover:bg-gray-50 dark:hover:bg-slate-700'}`}
                     onClick={() => setHandoverTab('to')}
                     aria-selected={handoverTab === 'to'}
                  >
                     For Next Shift
                  </button>
               </div>
            </div>

            {handoverTab === 'from' ? (
               <Card className="p-3 space-y-3 border border-gray-100 dark:border-slate-700 shadow-soft dark:bg-slate-800" role="tabpanel">
                  <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-2">
                     <div>
                        <p className="text-xs text-gray-500 dark:text-slate-400">Last updated: Feb 9, 7:00 AM by Nurse Sarah Chen</p>
                        <p className="text-xs font-semibold text-brand-medium">3 unread notes</p>
                     </div>
                     <div className="flex gap-2">
                        <Button variant="outline" className="border-brand-medium text-brand-medium text-xs py-1" onClick={handleMarkAllNotesRead}>
                           Mark All as Read
                        </Button>
                        <Button className="bg-brand-medium text-white text-xs py-1">View History</Button>
                     </div>
                  </div>

                  <div className="space-y-2">
                     {overview.handoverNotes.fromPreviousShift.map((note) => {
                        const isUrgent = note.priority === 'urgent';
                        const isRead = note.read;

                        return (
                           <div
                              key={note.id}
                              className={`rounded-lg border ${isUrgent ? 'border-red-200 dark:border-red-800 bg-red-50/50 dark:bg-red-900/20' : 'border-blue-100 dark:border-blue-800 bg-blue-50/40 dark:bg-blue-900/20'} p-3 flex flex-col gap-2 ${isRead ? 'opacity-75' : ''}`}
                           >
                              <div className="flex flex-col md:flex-row md:items-start md:justify-between gap-2">
                                 <div className="space-y-0.5">
                                    <div className="flex items-center gap-1.5 text-xs uppercase font-semibold tracking-wide">
                                       <span className={`px-2 py-0.5 rounded-full ${isUrgent ? 'bg-red-500 text-white' : 'bg-blue-500 text-white'}`}>
                                          {isUrgent ? 'Urgent' : 'Info'}
                                       </span>
                                       <span className="px-2 py-0.5 rounded-full bg-white/80 dark:bg-slate-700 text-gray-700 dark:text-slate-300">
                                          {note.type === 'general' ? 'General' : 'Patient Specific'}
                                       </span>
                                    </div>
                                    {note.patient && (
                                       <p className="text-xs font-semibold text-gray-800 dark:text-slate-200">
                                          {note.patient.name}, Room {note.patient.room}
                                       </p>
                                    )}
                                 </div>
                                 <div className="text-xs text-gray-500 dark:text-slate-400 text-right">
                                    <p>{new Date(note.timestamp).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}</p>
                                    <p>{note.author}</p>
                                 </div>
                              </div>
                              <p className="text-xs text-gray-700 dark:text-slate-300 leading-relaxed">{note.content}</p>
                              <label className="flex items-center gap-1.5 text-xs font-medium text-gray-600 dark:text-slate-400 cursor-pointer">
                                 <input
                                    type="checkbox"
                                    checked={note.read}
                                    onChange={() => handleMarkNoteRead(note.id)}
                                    className="form-checkbox w-3.5 h-3.5 text-brand-medium dark:bg-slate-700 dark:border-slate-600"
                                 />
                                 Mark as read
                              </label>
                           </div>
                        );
                     })}
                  </div>

                  {overview.handoverNotes.fromPreviousShift.length === 0 && (
                     <div className="text-center text-gray-500 dark:text-slate-400 py-6">
                        <CheckSquare className="w-8 h-8 mx-auto text-gray-300 dark:text-slate-600 mb-2" aria-hidden="true" />
                        No handover notes from previous shift
                     </div>
                  )}
               </Card>
            ) : (
               <Card className="p-3 space-y-3 border border-gray-100 dark:border-slate-700 shadow-soft dark:bg-slate-800" role="tabpanel">
                  <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-2">
                     <div>
                        <h3 className="text-sm font-bold text-gray-900 dark:text-slate-100">Notes for Next Shift</h3>
                        <p className="text-xs text-gray-500 dark:text-slate-400">Auto-save every 30 seconds</p>
                        {overview.handoverNotes.forNextShift.lastSaved && (
                           <p className="text-xs text-gray-400 dark:text-slate-500 mt-0.5">
                              Last saved: {new Date(overview.handoverNotes.forNextShift.lastSaved).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}
                           </p>
                        )}
                     </div>
                     <div className="flex gap-2">
                        <Button variant="outline" className="border-brand-medium text-brand-medium text-xs py-1" onClick={handleSaveHandover}>
                           Save Draft
                        </Button>
                        <Button className="bg-brand-medium text-white text-xs py-1" disabled>
                           Submit Handover
                        </Button>
                     </div>
                  </div>

                  <div className="space-y-2">
                     <div>
                        <label htmlFor="general-notes" className="block text-xs font-medium text-gray-700 dark:text-slate-300 mb-1">
                           General Notes
                        </label>
                        <textarea
                           id="general-notes"
                           rows={3}
                           className="w-full rounded-lg border border-gray-200 dark:border-slate-600 p-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand-medium bg-white dark:bg-slate-700 text-gray-900 dark:text-slate-100 dark:placeholder-slate-400"
                           placeholder="Enter general shift notes..."
                           value={overview.handoverNotes.forNextShift.generalNotes}
                           onChange={(event) => setOverview((prev) => ({
                              ...prev,
                              handoverNotes: {
                                 ...prev.handoverNotes,
                                 forNextShift: {
                                    ...prev.handoverNotes.forNextShift,
                                    generalNotes: event.target.value,
                                 },
                              },
                           }))}
                           maxLength={2000}
                        />
                        <div className="flex justify-between text-xs text-gray-400 dark:text-slate-500 mt-1">
                           <span>Quick templates: Staffing changes · Equipment issues · Unit updates</span>
                           <span>{overview.handoverNotes.forNextShift.generalNotes.length}/2000</span>
                        </div>
                     </div>

                     <div className="space-y-2">
                        <div className="flex items-center justify-between">
                           <h3 className="text-xs font-semibold text-gray-700 dark:text-slate-300 uppercase tracking-wide">Patient-Specific Notes</h3>
                           <Button variant="outline" className="text-xs flex items-center gap-1.5" onClick={handleAddPatientNote}>
                              <Plus className="w-3.5 h-3.5" />
                              Add Patient Note
                           </Button>
                        </div>

                        {overview.handoverNotes.forNextShift.patientNotes.length === 0 && (
                           <div className="border border-dashed border-gray-300 dark:border-slate-600 rounded-lg p-4 text-center text-xs text-gray-500 dark:text-slate-400">
                              <MessageSquare className="w-5 h-5 mx-auto text-gray-300 dark:text-slate-600 mb-1.5" aria-hidden="true" />
                              No patient-specific notes yet.
                           </div>
                        )}

                        <div className="space-y-2">
                           {overview.handoverNotes.forNextShift.patientNotes.map((note) => (
                              <div key={note.id} className="border border-gray-200 dark:border-slate-600 rounded-lg p-3 space-y-2 dark:bg-slate-700/50">
                                 <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                                    <div>
                                       <label className="block text-xs font-semibold text-gray-500 dark:text-slate-400 uppercase tracking-wide mb-1">Patient</label>
                                       <select
                                          value={note.patientId}
                                          onChange={(event) => handleUpdatePatientNote(note.id, { patientId: event.target.value })}
                                          className="w-full rounded-lg border border-gray-200 dark:border-slate-600 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand-medium bg-white dark:bg-slate-700 text-gray-900 dark:text-slate-100"
                                       >
                                          <option value="">Select patient</option>
                                          {overview.assignedPatients.map((patient) => (
                                             <option key={patient.id} value={patient.id}>
                                                {patient.name} - Room {patient.room}{patient.bed}
                                             </option>
                                          ))}
                                       </select>
                                    </div>
                                    <div>
                                       <label className="block text-xs font-semibold text-gray-500 dark:text-slate-400 uppercase tracking-wide mb-1">Priority</label>
                                       <select
                                          value={note.priority}
                                          onChange={(event) => handleUpdatePatientNote(note.id, { priority: event.target.value })}
                                          className="w-full rounded-lg border border-gray-200 dark:border-slate-600 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand-medium bg-white dark:bg-slate-700 text-gray-900 dark:text-slate-100"
                                       >
                                          <option value="normal">Normal</option>
                                          <option value="urgent">Urgent</option>
                                       </select>
                                    </div>
                                 </div>
                                 <div>
                                    <label className="block text-xs font-semibold text-gray-500 dark:text-slate-400 uppercase tracking-wide mb-1">Note</label>
                                    <textarea
                                       rows={3}
                                       className="w-full rounded-lg border border-gray-200 dark:border-slate-600 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand-medium bg-white dark:bg-slate-700 text-gray-900 dark:text-slate-100 dark:placeholder-slate-400"
                                       value={note.note}
                                       onChange={(event) => handleUpdatePatientNote(note.id, { note: event.target.value })}
                                       placeholder="Enter patient note..."
                                    />
                                 </div>
                                 <div className="flex justify-end">
                                    <button
                                       type="button"
                                       className="inline-flex items-center gap-2 text-sm text-red-600 font-semibold hover:text-red-700"
                                       onClick={() => handleDeletePatientNote(note.id)}
                                    >
                                       <Trash2 className="w-4 h-4" aria-hidden="true" />
                                       Remove
                                    </button>
                                 </div>
                              </div>
                           ))}
                        </div>
                     </div>
                  </div>
               </Card>
            )}
         </section>
      </div>
   );
};

export default NurseDashboard;