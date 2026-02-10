import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Users, FileText, ArrowRight, Activity, Bell, Search, Pill } from 'lucide-react';

import Card from '../../components/common/Card';
import Button from '../../components/common/Button';
import Badge from '../../components/common/Badge';

import AppointmentList from '../../components/AppointmentList';
import MiniCalendar from '../../components/MiniCalendar';
import { mockPatients } from '../../mocks/patients';
import { mockAppointments } from '../../mocks/appointments';
import api from '../../services/api';

const DoctorDashboard = () => {
   const navigate = useNavigate();
   const [searchTerm, setSearchTerm] = useState('');

   // State for data
   const [patients, setPatients] = useState(mockPatients);
   const [appointments, setAppointments] = useState(mockAppointments);

   // Fetch data from API
   React.useEffect(() => {
      const fetchData = async () => {
         try {
            // Attempt to fetch patients
            const patientsData = await api.patients.getAll();
            if (Array.isArray(patientsData)) {
               setPatients(patientsData);
            }
         } catch (error) {
            console.log('Using mock patient data (API backend not reachable)');
         }

         try {
            // Attempt to fetch appointments
            const appointmentsData = await api.appointments.getAll();
            if (Array.isArray(appointmentsData)) {
               setAppointments(appointmentsData);
            }
         } catch (error) {
            console.log('Using mock appointment data (API backend not reachable)');
         }
      };

      fetchData();
   }, []);

   // Filter patients based on search
   const filteredPatients = patients.filter(p =>
      p.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      p.id.toLowerCase().includes(searchTerm.toLowerCase())
   );

   const todaysAppointments = appointments.filter(a => a.date === '2023-12-15');

   return (
      <div className="space-y-4">
         <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-3">
            <div>
               <h2 className="text-lg font-bold text-gray-800 dark:text-slate-100 tracking-tight">Doctor Dashboard</h2>
               <p className="text-gray-500 dark:text-slate-400 text-sm">Welcome back, Dr. Smith. Here's your daily overview.</p>
            </div>
            <div className="flex gap-3">
               <Button variant="outline" className="text-gray-600 dark:text-slate-300 border-gray-300 dark:border-slate-600 hover:bg-gray-50 dark:hover:bg-slate-700">View Schedule</Button>
               <Button onClick={() => alert('Open Rx Modal')} className="bg-brand-medium hover:bg-brand-deep shadow-md shadow-brand-medium/20">+ New Prescription</Button>
            </div>
         </div>

         {/* Metrics */}
         <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
            <Card className="p-3 border border-gray-100 dark:border-slate-700 shadow-soft hover:shadow-lg transition-shadow duration-300 flex items-center justify-between group dark:bg-slate-800">
               <div>
                  <h3 className="text-gray-500 dark:text-slate-400 text-xs font-medium">Total Patients</h3>
                  <p className="text-xl font-bold text-gray-800 dark:text-slate-100 mt-1 group-hover:text-brand-medium transition-colors">{patients.length}</p>
               </div>
               <div className="w-8 h-8 bg-blue-50 dark:bg-blue-900/20 rounded-full flex items-center justify-center text-brand-medium group-hover:scale-110 transition-transform">
                  <Users className="w-4 h-4" />
               </div>
            </Card>
            <Card className="p-3 border border-gray-100 dark:border-slate-700 shadow-soft hover:shadow-lg transition-shadow duration-300 flex items-center justify-between group dark:bg-slate-800">
               <div>
                  <h3 className="text-gray-500 dark:text-slate-400 text-xs font-medium">Appointments</h3>
                  <p className="text-xl font-bold text-gray-800 dark:text-slate-100 mt-1 group-hover:text-brand-medium transition-colors">{todaysAppointments.length}</p>
               </div>
               <div className="w-8 h-8 bg-green-50 dark:bg-green-900/20 rounded-full flex items-center justify-center text-green-600 group-hover:scale-110 transition-transform">
                  <FileText className="w-4 h-4" />
               </div>
            </Card>
            <Card className="p-3 border border-gray-100 dark:border-slate-700 shadow-soft hover:shadow-lg transition-shadow duration-300 flex items-center justify-between group dark:bg-slate-800">
               <div>
                  <h3 className="text-gray-500 dark:text-slate-400 text-xs font-medium">Pending Labs</h3>
                  <p className="text-xl font-bold text-gray-800 dark:text-slate-100 mt-1 group-hover:text-brand-medium transition-colors">5</p>
               </div>
               <div className="w-8 h-8 bg-yellow-50 dark:bg-yellow-900/20 rounded-full flex items-center justify-center text-yellow-600 group-hover:scale-110 transition-transform">
                  <Activity className="w-4 h-4" />
               </div>
            </Card>
            <Card className="p-3 border border-gray-100 dark:border-slate-700 shadow-soft hover:shadow-lg transition-shadow duration-300 flex items-center justify-between group dark:bg-slate-800">
               <div>
                  <h3 className="text-gray-500 dark:text-slate-400 text-xs font-medium">Active Rx</h3>
                  <p className="text-xl font-bold text-gray-800 dark:text-slate-100 mt-1 group-hover:text-brand-medium transition-colors">12</p>
               </div>
               <div className="w-8 h-8 bg-purple-50 dark:bg-purple-900/20 rounded-full flex items-center justify-center text-purple-600 group-hover:scale-110 transition-transform">
                  <Pill className="w-4 h-4" />
               </div>
            </Card>
         </div>

         <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Left Column (Charts & Lists) */}
            <div className="lg:col-span-2 space-y-4">


               {/* Patient List */}
               <Card className="overflow-hidden border border-gray-100 dark:border-slate-700 shadow-soft dark:bg-slate-800">
                  <div className="px-4 py-3 border-b border-gray-100 dark:border-slate-700 flex flex-col sm:flex-row justify-between items-center bg-white dark:bg-slate-800 gap-2">
                     <h3 className="text-sm font-bold text-gray-800 dark:text-slate-100">Recent Patients</h3>

                     <div className="relative w-full sm:w-64">
                        <input
                           type="text"
                           placeholder="Search patients..."
                           value={searchTerm}
                           onChange={(e) => setSearchTerm(e.target.value)}
                           className="w-full pl-10 pr-4 py-2 border border-gray-200 dark:border-slate-600 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-brand-medium dark:bg-slate-700 dark:text-slate-100 dark:placeholder-slate-400"
                        />
                        <Search className="w-4 h-4 text-gray-400 dark:text-slate-500 absolute left-3 top-3" />
                     </div>
                  </div>

                  {filteredPatients.length > 0 ? (
                     <div className="overflow-x-auto">
                        <table className="min-w-full divide-y divide-gray-100 dark:divide-slate-700">
                           <thead className="bg-gray-50/50 dark:bg-slate-700/50">
                              <tr>
                                 <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500 dark:text-slate-300 uppercase tracking-wider">Patient</th>
                                 <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500 dark:text-slate-300 uppercase tracking-wider">Age/Gender</th>
                                 <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500 dark:text-slate-300 uppercase tracking-wider">Condition</th>
                                 <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500 dark:text-slate-300 uppercase tracking-wider">Status</th>
                                 <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500 dark:text-slate-300 uppercase tracking-wider">Last Visit</th>
                                 <th className="px-4 py-2 text-right text-xs font-semibold text-gray-500 dark:text-slate-300 uppercase tracking-wider">Action</th>
                              </tr>
                           </thead>
                           <tbody className="bg-white dark:bg-slate-800 divide-y divide-gray-100 dark:divide-slate-700">
                              {filteredPatients.map((patient) => (
                                 <tr key={patient.id} className="hover:bg-slate-50/80 dark:hover:bg-slate-700/50 transition-colors duration-150 group">
                                    <td className="px-4 py-2 whitespace-nowrap">
                                       <div className="flex items-center">
                                          <div className="flex-shrink-0 h-8 w-8 rounded-full bg-brand-light dark:bg-brand-medium/20 flex items-center justify-center text-brand-deep dark:text-brand-light text-xs font-bold border border-brand-medium/10">
                                             {patient.avatar}
                                          </div>
                                          <div className="ml-2">
                                             <div className="text-xs font-semibold text-gray-900 dark:text-slate-100 group-hover:text-brand-deep dark:group-hover:text-brand-light transition-colors">{patient.name}</div>
                                             <div className="text-xs text-gray-500 dark:text-slate-400">ID: {patient.id}</div>
                                          </div>
                                       </div>
                                    </td>
                                    <td className="px-4 py-2 whitespace-nowrap">
                                       <div className="text-xs text-gray-900 dark:text-slate-100">{patient.age} yrs</div>
                                       <div className="text-xs text-gray-500 dark:text-slate-400">{patient.gender}</div>
                                    </td>
                                    <td className="px-4 py-2 whitespace-nowrap">
                                       <span className="text-xs text-gray-700 dark:text-slate-300 bg-gray-100 dark:bg-slate-700 px-1.5 py-0.5 rounded">{patient.condition}</span>
                                    </td>
                                    <td className="px-4 py-2 whitespace-nowrap">
                                       <Badge type={patient.status === 'Needs Review' ? 'red' : 'green'}>
                                          {patient.status}
                                       </Badge>
                                    </td>
                                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-slate-400">
                                       {patient.lastVisit}
                                    </td>
                                    <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                       <button
                                          className="text-brand-medium hover:text-brand-deep dark:hover:text-brand-light flex items-center justify-end w-full opacity-0 group-hover:opacity-100 transition-opacity"
                                          onClick={() => navigate(`/dashboard/doctor/patient/${patient.id}`)}
                                       >
                                          View <ArrowRight className="w-4 h-4 ml-1" />
                                       </button>
                                    </td>
                                 </tr>
                              ))}
                           </tbody>
                        </table>
                     </div>
                  ) : (
                     <div className="p-6 text-center">
                        <Users className="w-8 h-8 text-gray-300 dark:text-slate-600 mx-auto mb-2" />
                        <h3 className="text-sm font-medium text-gray-900 dark:text-slate-100">No patients found</h3>
                        <p className="text-xs text-gray-500 dark:text-slate-400">Try adjusting your search terms.</p>
                     </div>
                  )}
               </Card>
            </div>

            {/* Right Column (Side Panel) */}
            <div className="space-y-4">
               {/* Mini Calendar */}
               <MiniCalendar appointments={appointments} />

               {/* Upcoming Appointments */}
               <Card className="p-3 border border-gray-100 dark:border-slate-700 shadow-soft h-fit dark:bg-slate-800">
                  <div className="flex justify-between items-center mb-3">
                     <h3 className="text-sm font-bold text-gray-800 dark:text-slate-100">Upcoming List</h3>
                     <button className="text-xs text-brand-medium hover:underline font-medium bg-transparent border-none cursor-pointer">See all</button>
                  </div>
                  <AppointmentList appointments={appointments.slice(0, 5)} />
               </Card>

               {/* Notifications/Alerts (Simplified) */}
               <div className="bg-brand-deep rounded-lg p-4 text-white shadow-lg relative overflow-hidden">
                  <div className="absolute top-0 right-0 w-24 h-24 bg-white opacity-10 rounded-full -mr-12 -mt-12"></div>
                  <div className="absolute bottom-0 left-0 w-16 h-16 bg-white opacity-10 rounded-full -ml-8 -mb-8"></div>

                  <div className="relative z-10">
                     <div className="flex items-center mb-2">
                        <div className="w-7 h-7 bg-white/20 rounded flex items-center justify-center backdrop-blur-sm">
                           <Bell className="w-3.5 h-3.5 text-white" />
                        </div>
                        <h3 className="ml-2 font-bold text-sm">Daily Briefing</h3>
                     </div>
                     <p className="text-blue-100 text-xs mb-3 leading-relaxed">
                        You have 3 high-priority lab results to review and 2 patient inquiries pending from yesterday.
                     </p>
                     <Button className="w-full bg-white text-brand-deep hover:bg-blue-50 border-none">
                        Review Items
                     </Button>
                  </div>
               </div>
            </div>
         </div>
      </div>
   );
};

export default DoctorDashboard;