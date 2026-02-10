import React, { useState } from 'react';
import { Activity, Calendar, Pill, AlertCircle, Clock, Stethoscope, Thermometer, Heart, Wind, Scale, AlertTriangle, RefreshCw, CalendarClock, FileText } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import Card from '../../components/common/Card';
import Button from '../../components/common/Button';
import Badge from '../../components/common/Badge';
import { mockAppointments } from '../../mocks/appointments';
import { mockPrescriptions, mockLabs, mockDiagnoses, mockVitalsHistory } from '../../mocks/records';
import { getPatientById } from '../../mocks/patients';

import api from '../../services/api';

const PatientDashboard = () => {
   const navigate = useNavigate();
   const patientId = 'P001';

   // State with Mock Fallbacks
   const [patient, setPatient] = useState(getPatientById(patientId));
   const [appointments, setAppointments] = useState(mockAppointments);
   const [prescriptions, setPrescriptions] = useState(mockPrescriptions);
   const [labs, setLabs] = useState(mockLabs);
   const [diagnoses, setDiagnoses] = useState(mockDiagnoses);
   const [vitals, setVitals] = useState(mockVitalsHistory);

   // Fetch API Data
   React.useEffect(() => {
      const fetchData = async () => {
         try {
            const pData = await api.patients.getById(patientId);
            if (pData && pData.id) setPatient(pData);
         } catch (e) { console.log('Using mock patient data'); }

         try {
            const aData = await api.appointments.getByPatient(patientId);
            if (Array.isArray(aData)) setAppointments(aData);
         } catch (e) { console.log('Using mock appointment data'); }

         try {
            const rData = await api.prescriptions.getByPatient(patientId);
            if (Array.isArray(rData)) setPrescriptions(rData);
         } catch (e) { console.log('Using mock prescription data'); }

         try {
            const lData = await api.labResults.getByPatient(patientId);
            if (Array.isArray(lData)) setLabs(lData);
         } catch (e) { console.log('Using mock lab data'); }

         try {
            const mData = await api.medicalRecords.getByPatient(patientId);
            if (Array.isArray(mData)) setDiagnoses(mData);
         } catch (e) { console.log('Using mock diagnoses data'); }

         try {
            // Vitals might be a single record or list. API says getByPatient returns list.
            const vData = await api.vitalSigns.getByPatient(patientId);
            if (Array.isArray(vData)) setVitals(vData);
         } catch (e) { console.log('Using mock vitals data'); }
      };

      fetchData();
   }, [patientId]);

   if (!patient) return <div className="p-8 text-center text-gray-500 dark:text-slate-400">Loading patient data...</div>;

   // --- Data Preparation ---
   const upcomingAppointments = appointments
      .filter(a => a.patientId === patientId && a.status !== 'Completed' && a.status !== 'Cancelled')
      .sort((a, b) => new Date(a.date) - new Date(b.date))
      .slice(0, 3);

   const pendingLabs = labs.filter(l => l.status === 'Pending' || l.type === 'Pending');
   const activeMedications = prescriptions.filter(p => p.active);
   const recentDiagnoses = diagnoses.sort((a, b) => new Date(b.date) - new Date(a.date)).slice(0, 5);
   const latestVitals = vitals[0] || {};

   // Helper for Vital Cards (Compact Style)
   const VitalCard = ({ label, value, unit, icon: Icon, colorClass, bgClass }) => (
      <Card className="p-3 flex items-center justify-between group hover:border-gray-300 dark:hover:border-slate-600">
         <div>
            <p className="text-xs text-gray-500 dark:text-slate-400 font-medium mb-1">{label}</p>
            <div className="flex items-baseline">
               <p className="text-xl font-semibold text-gray-800 dark:text-slate-100">{value}</p>
               {unit && <span className="text-xs text-gray-400 dark:text-slate-500 ml-1">{unit}</span>}
            </div>
         </div>
         <div className={`w-8 h-8 ${bgClass} rounded-md flex items-center justify-center ${colorClass}`}>
            <Icon className="w-4 h-4" />
         </div>
      </Card>
   );

   return (
      <div className="space-y-4">
         {/* Header - Compact */}
         <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-3">
            <div>
               <h2 className="text-lg font-semibold text-gray-800 dark:text-slate-100">Patient Dashboard</h2>
               <p className="text-sm text-gray-500 dark:text-slate-400">Welcome back, {patient.name}</p>
            </div>
            <div className="flex gap-2">
               <Button variant="outline" size="sm" onClick={() => navigate('/dashboard/patient/appointments')}>
                  My Appointments
               </Button>
               <Button size="sm" onClick={() => navigate('/dashboard/patient/records')}>
                  View Records
               </Button>
            </div>
         </div>

         {/* Pending Labs Alert - Compact */}
         {pendingLabs.length > 0 && (
            <div className="bg-orange-50 dark:bg-orange-900/20 border border-orange-200 dark:border-orange-800 rounded-md p-3 flex items-center gap-3">
               <AlertTriangle className="w-4 h-4 text-orange-500 flex-shrink-0" />
               <div className="flex-1 min-w-0">
                  <p className="text-sm text-orange-800 dark:text-orange-300 font-medium">Pending Lab Results: {pendingLabs.length} waiting for review</p>
               </div>
               <Button size="sm" variant="outline" className="flex-shrink-0 text-orange-600 dark:text-orange-400 border-orange-200 dark:border-orange-800">
                  <FileText className="w-3.5 h-3.5" />
               </Button>
            </div>
         )}

         {/* Vitals Grid - Compact */}
         <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
            <VitalCard
               label="Blood Pressure"
               value={latestVitals.bp}
               icon={Activity}
               colorClass="text-blue-600 dark:text-blue-400"
               bgClass="bg-blue-50 dark:bg-blue-900/20"
            />
            <VitalCard
               label="Heart Rate"
               value={latestVitals.hr}
               unit="bpm"
               icon={Heart}
               colorClass="text-red-600 dark:text-red-400"
               bgClass="bg-red-50 dark:bg-red-900/20"
            />
            <VitalCard
               label="SpO2"
               value={latestVitals.spo2}
               unit="%"
               icon={Wind}
               colorClass="text-cyan-600 dark:text-cyan-400"
               bgClass="bg-cyan-50 dark:bg-cyan-900/20"
            />
            <VitalCard
               label="Resp. Rate"
               value={latestVitals.resp}
               unit="/min"
               icon={Wind}
               colorClass="text-indigo-600 dark:text-indigo-400"
               bgClass="bg-indigo-50 dark:bg-indigo-900/20"
            />
            <VitalCard
               label="Temperature"
               value={latestVitals.temp}
               unit="°F"
               icon={Thermometer}
               colorClass="text-orange-600 dark:text-orange-400"
               bgClass="bg-orange-50 dark:bg-orange-900/20"
            />
            <VitalCard
               label="Weight"
               value={latestVitals.weight}
               unit="kg"
               icon={Scale}
               colorClass="text-green-600 dark:text-green-400"
               bgClass="bg-green-50 dark:bg-green-900/20"
            />
         </div>

         <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Left Column (2/3) - Main Content */}
            <div className="lg:col-span-2 space-y-4">

               {/* Upcoming Appointments - Compact */}
               <Card className="overflow-hidden">
                  <div className="px-4 py-3 border-b border-gray-200 dark:border-slate-700 flex justify-between items-center">
                     <h3 className="text-sm font-semibold text-gray-800 dark:text-slate-100 flex items-center gap-2">
                        <Calendar className="w-4 h-4 text-gray-400 dark:text-slate-500" />
                        Upcoming Appointments
                     </h3>
                     <button className="text-xs text-blue-600 dark:text-blue-400 hover:text-blue-700 font-medium" onClick={() => navigate('/dashboard/patient/appointments')}>
                        View All
                     </button>
                  </div>

                  {upcomingAppointments.length > 0 ? (
                     <div className="divide-y divide-gray-100 dark:divide-slate-700/50">
                        {upcomingAppointments.map((appt) => (
                           <div key={appt.id} className="p-3 hover:bg-gray-50 dark:hover:bg-slate-800/50 flex items-center justify-between gap-3">
                              <div className="flex items-center gap-3 flex-1 min-w-0">
                                 <div className="flex-shrink-0 w-10 text-center">
                                    <div className="text-xs font-semibold text-gray-900 dark:text-slate-100">{new Date(appt.date).getDate()}</div>
                                    <div className="text-xs text-gray-500 dark:text-slate-400 uppercase">{new Date(appt.date).toLocaleString('default', { month: 'short' })}</div>
                                 </div>
                                 <div className="w-px h-8 bg-gray-200 dark:bg-slate-700"></div>
                                 <div className="flex-1 min-w-0">
                                    <div className="text-sm font-medium text-gray-900 dark:text-slate-100 truncate">{appt.doctorName}</div>
                                    <div className="flex items-center gap-2 text-xs text-gray-500 dark:text-slate-400">
                                       <span className="flex items-center gap-1"><Clock size={12} /> {appt.time}</span>
                                       <span>•</span>
                                       <span>{appt.type}</span>
                                    </div>
                                 </div>
                              </div>
                              <button className="w-7 h-7 rounded hover:bg-gray-100 dark:hover:bg-slate-700 flex items-center justify-center text-gray-500 dark:text-slate-400" title="Reschedule">
                                 <CalendarClock className="w-4 h-4" />
                              </button>
                           </div>
                        ))}
                     </div>
                  ) : (
                     <div className="p-6 text-center">
                        <Calendar className="w-8 h-8 text-gray-300 dark:text-slate-600 mx-auto mb-2" />
                        <p className="text-sm text-gray-500 dark:text-slate-400">No upcoming appointments</p>
                        <Button size="sm" className="mt-3" onClick={() => navigate('/dashboard/patient/appointments')}>Schedule Now</Button>
                     </div>
                  )}
               </Card>

               {/* Recent Diagnoses - Compact list */}
               <Card className="overflow-hidden">
                  <div className="px-4 py-3 border-b border-gray-200 dark:border-slate-700">
                     <h3 className="text-sm font-semibold text-gray-800 dark:text-slate-100 flex items-center gap-2">
                        <Stethoscope className="w-4 h-4 text-gray-400 dark:text-slate-500" />
                        Recent Diagnoses
                     </h3>
                  </div>
                  <div className="divide-y divide-gray-100 dark:divide-slate-700/50">
                     {recentDiagnoses.map((dx) => (
                        <div key={dx.id} className="px-4 py-2.5 hover:bg-gray-50 dark:hover:bg-slate-800/50 flex justify-between items-center">
                           <div className="flex-1 min-w-0">
                              <div className="text-sm font-medium text-gray-900 dark:text-slate-100">{dx.name}</div>
                              <div className="text-xs text-gray-500 dark:text-slate-400">{dx.date} • {dx.doctor}</div>
                           </div>
                           <Badge size="sm" type={dx.severity === 'High' ? 'red' : dx.severity === 'Moderate' ? 'yellow' : 'green'}>
                              {dx.severity}
                           </Badge>
                        </div>
                     ))}
                  </div>
               </Card>
            </div>

            {/* Right Column (1/3) - Sidebar */}
            <div className="space-y-4">
               {/* Active Meds - Compact */}
               <Card>
                  <div className="px-4 py-3 border-b border-gray-200 dark:border-slate-700 flex justify-between items-center">
                     <h3 className="text-sm font-semibold text-gray-800 dark:text-slate-100 flex items-center gap-2">
                        <Pill className="w-4 h-4 text-gray-400 dark:text-slate-500" />
                        Active Meds
                     </h3>
                     <button className="text-xs text-blue-600 dark:text-blue-400 font-medium" onClick={() => navigate('/dashboard/patient/prescriptions')}>View All</button>
                  </div>
                  <div className="divide-y divide-gray-100 dark:divide-slate-700/50">
                     {activeMedications.map(rx => (
                        <div key={rx.id} className="group p-3 hover:bg-gray-50 dark:hover:bg-slate-800/50 flex items-center justify-between">
                           <div className="flex items-center gap-3 flex-1 min-w-0">
                              <div className="w-8 h-8 rounded bg-blue-50 dark:bg-blue-900/20 flex items-center justify-center flex-shrink-0">
                                 <Pill className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                              </div>
                              <div className="flex-1 min-w-0">
                                 <div className="flex items-center gap-2">
                                    <span className="text-sm font-medium text-gray-900 dark:text-slate-100">{rx.name}</span>
                                    {rx.refills <= 1 && <AlertCircle className="w-3.5 h-3.5 text-red-500" />}
                                 </div>
                                 <div className="text-xs text-gray-500 dark:text-slate-400">{rx.dosage} • {rx.frequency}</div>
                              </div>
                           </div>
                           <button className="w-7 h-7 rounded hover:bg-gray-200 dark:hover:bg-slate-700 flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity" title="Request Refill">
                              <RefreshCw className="w-3.5 h-3.5 text-gray-600 dark:text-slate-400" />
                           </button>
                        </div>
                     ))}
                     {activeMedications.length === 0 && <p className="text-sm text-gray-500 dark:text-slate-400 text-center py-4">No active medications.</p>}
                  </div>
               </Card>

               {/* Quick Help - Compact */}
               <Card className="bg-blue-600 dark:bg-blue-700 border-blue-600 dark:border-blue-700">
                  <div className="p-4 text-white">
                     <div className="flex items-center gap-2 mb-3">
                        <Activity className="w-4 h-4" />
                        <h3 className="text-sm font-semibold">Need Help?</h3>
                     </div>
                     <p className="text-xs text-blue-100 mb-3">
                        Contact your care team or check symptoms
                     </p>
                     <div className="space-y-2">
                        <button className="w-full py-1.5 px-3 bg-white text-blue-700 rounded text-xs font-medium hover:bg-blue-50">
                           Contact Doctor
                        </button>
                        <button className="w-full py-1.5 px-3 bg-blue-500/50 text-white rounded text-xs font-medium hover:bg-blue-500/70">
                           Symptom Checker
                        </button>
                     </div>
                  </div>
               </Card>
            </div>
         </div>
      </div>
   );
};

export default PatientDashboard;
