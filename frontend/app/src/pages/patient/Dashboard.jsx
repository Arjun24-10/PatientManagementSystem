import React, { useState } from 'react';
import { Activity, Calendar, FileText, Pill, AlertCircle, ArrowRight, Clock, MapPin, Stethoscope, Thermometer, Heart, Wind, Scale, AlertTriangle } from 'lucide-react';
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

   if (!patient) return <div className="p-8 text-center text-gray-500">Loading patient data...</div>;

   // --- Data Preparation ---
   const upcomingAppointments = appointments
      .filter(a => a.patientId === patientId && a.status !== 'Completed' && a.status !== 'Cancelled')
      .sort((a, b) => new Date(a.date) - new Date(b.date))
      .slice(0, 3);

   const pendingLabs = labs.filter(l => l.status === 'Pending' || l.type === 'Pending');
   const activeMedications = prescriptions.filter(p => p.active);
   const recentDiagnoses = diagnoses.sort((a, b) => new Date(b.date) - new Date(a.date)).slice(0, 5);
   const latestVitals = vitals[0] || {};

   // Helper for Vital Cards (Doctor Style)
   const VitalCard = ({ label, value, unit, icon: Icon, colorClass, bgClass }) => (
      <Card className="p-6 border border-gray-100 shadow-soft hover:shadow-lg transition-shadow duration-300 flex items-center justify-between group">
         <div>
            <h3 className="text-gray-500 text-sm font-medium">{label}</h3>
            <div className="flex items-baseline mt-2">
               <p className="text-3xl font-bold text-gray-800 group-hover:text-brand-medium transition-colors">{value}</p>
               {unit && <span className="text-sm text-gray-400 ml-1 font-medium">{unit}</span>}
            </div>
         </div>
         <div className={`w-12 h-12 ${bgClass} rounded-full flex items-center justify-center ${colorClass} group-hover:scale-110 transition-transform`}>
            <Icon className="w-6 h-6" />
         </div>
      </Card>
   );

   return (
      <div className="space-y-8">
         {/* Header - Matches Doctor Dashboard Structure */}
         <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
            <div>
               <h2 className="text-2xl font-bold text-gray-800 tracking-tight">Patient Dashboard</h2>
               <p className="text-gray-500 mt-1">Welcome back, {patient.name}. Here's your health overview.</p>
            </div>
            <div className="flex gap-3">
               <Button variant="outline" className="text-gray-600 border-gray-300 hover:bg-gray-50" onClick={() => navigate('/dashboard/patient/appointments')}>
                  My Appointments
               </Button>
               <Button onClick={() => navigate('/dashboard/patient/records')} className="bg-brand-medium hover:bg-brand-deep shadow-md shadow-brand-medium/20">
                  View Records
               </Button>
            </div>
         </div>

         {/* Pending Labs Alert - Kept but styled cleanly */}
         {pendingLabs.length > 0 && (
            <div className="bg-orange-50 border border-orange-200 rounded-xl p-4 flex items-start gap-3 animate-fade-in shadow-sm">
               <AlertTriangle className="w-5 h-5 text-orange-500 mt-0.5" />
               <div className="flex-1">
                  <h3 className="text-orange-800 font-semibold text-sm">Action Required: Pending Lab Results</h3>
                  <p className="text-orange-600 text-sm mt-1">You have {pendingLabs.length} lab results waiting for review.</p>
               </div>
               <Button size="sm" className="bg-white text-orange-600 border border-orange-200 hover:bg-orange-100 text-xs py-1 px-3 h-auto">
                  View Labs
               </Button>
            </div>
         )}

         {/* Vitals Grid - Matches Doctor Metrics Grid Style */}
         <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-6">
            <VitalCard
               label="Blood Pressure"
               value={latestVitals.bp}
               icon={Activity}
               colorClass="text-blue-600"
               bgClass="bg-blue-50"
            />
            <VitalCard
               label="Heart Rate"
               value={latestVitals.hr}
               unit="bpm"
               icon={Heart}
               colorClass="text-red-600"
               bgClass="bg-red-50"
            />
            <VitalCard
               label="SpO2"
               value={latestVitals.spo2}
               unit="%"
               icon={Wind}
               colorClass="text-cyan-600"
               bgClass="bg-cyan-50"
            />
            <VitalCard
               label="Resp. Rate"
               value={latestVitals.resp}
               unit="/min"
               icon={Wind}
               colorClass="text-indigo-600"
               bgClass="bg-indigo-50"
            />
            <VitalCard
               label="Temperature"
               value={latestVitals.temp}
               unit="°F"
               icon={Thermometer}
               colorClass="text-orange-600"
               bgClass="bg-orange-50"
            />
            <VitalCard
               label="Weight"
               value={latestVitals.weight}
               unit="kg"
               icon={Scale}
               colorClass="text-green-600"
               bgClass="bg-green-50"
            />
         </div>

         <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            {/* Left Column (2/3) - Main Content */}
            <div className="lg:col-span-2 space-y-8">

               {/* Upcoming Appointments - Styled like Doctor's Tables */}
               <Card className="overflow-hidden border border-gray-100 shadow-soft">
                  <div className="px-6 py-5 border-b border-gray-100 flex justify-between items-center bg-white">
                     <h3 className="text-lg font-bold text-gray-800 flex items-center gap-2">
                        <Calendar className="w-5 h-5 text-gray-400" />
                        Upcoming Appointments
                     </h3>
                     <Button variant="link" className="text-brand-medium text-sm font-medium hover:text-brand-deep p-0" onClick={() => navigate('/dashboard/patient/appointments')}>
                        View All
                     </Button>
                  </div>

                  {upcomingAppointments.length > 0 ? (
                     <div className="divide-y divide-gray-100">
                        {upcomingAppointments.map((appt) => (
                           <div key={appt.id} className="p-6 hover:bg-gray-50 transition-colors flex flex-col md:flex-row md:items-center justify-between gap-4">
                              <div className="flex items-start gap-4">
                                 <div className="flex-shrink-0 w-14 h-14 bg-blue-50 text-brand-medium rounded-xl flex flex-col items-center justify-center border border-blue-100">
                                    <span className="text-xs font-bold uppercase">{new Date(appt.date).toLocaleString('default', { month: 'short' })}</span>
                                    <span className="text-xl font-bold">{new Date(appt.date).getDate()}</span>
                                 </div>
                                 <div>
                                    <h4 className="font-bold text-gray-900">{appt.doctorName}</h4>
                                    <div className="flex items-center gap-3 text-sm text-gray-500 mt-1">
                                       <span className="flex items-center gap-1"><Clock size={14} /> {appt.time}</span>
                                       <span className="flex items-center gap-1"><MapPin size={14} /> {appt.room || 'General Clinic'}</span>
                                    </div>
                                    <span className="inline-block mt-2 px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-50 text-blue-700 border border-blue-100">
                                       {appt.type}
                                    </span>
                                 </div>
                              </div>
                              <div className="flex gap-2">
                                 <Button variant="outline" className="text-xs py-1.5 h-auto text-gray-600">Reschedule</Button>
                              </div>
                           </div>
                        ))}
                     </div>
                  ) : (
                     <div className="p-12 text-center">
                        <Calendar className="w-12 h-12 text-gray-300 mx-auto mb-3" />
                        <h3 className="text-gray-900 font-medium">No upcoming appointments</h3>
                        <p className="text-gray-500 text-sm mt-1">You're all caught up!</p>
                        <Button className="mt-4 bg-brand-medium text-white" onClick={() => navigate('/dashboard/patient/appointments')}>Schedule Now</Button>
                     </div>
                  )}
               </Card>

               {/* Recent Diagnoses - Styled list */}
               <Card className="overflow-hidden border border-gray-100 shadow-soft">
                  <div className="px-6 py-5 border-b border-gray-100 bg-white">
                     <h3 className="text-lg font-bold text-gray-800 flex items-center gap-2">
                        <Stethoscope className="w-5 h-5 text-gray-400" />
                        Recent Diagnoses
                     </h3>
                  </div>
                  <div className="divide-y divide-gray-100">
                     {recentDiagnoses.map((dx) => (
                        <div key={dx.id} className="p-6 hover:bg-gray-50 transition-colors flex justify-between items-start">
                           <div>
                              <h4 className="font-bold text-gray-900">{dx.name}</h4>
                              <p className="text-xs text-gray-500 mt-1">Diagnosed on {dx.date} by {dx.doctor}</p>
                           </div>
                           <Badge type={dx.severity === 'High' ? 'red' : dx.severity === 'Moderate' ? 'yellow' : 'green'}>
                              {dx.severity}
                           </Badge>
                        </div>
                     ))}
                  </div>
               </Card>
            </div>

            {/* Right Column (1/3) - Sidebar */}
            <div className="space-y-8">
               {/* Active Meds */}
               <Card className="border border-gray-100 shadow-soft">
                  <div className="p-6 border-b border-gray-100 flex justify-between items-center">
                     <h3 className="font-bold text-gray-800 flex items-center gap-2">
                        <Pill className="w-5 h-5 text-gray-400" />
                        Active Meds
                     </h3>
                     <Button variant="link" className="text-xs p-0 text-brand-medium" onClick={() => navigate('/dashboard/patient/prescriptions')}>View All</Button>
                  </div>
                  <div className="p-6 space-y-4">
                     {activeMedications.map(rx => (
                        <div key={rx.id} className="bg-gray-50 rounded-lg p-4 border border-gray-200">
                           <div className="flex justify-between items-start mb-2">
                              <h4 className="font-bold text-gray-800">{rx.name}</h4>
                              {rx.refills <= 1 && <AlertCircle className="w-4 h-4 text-red-500" />}
                           </div>
                           <p className="text-sm text-gray-600">{rx.dosage} • {rx.frequency}</p>
                           <p className="text-xs text-gray-400 mt-2">Refills: <span className={rx.refills === 0 ? 'text-red-500 font-bold' : ''}>{rx.refills}</span></p>

                           <Button className="w-full mt-3 text-xs py-1.5 h-auto bg-white border border-gray-300 text-gray-700 hover:bg-gray-100">
                              Request Refill
                           </Button>
                        </div>
                     ))}
                     {activeMedications.length === 0 && <p className="text-gray-500 italic text-center">No active medications.</p>}
                  </div>
               </Card>

               {/* Notifications/Support */}
               <div className="bg-gradient-to-br from-blue-600 to-indigo-700 rounded-2xl p-6 text-white shadow-lg relative overflow-hidden">
                  <div className="relative z-10">
                     <div className="flex items-center mb-4">
                        <div className="w-10 h-10 bg-white/20 rounded-lg flex items-center justify-center backdrop-blur-sm">
                           <Activity className="w-5 h-5 text-white" />
                        </div>
                        <h3 className="ml-3 font-bold text-lg">Need Help?</h3>
                     </div>
                     <p className="text-blue-100 text-sm mb-4 leading-relaxed">
                        Have changes in your symptoms? Contact your care team or use our checker.
                     </p>
                     <div className="space-y-2">
                        <Button className="w-full bg-white text-blue-700 hover:bg-blue-50 border-none transition-colors">
                           Contact Doctor
                        </Button>
                        <Button className="w-full bg-blue-500/50 text-white hover:bg-blue-500/70 border-none transition-colors">
                           Symptom Checker
                        </Button>
                     </div>
                  </div>
               </div>
            </div>
         </div>
      </div>
   );
};

export default PatientDashboard;
