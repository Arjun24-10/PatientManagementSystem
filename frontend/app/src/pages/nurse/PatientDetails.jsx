import React, { useState, useMemo } from 'react';
import {
   ArrowLeft,
   Activity,
   Pill,
   Clock,
   AlertTriangle,
   FileText,
   User,
   Calendar,
   Heart,
   Thermometer,
   Droplet,
   Wind,
   Gauge,
   Frown,
   CheckCircle,
   XCircle,
} from 'lucide-react';
import { useNavigate, useParams } from 'react-router-dom';

import Card from '../../components/common/Card';
import Button from '../../components/common/Button';
import Badge from '../../components/common/Badge';
import { mockNurseOverview } from '../../mocks/nurseOverview';

const PatientDetails = () => {
   const navigate = useNavigate();
   const { patientId } = useParams();
   const [activeTab, setActiveTab] = useState('vitals');
   const [careNotes, setCareNotes] = useState('');

   // Find patient from mock data
   const patient = useMemo(() => {
      return mockNurseOverview.assignedPatients.find((p) => p.id === patientId);
   }, [patientId]);

   if (!patient) {
      return (
         <div className="p-8 text-center">
            <p className="text-gray-500 dark:text-slate-400">Patient not found</p>
            <Button onClick={() => navigate('/nurse/dashboard')} className="mt-4">
               Back to Dashboard
            </Button>
         </div>
      );
   }

   // Mock medication schedule
   const medicationSchedule = [
      {
         id: 1,
         medication: 'Metformin 500mg',
         time: '08:00',
         route: 'Oral',
         status: 'completed',
         completedAt: '08:05',
         notes: 'Given with breakfast',
      },
      {
         id: 2,
         medication: 'Lisinopril 10mg',
         time: '08:00',
         route: 'Oral',
         status: 'completed',
         completedAt: '08:05',
      },
      {
         id: 3,
         medication: 'Insulin Lispro 8 units',
         time: '12:00',
         route: 'Subcutaneous',
         status: 'due',
      },
      {
         id: 4,
         medication: 'Metformin 500mg',
         time: '18:00',
         route: 'Oral',
         status: 'scheduled',
      },
   ];

   // Mock treatment schedule
   const treatmentSchedule = [
      {
         id: 1,
         treatment: 'Wound dressing change',
         time: '10:00',
         status: 'completed',
         completedAt: '10:15',
         notes: 'Wound healing well, no signs of infection',
      },
      {
         id: 2,
         treatment: 'Physical therapy',
         time: '14:00',
         status: 'scheduled',
      },
      {
         id: 3,
         treatment: 'Blood glucose check',
         time: '16:00',
         status: 'scheduled',
      },
   ];

   // Current vitals from mock data
   const currentVitals = mockNurseOverview.vitals.current;

   const getStatusBadge = (status) => {
      if (status === 'completed') return { type: 'green', icon: CheckCircle, text: 'Completed' };
      if (status === 'due') return { type: 'yellow', icon: Clock, text: 'Due Now' };
      if (status === 'overdue') return { type: 'red', icon: AlertTriangle, text: 'Overdue' };
      return { type: 'gray', icon: Clock, text: 'Scheduled' };
   };

   return (
      <div className="space-y-4">
         {/* Header */}
         <div className="flex items-center gap-3">
            <Button
               variant="outline"
               size="sm"
               onClick={() => navigate('/nurse/dashboard')}
               className="flex items-center gap-2"
            >
               <ArrowLeft className="w-4 h-4" />
               Back
            </Button>
            <div className="flex-1">
               <h1 className="text-lg font-bold text-gray-900 dark:text-slate-100">{patient.name}</h1>
               <p className="text-sm text-gray-500 dark:text-slate-400">
                  Room {patient.room} • Bed {patient.bed} • MRN: {patient.mrn}
               </p>
            </div>
            <Badge type={patient.acuityLevel === 'critical' ? 'red' : patient.acuityLevel === 'high' ? 'yellow' : 'green'}>
               {patient.acuityLevel}
            </Badge>
         </div>

         {/* Patient Basic Info - HIPAA Compliant (Demographics Only) */}
         <Card>
            <div className="p-4">
               <h2 className="text-sm font-bold text-gray-900 dark:text-slate-100 mb-3 flex items-center gap-2">
                  <User className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                  Patient Information
               </h2>
               <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div>
                     <p className="text-xs text-gray-500 dark:text-slate-400">Age</p>
                     <p className="text-sm font-semibold text-gray-900 dark:text-slate-100">{patient.age} years</p>
                  </div>
                  <div>
                     <p className="text-xs text-gray-500 dark:text-slate-400">Gender</p>
                     <p className="text-sm font-semibold text-gray-900 dark:text-slate-100">{patient.gender}</p>
                  </div>
                  <div>
                     <p className="text-xs text-gray-500 dark:text-slate-400">Admission Date</p>
                     <p className="text-sm font-semibold text-gray-900 dark:text-slate-100">
                        {new Date(patient.admissionDate).toLocaleDateString()}
                     </p>
                  </div>
                  <div>
                     <p className="text-xs text-gray-500 dark:text-slate-400">Acuity Level</p>
                     <Badge type={patient.acuityLevel === 'critical' ? 'red' : 'yellow'} size="sm">
                        {patient.acuityLevel}
                     </Badge>
                  </div>
               </div>

               {/* Allergies Alert */}
               {patient.allergies && patient.allergies.length > 0 && (
                  <div className="mt-4 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                     <div className="flex items-start gap-2">
                        <AlertTriangle className="w-4 h-4 text-red-600 dark:text-red-400 flex-shrink-0 mt-0.5" />
                        <div>
                           <p className="text-sm font-semibold text-red-900 dark:text-red-100">Allergies</p>
                           <div className="flex flex-wrap gap-2 mt-1">
                              {patient.allergies.map((allergy, idx) => (
                                 <Badge key={idx} type="red" size="sm">
                                    {allergy.allergen} ({allergy.severity})
                                 </Badge>
                              ))}
                           </div>
                        </div>
                     </div>
                  </div>
               )}

               {/* Special Alerts */}
               {patient.specialAlerts && patient.specialAlerts.length > 0 && (
                  <div className="mt-3 flex flex-wrap gap-2">
                     {patient.specialAlerts.map((alert, idx) => (
                        <Badge key={idx} type="yellow" size="sm">
                           {alert.replace('-', ' ').toUpperCase()}
                        </Badge>
                     ))}
                  </div>
               )}
            </div>
         </Card>

         {/* Tabs */}
         <div className="border-b border-gray-200 dark:border-slate-700">
            <div className="flex gap-4 overflow-x-auto">
               {[
                  { id: 'vitals', label: 'Current Vitals', icon: Activity },
                  { id: 'medications', label: 'Medications', icon: Pill },
                  { id: 'treatments', label: 'Treatments', icon: Calendar },
                  { id: 'notes', label: 'Care Notes', icon: FileText },
               ].map((tab) => {
                  const Icon = tab.icon;
                  return (
                     <button
                        key={tab.id}
                        onClick={() => setActiveTab(tab.id)}
                        className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors ${activeTab === tab.id
                              ? 'border-blue-600 text-blue-600 dark:text-blue-400'
                              : 'border-transparent text-gray-500 dark:text-slate-400 hover:text-gray-700 dark:hover:text-slate-300'
                           }`}
                     >
                        <Icon className="w-4 h-4" />
                        {tab.label}
                     </button>
                  );
               })}
            </div>
         </div>

         {/* Tab Content */}
         {activeTab === 'vitals' && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
               {/* Blood Pressure */}
               <Card className="p-4">
                  <div className="flex items-start justify-between">
                     <div className="flex items-center gap-3">
                        <div className="w-10 h-10 bg-red-100 dark:bg-red-900/30 rounded-lg flex items-center justify-center">
                           <Gauge className="w-5 h-5 text-red-600 dark:text-red-400" />
                        </div>
                        <div>
                           <p className="text-xs text-gray-500 dark:text-slate-400">Blood Pressure</p>
                           <p className="text-lg font-bold text-gray-900 dark:text-slate-100">
                              {currentVitals.bp.systolic}/{currentVitals.bp.diastolic}
                           </p>
                           <p className="text-xs text-gray-500 dark:text-slate-400">mmHg</p>
                        </div>
                     </div>
                  </div>
               </Card>

               {/* Heart Rate */}
               <Card className="p-4">
                  <div className="flex items-start justify-between">
                     <div className="flex items-center gap-3">
                        <div className="w-10 h-10 bg-pink-100 dark:bg-pink-900/30 rounded-lg flex items-center justify-center">
                           <Heart className="w-5 h-5 text-pink-600 dark:text-pink-400" />
                        </div>
                        <div>
                           <p className="text-xs text-gray-500 dark:text-slate-400">Heart Rate</p>
                           <p className="text-lg font-bold text-gray-900 dark:text-slate-100">{currentVitals.heartRate}</p>
                           <p className="text-xs text-gray-500 dark:text-slate-400">bpm</p>
                        </div>
                     </div>
                  </div>
               </Card>

               {/* Temperature */}
               <Card className="p-4">
                  <div className="flex items-start justify-between">
                     <div className="flex items-center gap-3">
                        <div className="w-10 h-10 bg-orange-100 dark:bg-orange-900/30 rounded-lg flex items-center justify-center">
                           <Thermometer className="w-5 h-5 text-orange-600 dark:text-orange-400" />
                        </div>
                        <div>
                           <p className="text-xs text-gray-500 dark:text-slate-400">Temperature</p>
                           <p className="text-lg font-bold text-gray-900 dark:text-slate-100">
                              {currentVitals.temperature.value}°{currentVitals.temperature.unit}
                           </p>
                           <p className="text-xs text-gray-500 dark:text-slate-400">{currentVitals.temperature.route}</p>
                        </div>
                     </div>
                  </div>
               </Card>

               {/* Respiratory Rate */}
               <Card className="p-4">
                  <div className="flex items-start justify-between">
                     <div className="flex items-center gap-3">
                        <div className="w-10 h-10 bg-blue-100 dark:bg-blue-900/30 rounded-lg flex items-center justify-center">
                           <Wind className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                        </div>
                        <div>
                           <p className="text-xs text-gray-500 dark:text-slate-400">Respiratory Rate</p>
                           <p className="text-lg font-bold text-gray-900 dark:text-slate-100">{currentVitals.respiratoryRate}</p>
                           <p className="text-xs text-gray-500 dark:text-slate-400">breaths/min</p>
                        </div>
                     </div>
                  </div>
               </Card>

               {/* Oxygen Saturation */}
               <Card className="p-4">
                  <div className="flex items-start justify-between">
                     <div className="flex items-center gap-3">
                        <div className="w-10 h-10 bg-cyan-100 dark:bg-cyan-900/30 rounded-lg flex items-center justify-center">
                           <Droplet className="w-5 h-5 text-cyan-600 dark:text-cyan-400" />
                        </div>
                        <div>
                           <p className="text-xs text-gray-500 dark:text-slate-400">Oxygen Saturation</p>
                           <p className="text-lg font-bold text-gray-900 dark:text-slate-100">{currentVitals.oxygenSaturation}%</p>
                           <p className="text-xs text-gray-500 dark:text-slate-400">SpO₂</p>
                        </div>
                     </div>
                  </div>
               </Card>

               {/* Pain Level */}
               <Card className="p-4">
                  <div className="flex items-start justify-between">
                     <div className="flex items-center gap-3">
                        <div className="w-10 h-10 bg-purple-100 dark:bg-purple-900/30 rounded-lg flex items-center justify-center">
                           <Frown className="w-5 h-5 text-purple-600 dark:text-purple-400" />
                        </div>
                        <div>
                           <p className="text-xs text-gray-500 dark:text-slate-400">Pain Level</p>
                           <p className="text-lg font-bold text-gray-900 dark:text-slate-100">{currentVitals.painLevel}/10</p>
                           <p className="text-xs text-gray-500 dark:text-slate-400">self-reported</p>
                        </div>
                     </div>
                  </div>
               </Card>

               {/* Last Recorded */}
               <Card className="p-4 md:col-span-2 lg:col-span-3 bg-gray-50 dark:bg-slate-800/50">
                  <p className="text-xs text-gray-500 dark:text-slate-400">
                     Last recorded: {new Date(currentVitals.timestamp).toLocaleString()} by {currentVitals.recordedBy}
                  </p>
                  <Button
                     onClick={() => navigate('/nurse/vitals')}
                     className="mt-3 bg-blue-600 hover:bg-blue-700 text-white flex items-center gap-2"
                     size="sm"
                  >
                     <Activity className="w-4 h-4" />
                     Record New Vitals
                  </Button>
               </Card>
            </div>
         )}

         {activeTab === 'medications' && (
            <Card>
               <div className="divide-y divide-gray-100 dark:divide-slate-700/50">
                  {medicationSchedule.map((med) => {
                     const statusInfo = getStatusBadge(med.status);
                     const StatusIcon = statusInfo.icon;
                     return (
                        <div key={med.id} className="p-4 hover:bg-gray-50 dark:hover:bg-slate-800/30">
                           <div className="flex items-start justify-between gap-4">
                              <div className="flex-1">
                                 <div className="flex items-center gap-2 mb-1">
                                    <h3 className="text-sm font-semibold text-gray-900 dark:text-slate-100">
                                       {med.medication}
                                    </h3>
                                    <Badge type={statusInfo.type} size="sm" className="flex items-center gap-1">
                                       <StatusIcon className="w-3 h-3" />
                                       {statusInfo.text}
                                    </Badge>
                                 </div>
                                 <p className="text-xs text-gray-500 dark:text-slate-400">
                                    Scheduled: {med.time} • Route: {med.route}
                                 </p>
                                 {med.completedAt && (
                                    <p className="text-xs text-green-600 dark:text-green-400 mt-1">
                                       Administered at {med.completedAt}
                                    </p>
                                 )}
                                 {med.notes && (
                                    <p className="text-xs text-gray-600 dark:text-slate-300 mt-1 italic">
                                       Note: {med.notes}
                                    </p>
                                 )}
                              </div>
                              {med.status === 'due' && (
                                 <Button size="sm" className="bg-green-600 hover:bg-green-700 text-white">
                                    Mark Given
                                 </Button>
                              )}
                           </div>
                        </div>
                     );
                  })}
               </div>
            </Card>
         )}

         {activeTab === 'treatments' && (
            <Card>
               <div className="divide-y divide-gray-100 dark:divide-slate-700/50">
                  {treatmentSchedule.map((treatment) => {
                     const statusInfo = getStatusBadge(treatment.status);
                     const StatusIcon = statusInfo.icon;
                     return (
                        <div key={treatment.id} className="p-4 hover:bg-gray-50 dark:hover:bg-slate-800/30">
                           <div className="flex items-start justify-between gap-4">
                              <div className="flex-1">
                                 <div className="flex items-center gap-2 mb-1">
                                    <h3 className="text-sm font-semibold text-gray-900 dark:text-slate-100">
                                       {treatment.treatment}
                                    </h3>
                                    <Badge type={statusInfo.type} size="sm" className="flex items-center gap-1">
                                       <StatusIcon className="w-3 h-3" />
                                       {statusInfo.text}
                                    </Badge>
                                 </div>
                                 <p className="text-xs text-gray-500 dark:text-slate-400">Scheduled: {treatment.time}</p>
                                 {treatment.completedAt && (
                                    <p className="text-xs text-green-600 dark:text-green-400 mt-1">
                                       Completed at {treatment.completedAt}
                                    </p>
                                 )}
                                 {treatment.notes && (
                                    <p className="text-xs text-gray-600 dark:text-slate-300 mt-1 italic">
                                       Note: {treatment.notes}
                                    </p>
                                 )}
                              </div>
                              {treatment.status === 'scheduled' && (
                                 <Button size="sm" variant="outline">
                                    Mark Complete
                                 </Button>
                              )}
                           </div>
                        </div>
                     );
                  })}
               </div>
            </Card>
         )}

         {activeTab === 'notes' && (
            <Card className="p-4">
               <h3 className="text-sm font-bold text-gray-900 dark:text-slate-100 mb-3">Care Observations</h3>
               <p className="text-xs text-gray-500 dark:text-slate-400 mb-3">
                  Document care observations, patient responses, and immediate care notes. Full medical documentation
                  should be done in the EMR system.
               </p>
               <textarea
                  value={careNotes}
                  onChange={(e) => setCareNotes(e.target.value)}
                  className="w-full px-3 py-2 text-sm border border-gray-300 dark:border-slate-600 rounded-lg focus:outline-none focus:ring-2 focus:border-blue-500 focus:ring-blue-400/60 bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100"
                  rows="6"
                  placeholder="Enter care observations here..."
               />
               <div className="flex justify-end gap-2 mt-3">
                  <Button variant="outline" size="sm">
                     Clear
                  </Button>
                  <Button size="sm" className="bg-blue-600 hover:bg-blue-700 text-white">
                     Save Note
                  </Button>
               </div>

               {/* Previous Notes */}
               <div className="mt-6">
                  <h4 className="text-sm font-semibold text-gray-900 dark:text-slate-100 mb-3">Recent Notes</h4>
                  <div className="space-y-3">
                     <div className="p-3 bg-gray-50 dark:bg-slate-800/50 rounded-lg border border-gray-200 dark:border-slate-700">
                        <p className="text-xs text-gray-600 dark:text-slate-300">
                           Patient ambulated to bathroom with assistance. No dizziness reported. Vital signs stable.
                        </p>
                        <p className="text-xs text-gray-500 dark:text-slate-400 mt-2">
                           {new Date().toLocaleString()} • Nurse Martinez
                        </p>
                     </div>
                  </div>
               </div>
            </Card>
         )}
      </div>
   );
};

export default PatientDetails;
