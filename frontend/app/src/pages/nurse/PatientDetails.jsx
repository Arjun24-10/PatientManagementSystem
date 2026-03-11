import React, { useState, useEffect } from 'react';
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
   CheckCircle,
   XCircle,
} from 'lucide-react';
import { useNavigate, useParams } from 'react-router-dom';

import Card from '../../components/common/Card';
import Button from '../../components/common/Button';
import Badge from '../../components/common/Badge';
import api from '../../services/api';

const PatientDetails = () => {
   const navigate = useNavigate();
   const { patientId } = useParams();
   const [activeTab, setActiveTab] = useState('vitals');
   const [careNotes, setCareNotes] = useState('');
   const [patient, setPatient] = useState(null);
   const [latestVitals, setLatestVitals] = useState(null);
   const [prescriptions, setPrescriptions] = useState([]);
   const [loading, setLoading] = useState(true);

   useEffect(() => {
      const loadData = async () => {
         try {
            const [patients, vitals, rxData] = await Promise.all([
               api.nurse.getAssignedPatients(),
               api.vitalSigns.getLatest(patientId).catch(() => null),
               api.prescriptions.getByPatient(patientId).catch(() => []),
            ]);
            const found = Array.isArray(patients)
               ? patients.find((p) => String(p.profileId) === String(patientId))
               : null;
            setPatient(found || null);
            setLatestVitals(vitals || null);
            setPrescriptions(Array.isArray(rxData) ? rxData : []);
         } catch (err) {
            console.error('Failed to load patient details:', err);
         } finally {
            setLoading(false);
         }
      };
      loadData();
   }, [patientId]);

   if (loading) {
      return <div className="p-8 text-center text-gray-500 dark:text-slate-400">Loading...</div>;
   }

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

   const patientName = `${patient.firstName || ''} ${patient.lastName || ''}`.trim() || 'Unknown';
   const bpParts = latestVitals?.bloodPressure ? latestVitals.bloodPressure.split('/') : ['—', '—'];

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
               <h1 className="text-lg font-bold text-gray-900 dark:text-slate-100">{patientName}</h1>
               <p className="text-sm text-gray-500 dark:text-slate-400">
                  MRN: {patient.profileId}
               </p>
            </div>
            </div>

         {/* Patient Basic Info - HIPAA Compliant (Demographics Only) */}
         <Card>
            <div className="p-4">
               <h2 className="text-sm font-bold text-gray-900 dark:text-slate-100 mb-3 flex items-center gap-2">
                  <User className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                  Patient Information
               </h2>
               <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                  <div>
                     <p className="text-xs text-gray-500 dark:text-slate-400">Age</p>
                     <p className="text-sm font-semibold text-gray-900 dark:text-slate-100">
                        {patient.dateOfBirth
                           ? `${new Date().getFullYear() - new Date(patient.dateOfBirth).getFullYear()} years`
                           : '—'}
                     </p>
                  </div>
                  <div>
                     <p className="text-xs text-gray-500 dark:text-slate-400">Gender</p>
                     <p className="text-sm font-semibold text-gray-900 dark:text-slate-100">{patient.gender || '—'}</p>
                  </div>
                  <div>
                     <p className="text-xs text-gray-500 dark:text-slate-400">Admission Date</p>
                     <p className="text-sm font-semibold text-gray-900 dark:text-slate-100">
                        {patient.createdAt ? new Date(patient.createdAt).toLocaleDateString() : '—'}
                     </p>
                  </div>
               </div>

               {/* Medical History / Allergies */}
               {patient.medicalHistory && (
                  <div className="mt-4 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                     <div className="flex items-start gap-2">
                        <AlertTriangle className="w-4 h-4 text-red-600 dark:text-red-400 flex-shrink-0 mt-0.5" />
                        <div>
                           <p className="text-sm font-semibold text-red-900 dark:text-red-100">Medical History / Allergies</p>
                           <p className="text-xs text-red-800 dark:text-red-200 mt-1">{patient.medicalHistory}</p>
                        </div>
                     </div>
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
                              {bpParts[0]}/{bpParts[1]}
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
                           <p className="text-lg font-bold text-gray-900 dark:text-slate-100">{latestVitals?.heartRate ?? '—'}</p>
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
                              {latestVitals?.temperature != null ? `${latestVitals.temperature}°F` : '—'}
                           </p>
                           <p className="text-xs text-gray-500 dark:text-slate-400">oral</p>
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
                           <p className="text-lg font-bold text-gray-900 dark:text-slate-100">{latestVitals?.respiratoryRate ?? '—'}</p>
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
                           <p className="text-lg font-bold text-gray-900 dark:text-slate-100">{latestVitals?.oxygenSaturation != null ? `${latestVitals.oxygenSaturation}%` : '—'}</p>
                           <p className="text-xs text-gray-500 dark:text-slate-400">SpO₂</p>
                        </div>
                     </div>
                  </div>
               </Card>

               {/* Last Recorded */}
               <Card className="p-4 md:col-span-2 lg:col-span-3 bg-gray-50 dark:bg-slate-800/50">
                  <p className="text-xs text-gray-500 dark:text-slate-400">
                     {latestVitals?.recordedAt
                        ? `Last recorded: ${new Date(latestVitals.recordedAt).toLocaleString()}${latestVitals.nurse?.username ? ` by ${latestVitals.nurse.username}` : ''}`
                        : 'No vitals recorded yet'}
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
               {prescriptions.length === 0 ? (
                  <p className="p-6 text-sm text-gray-500 dark:text-slate-400 text-center">No prescriptions found.</p>
               ) : (
                  <div className="divide-y divide-gray-100 dark:divide-slate-700/50">
                     {prescriptions.map((med) => {
                        const status = (med.status || 'ACTIVE').toUpperCase();
                        const normalized = status === 'ACTIVE' ? 'scheduled' : status === 'COMPLETED' ? 'completed' : 'scheduled';
                        const statusInfo = getStatusBadge(normalized);
                        const StatusIcon = statusInfo.icon;
                        return (
                           <div key={med.prescriptionId} className="p-4 hover:bg-gray-50 dark:hover:bg-slate-800/30">
                              <div className="flex items-start justify-between gap-4">
                                 <div className="flex-1">
                                    <div className="flex items-center gap-2 mb-1">
                                       <h3 className="text-sm font-semibold text-gray-900 dark:text-slate-100">
                                          {med.medicationName}{med.dosage ? ` (${med.dosage})` : ''}
                                       </h3>
                                       <Badge type={statusInfo.type} size="sm" className="flex items-center gap-1">
                                          <StatusIcon className="w-3 h-3" />
                                          {statusInfo.text}
                                       </Badge>
                                    </div>
                                    <p className="text-xs text-gray-500 dark:text-slate-400">
                                       Frequency: {med.frequency || '—'}
                                    </p>
                                    {med.specialInstructions && (
                                       <p className="text-xs text-gray-600 dark:text-slate-300 mt-1 italic">
                                          Note: {med.specialInstructions}
                                       </p>
                                    )}
                                 </div>
                              </div>
                           </div>
                        );
                     })}
                  </div>
               )}
            </Card>
         )}

         {activeTab === 'treatments' && (
            <Card className="p-6">
               <p className="text-sm text-gray-500 dark:text-slate-400 text-center">
                  Treatment information is managed in the EMR system.
               </p>
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
