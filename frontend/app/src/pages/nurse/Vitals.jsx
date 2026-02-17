import React, { useState, useMemo, useEffect } from 'react';
import {
   Activity,
   AlertTriangle,
   Heart,
   Clock,
   Save,
   Bell,
   TrendingUp,
   RefreshCw,
} from 'lucide-react';

import Card from '../../components/common/Card';
import Button from '../../components/common/Button';
import Badge from '../../components/common/Badge';
import { mockNurseOverview } from '../../mocks/nurseOverview';



const NurseVitals = () => {
   const [overview, setOverview] = useState(mockNurseOverview);
   const [selectedPatient, setSelectedPatient] = useState(null);
   const [vitalsForm, setVitalsForm] = useState({
      systolic: '',
      diastolic: '',
      heartRate: '',
      temperature: '',
      respiratoryRate: '',
      oxygenSaturation: '',
      painLevel: 0,
   });
   const [notes, setNotes] = useState('');
   const [toast, setToast] = useState(null);

   // Auto-dismiss toast
   useEffect(() => {
      if (!toast) return;
      const timer = setTimeout(() => setToast(null), 4000);
      return () => clearTimeout(timer);
   }, [toast]);

   // Select first patient with vitals due
   useEffect(() => {
      if (!selectedPatient && overview.assignedPatients.length > 0) {
         const patientWithVitalsDue = overview.assignedPatients.find(
            (p) => p.vitalsStatus === 'overdue' || p.vitalsStatus === 'due'
         );
         setSelectedPatient(patientWithVitalsDue || overview.assignedPatients[0]);
      }
   }, [overview.assignedPatients, selectedPatient]);

   // Classify vital value
   const classifyVital = (type, value) => {
      if (!value || value === '') return 'normal';
      const num = Number(value);

      switch (type) {
         case 'systolic':
            if (num < 90 || num > 180) return 'critical';
            if (num > 130) return 'abnormal';
            return 'normal';
         case 'diastolic':
            if (num < 60 || num > 110) return 'critical';
            if (num > 85) return 'abnormal';
            return 'normal';
         case 'heartRate':
            if (num < 50 || num > 120) return 'critical';
            if (num < 60 || num > 100) return 'abnormal';
            return 'normal';
         case 'temperature':
            if (num < 95 || num > 101) return 'critical';
            if (num < 97 || num > 99) return 'abnormal';
            return 'normal';
         case 'respiratoryRate':
            if (num < 8 || num > 30) return 'critical';
            if (num < 12 || num > 20) return 'abnormal';
            return 'normal';
         case 'oxygenSaturation':
            if (num < 90) return 'critical';
            if (num < 95) return 'abnormal';
            return 'normal';
         case 'painLevel':
            if (num >= 7) return 'critical';
            if (num >= 4) return 'abnormal';
            return 'normal';
         default:
            return 'normal';
      }
   };

   // Get input border color
   const getInputClass = (status) => {
      if (status === 'critical') return 'border-red-500 focus:border-red-600 focus:ring-red-400/60';
      if (status === 'abnormal') return 'border-yellow-500 focus:border-yellow-600 focus:ring-yellow-400/60';
      return 'border-gray-300 dark:border-slate-600 focus:border-blue-500 focus:ring-blue-400/60';
   };

   // Check if form has critical values
   const hasCriticalValues = useMemo(() => {
      return (
         classifyVital('systolic', vitalsForm.systolic) === 'critical' ||
         classifyVital('diastolic', vitalsForm.diastolic) === 'critical' ||
         classifyVital('heartRate', vitalsForm.heartRate) === 'critical' ||
         classifyVital('temperature', vitalsForm.temperature) === 'critical' ||
         classifyVital('respiratoryRate', vitalsForm.respiratoryRate) === 'critical' ||
         classifyVital('oxygenSaturation', vitalsForm.oxygenSaturation) === 'critical' ||
         classifyVital('painLevel', vitalsForm.painLevel) === 'critical'
      );
   }, [vitalsForm]);

   // Handle form field change
   const handleFieldChange = (field, value) => {
      setVitalsForm((prev) => ({ ...prev, [field]: value }));
   };

   // Validate form
   const validateForm = () => {
      return (
         vitalsForm.systolic &&
         vitalsForm.diastolic &&
         vitalsForm.heartRate &&
         vitalsForm.temperature &&
         vitalsForm.respiratoryRate &&
         vitalsForm.oxygenSaturation
      );
   };

   // Save vitals
   const handleSave = (notifyPhysician = false) => {
      if (!validateForm()) {
         setToast({ type: 'error', message: 'Please complete all required fields' });
         return;
      }

      if (hasCriticalValues && !notifyPhysician) {
         if (
            !window.confirm(
               'Critical values detected. Do you want to save and notify the physician?'
            )
         ) {
            return;
         }
      }

      // Save vitals (mock)
      const timestamp = new Date().toISOString();
      const newEntry = {
         timestamp,
         bp: `${vitalsForm.systolic}/${vitalsForm.diastolic}`,
         hr: Number(vitalsForm.heartRate),
         temp: Number(vitalsForm.temperature),
         rr: Number(vitalsForm.respiratoryRate),
         spo2: Number(vitalsForm.oxygenSaturation),
         pain: Number(vitalsForm.painLevel),
         recordedBy: overview.nurse.name,
         notes,
      };

      setOverview((prev) => ({
         ...prev,
         vitals: {
            ...prev.vitals,
            history: [newEntry, ...(prev.vitals?.history || [])],
         },
      }));

      // Reset form
      setVitalsForm({
         systolic: '',
         diastolic: '',
         heartRate: '',
         temperature: '',
         respiratoryRate: '',
         oxygenSaturation: '',
         painLevel: 0,
      });
      setNotes('');

      setToast({
         type: 'success',
         message: notifyPhysician
            ? 'Vitals saved and physician notified'
            : 'Vitals saved successfully',
      });
   };

   // Get vitals history
   const vitalsHistory = overview.vitals?.history || [];

   return (
      <div className="space-y-4">
         {/* Header */}
         <Card>
            <div className="p-4 flex items-center justify-between">
               <div className="flex items-center gap-3">
                  <div className="w-10 h-10 bg-blue-100 dark:bg-blue-900/30 rounded-lg flex items-center justify-center">
                     <Heart className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                  </div>
                  <div>
                     <h1 className="text-lg font-bold text-gray-900 dark:text-slate-100">
                        Patient Vitals
                     </h1>
                     <p className="text-xs text-gray-500 dark:text-slate-400">
                        Record and monitor vital signs
                     </p>
                  </div>
               </div>

               {overview.stats.overdueVitals > 0 && (
                  <Badge type="red" className="flex items-center gap-1">
                     <AlertTriangle className="w-3.5 h-3.5" />
                     {overview.stats.overdueVitals} overdue
                  </Badge>
               )}
            </div>
         </Card>

         {/* Toast */}
         {toast && (
            <div
               className={`fixed top-6 right-6 z-50 px-4 py-3 rounded-lg shadow-xl ${toast.type === 'success'
                  ? 'bg-green-600 text-white'
                  : 'bg-red-600 text-white'
                  }`}
            >
               {toast.message}
            </div>
         )}

         <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Patient Selection */}
            <Card className="lg:col-span-1">
               <div className="px-4 py-3 border-b border-gray-200 dark:border-slate-700">
                  <h2 className="text-sm font-bold text-gray-900 dark:text-slate-100">
                     Select Patient
                  </h2>
               </div>
               <div className="divide-y divide-gray-100 dark:divide-slate-700/50 max-h-96 overflow-y-auto">
                  {overview.assignedPatients.map((patient) => (
                     <button
                        key={patient.id}
                        onClick={() => setSelectedPatient(patient)}
                        className={`w-full p-3 text-left hover:bg-gray-50 dark:hover:bg-slate-800/50 transition-colors ${selectedPatient?.id === patient.id
                           ? 'bg-blue-50 dark:bg-blue-900/20'
                           : ''
                           }`}
                     >
                        <div className="flex items-start justify-between gap-2">
                           <div className="flex-1 min-w-0">
                              <p className="text-sm font-semibold text-gray-900 dark:text-slate-100 truncate">
                                 {patient.name}
                              </p>
                              <p className="text-xs text-gray-500 dark:text-slate-400 mt-0.5">
                                 Room {patient.room} • Bed {patient.bed}
                              </p>
                           </div>
                           <div className="flex flex-col items-end gap-1">
                              <Badge
                                 type={
                                    patient.vitalsStatus === 'overdue'
                                       ? 'red'
                                       : patient.vitalsStatus === 'due'
                                          ? 'yellow'
                                          : 'green'
                                 }
                                 size="sm"
                              >
                                 {patient.vitalsStatus}
                              </Badge>
                           </div>
                        </div>
                     </button>
                  ))}
               </div>
            </Card>

            {/* Vitals Entry Form */}
            <Card className="lg:col-span-2">
               <div className="px-4 py-3 border-b border-gray-200 dark:border-slate-700 flex items-center justify-between">
                  <div>
                     <h2 className="text-sm font-bold text-gray-900 dark:text-slate-100">
                        Record Vitals
                     </h2>
                     {selectedPatient && (
                        <p className="text-xs text-gray-500 dark:text-slate-400 mt-0.5">
                           {selectedPatient.name} • Room {selectedPatient.room}
                        </p>
                     )}
                  </div>
                  {hasCriticalValues && (
                     <Badge type="red" className="flex items-center gap-1">
                        <AlertTriangle className="w-3.5 h-3.5" />
                        Critical values
                     </Badge>
                  )}
               </div>

               <div className="p-4 space-y-4">
                  {/* Blood Pressure */}
                  <div className="grid grid-cols-2 gap-3">
                     <div>
                        <label className="block text-xs font-medium text-gray-700 dark:text-slate-300 mb-1">
                           Systolic BP (mmHg) *
                        </label>
                        <input
                           type="number"
                           value={vitalsForm.systolic}
                           onChange={(e) => handleFieldChange('systolic', e.target.value)}
                           className={`w-full px-3 py-2 text-sm border rounded-lg focus:outline-none focus:ring-2 ${getInputClass(
                              classifyVital('systolic', vitalsForm.systolic)
                           )}`}
                           placeholder="120"
                        />
                        <p className="text-xs text-gray-500 dark:text-slate-400 mt-1">
                           Normal: 90-130
                        </p>
                     </div>
                     <div>
                        <label className="block text-xs font-medium text-gray-700 dark:text-slate-300 mb-1">
                           Diastolic BP (mmHg) *
                        </label>
                        <input
                           type="number"
                           value={vitalsForm.diastolic}
                           onChange={(e) => handleFieldChange('diastolic', e.target.value)}
                           className={`w-full px-3 py-2 text-sm border rounded-lg focus:outline-none focus:ring-2 ${getInputClass(
                              classifyVital('diastolic', vitalsForm.diastolic)
                           )}`}
                           placeholder="80"
                        />
                        <p className="text-xs text-gray-500 dark:text-slate-400 mt-1">
                           Normal: 60-85
                        </p>
                     </div>
                  </div>

                  {/* Heart Rate & Temperature */}
                  <div className="grid grid-cols-2 gap-3">
                     <div>
                        <label className="block text-xs font-medium text-gray-700 dark:text-slate-300 mb-1">
                           Heart Rate (bpm) *
                        </label>
                        <input
                           type="number"
                           value={vitalsForm.heartRate}
                           onChange={(e) => handleFieldChange('heartRate', e.target.value)}
                           className={`w-full px-3 py-2 text-sm border rounded-lg focus:outline-none focus:ring-2 ${getInputClass(
                              classifyVital('heartRate', vitalsForm.heartRate)
                           )}`}
                           placeholder="72"
                        />
                        <p className="text-xs text-gray-500 dark:text-slate-400 mt-1">
                           Normal: 60-100
                        </p>
                     </div>
                     <div>
                        <label className="block text-xs font-medium text-gray-700 dark:text-slate-300 mb-1">
                           Temperature (°F) *
                        </label>
                        <input
                           type="number"
                           step="0.1"
                           value={vitalsForm.temperature}
                           onChange={(e) => handleFieldChange('temperature', e.target.value)}
                           className={`w-full px-3 py-2 text-sm border rounded-lg focus:outline-none focus:ring-2 ${getInputClass(
                              classifyVital('temperature', vitalsForm.temperature)
                           )}`}
                           placeholder="98.6"
                        />
                        <p className="text-xs text-gray-500 dark:text-slate-400 mt-1">
                           Normal: 97-99
                        </p>
                     </div>
                  </div>

                  {/* Respiratory Rate & Oxygen Saturation */}
                  <div className="grid grid-cols-2 gap-3">
                     <div>
                        <label className="block text-xs font-medium text-gray-700 dark:text-slate-300 mb-1">
                           Respiratory Rate (breaths/min) *
                        </label>
                        <input
                           type="number"
                           value={vitalsForm.respiratoryRate}
                           onChange={(e) => handleFieldChange('respiratoryRate', e.target.value)}
                           className={`w-full px-3 py-2 text-sm border rounded-lg focus:outline-none focus:ring-2 ${getInputClass(
                              classifyVital('respiratoryRate', vitalsForm.respiratoryRate)
                           )}`}
                           placeholder="16"
                        />
                        <p className="text-xs text-gray-500 dark:text-slate-400 mt-1">
                           Normal: 12-20
                        </p>
                     </div>
                     <div>
                        <label className="block text-xs font-medium text-gray-700 dark:text-slate-300 mb-1">
                           Oxygen Saturation (%) *
                        </label>
                        <input
                           type="number"
                           value={vitalsForm.oxygenSaturation}
                           onChange={(e) => handleFieldChange('oxygenSaturation', e.target.value)}
                           className={`w-full px-3 py-2 text-sm border rounded-lg focus:outline-none focus:ring-2 ${getInputClass(
                              classifyVital('oxygenSaturation', vitalsForm.oxygenSaturation)
                           )}`}
                           placeholder="98"
                        />
                        <p className="text-xs text-gray-500 dark:text-slate-400 mt-1">
                           Normal: 95-100
                        </p>
                     </div>
                  </div>

                  {/* Pain Level */}
                  <div>
                     <label className="block text-xs font-medium text-gray-700 dark:text-slate-300 mb-2">
                        Pain Level (0-10)
                     </label>
                     <div className="flex items-center gap-2">
                        <input
                           type="range"
                           min="0"
                           max="10"
                           value={vitalsForm.painLevel}
                           onChange={(e) => handleFieldChange('painLevel', e.target.value)}
                           className="flex-1"
                        />
                        <span
                           className={`text-lg font-bold w-8 text-center ${classifyVital('painLevel', vitalsForm.painLevel) === 'critical'
                              ? 'text-red-600'
                              : classifyVital('painLevel', vitalsForm.painLevel) === 'abnormal'
                                 ? 'text-yellow-600'
                                 : 'text-green-600'
                              }`}
                        >
                           {vitalsForm.painLevel}
                        </span>
                     </div>
                     <p className="text-xs text-gray-500 dark:text-slate-400 mt-1">Goal: 0-3</p>
                  </div>

                  {/* Notes */}
                  <div>
                     <label className="block text-xs font-medium text-gray-700 dark:text-slate-300 mb-1">
                        Notes (Optional)
                     </label>
                     <textarea
                        value={notes}
                        onChange={(e) => setNotes(e.target.value)}
                        className="w-full px-3 py-2 text-sm border border-gray-300 dark:border-slate-600 rounded-lg focus:outline-none focus:ring-2 focus:border-blue-500 focus:ring-blue-400/60"
                        rows="2"
                        placeholder="Additional observations..."
                     />
                  </div>

                  {/* Action Buttons */}
                  <div className="flex gap-2 pt-2">
                     <Button
                        onClick={() => handleSave(false)}
                        className="flex-1 bg-blue-600 hover:bg-blue-700 text-white flex items-center justify-center gap-2"
                     >
                        <Save className="w-4 h-4" />
                        Save Vitals
                     </Button>
                     {hasCriticalValues && (
                        <Button
                           onClick={() => handleSave(true)}
                           className="flex-1 bg-red-600 hover:bg-red-700 text-white flex items-center justify-center gap-2"
                        >
                           <Bell className="w-4 h-4" />
                           Save & Notify MD
                        </Button>
                     )}
                  </div>
               </div>
            </Card>
         </div>

         {/* Vitals History */}
         <Card>
            <div className="px-4 py-3 border-b border-gray-200 dark:border-slate-700 flex items-center justify-between">
               <h2 className="text-sm font-bold text-gray-900 dark:text-slate-100">
                  Recent Vitals History
               </h2>
               <Button variant="link" size="sm" className="flex items-center gap-1">
                  <RefreshCw className="w-3.5 h-3.5" />
                  Refresh
               </Button>
            </div>
            <div className="overflow-x-auto">
               <table className="w-full text-sm">
                  <thead className="bg-gray-50 dark:bg-slate-800/50 border-b border-gray-200 dark:border-slate-700">
                     <tr>
                        <th className="px-4 py-2 text-left text-xs font-medium text-gray-700 dark:text-slate-300">
                           Time
                        </th>
                        <th className="px-4 py-2 text-left text-xs font-medium text-gray-700 dark:text-slate-300">
                           BP
                        </th>
                        <th className="px-4 py-2 text-left text-xs font-medium text-gray-700 dark:text-slate-300">
                           HR
                        </th>
                        <th className="px-4 py-2 text-left text-xs font-medium text-gray-700 dark:text-slate-300">
                           Temp
                        </th>
                        <th className="px-4 py-2 text-left text-xs font-medium text-gray-700 dark:text-slate-300">
                           RR
                        </th>
                        <th className="px-4 py-2 text-left text-xs font-medium text-gray-700 dark:text-slate-300">
                           SpO₂
                        </th>
                        <th className="px-4 py-2 text-left text-xs font-medium text-gray-700 dark:text-slate-300">
                           Pain
                        </th>
                        <th className="px-4 py-2 text-left text-xs font-medium text-gray-700 dark:text-slate-300">
                           Recorded By
                        </th>
                     </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100 dark:divide-slate-700/50">
                     {vitalsHistory.slice(0, 10).map((entry, index) => (
                        <tr key={index} className="hover:bg-gray-50 dark:hover:bg-slate-800/30">
                           <td className="px-4 py-2 text-xs text-gray-900 dark:text-slate-100">
                              {new Date(entry.timestamp).toLocaleString(undefined, {
                                 month: 'short',
                                 day: 'numeric',
                                 hour: 'numeric',
                                 minute: '2-digit',
                              })}
                           </td>
                           <td className="px-4 py-2 text-xs text-gray-700 dark:text-slate-300">
                              {entry.bp}
                           </td>
                           <td className="px-4 py-2 text-xs text-gray-700 dark:text-slate-300">
                              {entry.hr}
                           </td>
                           <td className="px-4 py-2 text-xs text-gray-700 dark:text-slate-300">
                              {entry.temp}°F
                           </td>
                           <td className="px-4 py-2 text-xs text-gray-700 dark:text-slate-300">
                              {entry.rr}
                           </td>
                           <td className="px-4 py-2 text-xs text-gray-700 dark:text-slate-300">
                              {entry.spo2}%
                           </td>
                           <td className="px-4 py-2 text-xs text-gray-700 dark:text-slate-300">
                              {entry.pain}/10
                           </td>
                           <td className="px-4 py-2 text-xs text-gray-500 dark:text-slate-400">
                              {entry.recordedBy}
                           </td>
                        </tr>
                     ))}
                     {vitalsHistory.length === 0 && (
                        <tr>
                           <td colSpan="8" className="px-4 py-8 text-center text-gray-500 dark:text-slate-400">
                              <Activity className="w-12 h-12 mx-auto mb-2 opacity-50" />
                              <p className="text-sm">No vitals recorded yet</p>
                           </td>
                        </tr>
                     )}
                  </tbody>
               </table>
            </div>
         </Card>
      </div>
   );
};

export default NurseVitals;
