import React, { useEffect, useMemo, useState } from 'react';
import {
   Activity,
   AlertCircle,
   AlertTriangle,
   Calendar,
   Check,
   Clock,
   Frown,
   Heart,
   Meh,
   Minus,
   Smile,
   TrendingDown,
   TrendingUp,
   Users,
   X,
} from 'lucide-react';

import Card from '../../components/common/Card';
import Button from '../../components/common/Button';
import { mockNurseOverview } from '../../mocks/nurseOverview';
import VitalsSectionHeader from './components/VitalsSectionHeader';
import VitalsAlertBanner from './components/VitalsAlertBanner';
import VitalsEntryForm from './components/VitalsEntryForm';
import VitalsOverviewCard from './components/VitalsOverviewCard';
import VitalsTrendCard from './components/VitalsTrendCard';
import VitalsLogTable from './components/VitalsLogTable';
import AssignedPatientsPanel from './components/AssignedPatientsPanel';

const acuityStyles = {
   critical: {
      label: 'Critical',
      badge: 'bg-red-500 text-white',
      border: 'border-l-4 border-red-500 ring-1 ring-red-100',
   },
   high: {
      label: 'High',
      badge: 'bg-orange-500 text-white',
      border: 'border-l-4 border-orange-400',
   },
   moderate: {
      label: 'Moderate',
      badge: 'bg-yellow-300 text-gray-900',
      border: 'border-l-4 border-yellow-300',
   },
   stable: {
      label: 'Stable',
      badge: 'bg-green-500 text-white',
      border: 'border-l-4 border-green-500',
   },
};

const vitalsStatusMap = {
   done: { icon: Check, text: 'Vitals done', classes: 'text-green-600' },
   due: { icon: Clock, text: 'Due soon', classes: 'text-yellow-500' },
   overdue: { icon: AlertTriangle, text: 'Overdue', classes: 'text-red-500' },
};

const medicationStatusMap = {
   'all-given': { icon: Check, text: 'All given', classes: 'text-green-600' },
   'due-soon': { icon: Activity, text: 'Due soon', classes: 'text-amber-500' },
   overdue: { icon: AlertCircle, text: 'Overdue', classes: 'text-red-500' },
};

const VITAL_LIMITS = {
   bp: {
      normal: { systolic: [90, 130], diastolic: [60, 85] },
      abnormal: { systolic: [130, 180], diastolic: [85, 110] },
      criticalHigh: { systolic: 180, diastolic: 110 },
      criticalLow: { systolic: 90, diastolic: 60 },
   },
   heartRate: { normal: [60, 100], abnormal: [100, 120], criticalHigh: 120, criticalLow: 50 },
   temperature: {
      normalF: [97, 99],
      abnormalF: [99, 101],
      criticalHighF: 101,
      criticalLowF: 95,
   },
   respiratoryRate: { normal: [12, 20], abnormal: [20, 24], criticalHigh: 30, criticalLow: 8 },
   oxygenSaturation: { normal: [95, 100], abnormal: [90, 95], criticalLow: 90 },
   painLevel: { normal: [0, 3], abnormal: [4, 6], critical: [7, 10] },
};

const statusTone = {
   normal: { text: 'text-green-600', border: 'border-green-400', bg: 'bg-green-50' },
   abnormal: { text: 'text-amber-600', border: 'border-amber-400', bg: 'bg-amber-50' },
   critical: { text: 'text-red-600', border: 'border-red-400', bg: 'bg-red-50' },
};

const convertTemperature = (value, fromUnit, toUnit) => {
   const numericValue = Number(value);
   if (Number.isNaN(numericValue) || fromUnit === toUnit) return numericValue;
   if (fromUnit === 'F' && toUnit === 'C') {
      return ((numericValue - 32) * 5) / 9;
   }
   if (fromUnit === 'C' && toUnit === 'F') {
      return (numericValue * 9) / 5 + 32;
   }
   return numericValue;
};

const formatTimestamp = (timestamp) =>
   new Date(timestamp).toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      hour: 'numeric',
      minute: '2-digit',
   });

const parseBpString = (value) => {
   if (!value) return { systolic: NaN, diastolic: NaN };
   const [systolic, diastolic] = value.split('/').map((segment) => Number.parseInt(segment, 10));
   return { systolic, diastolic };
};

const classifyBp = (systolic, diastolic) => {
   if (Number.isNaN(systolic) || Number.isNaN(diastolic)) return 'normal';
   if (systolic > VITAL_LIMITS.bp.criticalHigh.systolic || diastolic > VITAL_LIMITS.bp.criticalHigh.diastolic || systolic < VITAL_LIMITS.bp.criticalLow.systolic || diastolic < VITAL_LIMITS.bp.criticalLow.diastolic) {
      return 'critical';
   }
   if (systolic > VITAL_LIMITS.bp.normal.systolic[1] || diastolic > VITAL_LIMITS.bp.normal.diastolic[1]) {
      return 'abnormal';
   }
   return 'normal';
};

const classifyValue = (type, value) => {
   if (value === '' || value === null || Number.isNaN(Number(value))) return 'normal';
   const numericValue = Number(value);

   switch (type) {
      case 'heartRate':
         if (numericValue > VITAL_LIMITS.heartRate.criticalHigh || numericValue < VITAL_LIMITS.heartRate.criticalLow) return 'critical';
         if (numericValue > VITAL_LIMITS.heartRate.normal[1] || numericValue < VITAL_LIMITS.heartRate.normal[0]) return 'abnormal';
         return 'normal';
      case 'temperature':
         if (numericValue > VITAL_LIMITS.temperature.criticalHighF || numericValue < VITAL_LIMITS.temperature.criticalLowF) return 'critical';
         if (numericValue > VITAL_LIMITS.temperature.normalF[1] || numericValue < VITAL_LIMITS.temperature.normalF[0]) return 'abnormal';
         return 'normal';
      case 'respiratoryRate':
         if (numericValue > VITAL_LIMITS.respiratoryRate.criticalHigh || numericValue < VITAL_LIMITS.respiratoryRate.criticalLow) return 'critical';
         if (numericValue > VITAL_LIMITS.respiratoryRate.normal[1] || numericValue < VITAL_LIMITS.respiratoryRate.normal[0]) return 'abnormal';
         return 'normal';
      case 'oxygenSaturation':
         if (numericValue < VITAL_LIMITS.oxygenSaturation.criticalLow) return 'critical';
         if (numericValue < VITAL_LIMITS.oxygenSaturation.normal[0]) return 'abnormal';
         return 'normal';
      case 'painLevel':
         if (numericValue >= VITAL_LIMITS.painLevel.critical[0]) return 'critical';
         if (numericValue >= VITAL_LIMITS.painLevel.abnormal[0]) return 'abnormal';
         return 'normal';
      default:
         return 'normal';
   }
};

const getStatusClasses = (status) => {
   const tone = statusTone[status] || statusTone.normal;
   return {
      border: tone.border,
      text: tone.text,
      bg: tone.bg,
   };
};

const inputBorderByStatus = {
   normal: 'border-gray-200 focus:border-brand-medium focus:ring-brand-medium/60',
   abnormal: 'border-amber-400 focus:border-amber-500 focus:ring-amber-300/60',
   critical: 'border-red-500 focus:border-red-600 focus:ring-red-400/60',
};

const getInputStatusClasses = (status) => inputBorderByStatus[status] || inputBorderByStatus.normal;

const vitalsNormalText = {
   bp: 'Normal: 90-130 / 60-85 mmHg',
   heartRate: 'Normal: 60-100 bpm',
   temperature: 'Normal: 97-99 °F',
   respiratoryRate: 'Normal: 12-20 breaths/min',
   oxygenSaturation: 'Normal: 95-100 %',
   painLevel: 'Goal: 0-3 / 10',
};

const painFaces = [
   { icon: Smile, label: 'No pain', values: [0, 1] },
   { icon: Meh, label: 'Mild', values: [2, 3, 4] },
   { icon: Frown, label: 'Severe', values: [5, 6, 7, 8, 9, 10] },
];

const trendIcon = (direction) => {
   if (direction === 'up') return <TrendingUp className="w-4 h-4 text-red-500" aria-hidden="true" />;
   if (direction === 'down') return <TrendingDown className="w-4 h-4 text-green-500" aria-hidden="true" />;
   return <Minus className="w-4 h-4 text-gray-400" aria-hidden="true" />;
};

const filterPresets = [
   { id: 'all', label: 'All' },
   { id: 'critical', label: 'Critical' },
   { id: 'needs-attention', label: 'Needs Attention' },
   { id: 'stable', label: 'Stable' },
];

const sortOptions = [
   { id: 'room', label: 'Room Number' },
   { id: 'priority', label: 'Priority' },
   { id: 'name', label: 'Name' },
   { id: 'vitals', label: 'Vitals Due' },
];

const NurseVitals = () => {
   const [overview, setOverview] = useState(mockNurseOverview);
   const [currentTime, setCurrentTime] = useState(new Date());
   const [viewMode, setViewMode] = useState('grid');
   const [activeFilter, setActiveFilter] = useState('all');
   const [sortBy, setSortBy] = useState('room');
   const [temperatureUnit, setTemperatureUnit] = useState(mockNurseOverview.vitals?.current?.temperature?.unit || 'F');
   const [temperatureRoute, setTemperatureRoute] = useState(mockNurseOverview.vitals?.current?.temperature?.route || 'oral');
   const [vitalsForm, setVitalsForm] = useState(() => ({
      systolic: mockNurseOverview.vitals?.current?.bp?.systolic ?? '',
      diastolic: mockNurseOverview.vitals?.current?.bp?.diastolic ?? '',
      heartRate: mockNurseOverview.vitals?.current?.heartRate ?? '',
      temperature: mockNurseOverview.vitals?.current?.temperature?.value ?? '',
      respiratoryRate: mockNurseOverview.vitals?.current?.respiratoryRate ?? '',
      oxygenSaturation: mockNurseOverview.vitals?.current?.oxygenSaturation ?? '',
      painLevel: mockNurseOverview.vitals?.current?.painLevel ?? 0,
   }));
   const [vitalsNotes, setVitalsNotes] = useState('');
   const [showCriticalModal, setShowCriticalModal] = useState(false);
   const [pendingAction, setPendingAction] = useState(null);
   const [toast, setToast] = useState(null);
   const [timeRange, setTimeRange] = useState('24h');
   const [customRange, setCustomRange] = useState({ start: '', end: '' });
   const [visibleVitals, setVisibleVitals] = useState({
      bpSystolic: true,
      bpDiastolic: true,
      heartRate: true,
      temperature: true,
      respiratoryRate: true,
      oxygenSaturation: true,
   });
   const [alertAcknowledged, setAlertAcknowledged] = useState(false);
   const [alertNotified, setAlertNotified] = useState(false);
   const [historySearch, setHistorySearch] = useState('');
   const [historyRange, setHistoryRange] = useState({ start: '', end: '' });
   const [formError, setFormError] = useState('');

   useEffect(() => {
      const interval = setInterval(() => setCurrentTime(new Date()), 60_000);
      return () => clearInterval(interval);
   }, []);

   useEffect(() => {
      if (!toast) return undefined;
      const timer = setTimeout(() => setToast(null), 4000);
      return () => clearTimeout(timer);
   }, [toast]);

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

   const segmentedPatients = useMemo(() => overview.assignedPatients.map((patient) => {
      let filterKey = 'stable';
      if (patient.acuityLevel === 'critical') filterKey = 'critical';
      else if (patient.acuityLevel === 'high' || patient.vitalsStatus === 'overdue' || patient.medicationStatus === 'overdue') {
         filterKey = 'needs-attention';
      }
      return { ...patient, filterKey };
   }), [overview.assignedPatients]);

   const filteredPatients = useMemo(() => {
      const subset = segmentedPatients.filter((patient) => activeFilter === 'all' || patient.filterKey === activeFilter);

      const sorter = {
         room: (a, b) => `${a.room}${a.bed}`.localeCompare(`${b.room}${b.bed}`),
         priority: (a, b) => {
            const priorityOrder = ['critical', 'high', 'moderate', 'stable'];
            return priorityOrder.indexOf(a.acuityLevel) - priorityOrder.indexOf(b.acuityLevel);
         },
         name: (a, b) => a.name.localeCompare(b.name),
         vitals: (a, b) => {
            const statusOrder = ['overdue', 'due', 'done'];
            return statusOrder.indexOf(a.vitalsStatus) - statusOrder.indexOf(b.vitalsStatus);
         },
      };

      return subset.sort(sorter[sortBy]);
   }, [activeFilter, segmentedPatients, sortBy]);

   const patientFilterOptions = useMemo(() => {
      const counts = segmentedPatients.reduce((acc, patient) => {
         acc[patient.filterKey] = (acc[patient.filterKey] || 0) + 1;
         return acc;
      }, {});

      return filterPresets.map((filter) => {
         const count = filter.id === 'all' ? overview.assignedPatients.length : counts[filter.id] || 0;
         return {
            ...filter,
            label: `${filter.label} (${count})`,
         };
      });
   }, [overview.assignedPatients.length, segmentedPatients]);

   const vitalsData = overview.vitals || null;

   const temperatureInFahrenheit = useMemo(() => (
      temperatureUnit === 'F' ? Number(vitalsForm.temperature) : convertTemperature(vitalsForm.temperature, 'C', 'F')
   ), [temperatureUnit, vitalsForm.temperature]);

   const formStatuses = useMemo(() => ({
      bp: classifyBp(Number(vitalsForm.systolic), Number(vitalsForm.diastolic)),
      heartRate: classifyValue('heartRate', vitalsForm.heartRate),
      temperature: classifyValue('temperature', temperatureInFahrenheit),
      respiratoryRate: classifyValue('respiratoryRate', vitalsForm.respiratoryRate),
      oxygenSaturation: classifyValue('oxygenSaturation', vitalsForm.oxygenSaturation),
      painLevel: classifyValue('painLevel', vitalsForm.painLevel),
   }), [vitalsForm, temperatureInFahrenheit]);

   const formHasCritical = useMemo(() => Object.values(formStatuses).some((status) => status === 'critical'), [formStatuses]);

   const currentVitalsStatuses = useMemo(() => {
      if (!vitalsData?.current) return {};
      const { bp, heartRate: hr, temperature, respiratoryRate: rr, oxygenSaturation: spo2, painLevel } = vitalsData.current;
      const tempF = temperature ? convertTemperature(temperature.value, temperature.unit || 'F', 'F') : null;
      return {
         bp: classifyBp(bp?.systolic, bp?.diastolic),
         heartRate: classifyValue('heartRate', hr),
         temperature: classifyValue('temperature', tempF),
         respiratoryRate: classifyValue('respiratoryRate', rr),
         oxygenSaturation: classifyValue('oxygenSaturation', spo2),
         painLevel: classifyValue('painLevel', painLevel),
      };
   }, [vitalsData]);

   const currentHasCritical = useMemo(() => Object.values(currentVitalsStatuses).includes('critical'), [currentVitalsStatuses]);
   const currentHasAbnormal = useMemo(() => Object.values(currentVitalsStatuses).includes('abnormal'), [currentVitalsStatuses]);
   const alertSeverity = currentHasCritical ? 'critical' : currentHasAbnormal ? 'abnormal' : 'normal';

   const vitalAlerts = useMemo(() => {
      if (!vitalsData?.current) return [];
      const alerts = [];
      if (currentVitalsStatuses.bp === 'critical') alerts.push('Blood pressure outside safe range');
      if (currentVitalsStatuses.heartRate === 'critical') alerts.push('Heart rate critical');
      if (currentVitalsStatuses.temperature === 'critical') alerts.push('Temperature critical');
      if (currentVitalsStatuses.oxygenSaturation === 'critical') alerts.push('SpO₂ below 90%');
      if (currentVitalsStatuses.respiratoryRate === 'critical') alerts.push('Respiratory rate critical');
      if (currentVitalsStatuses.painLevel === 'critical') alerts.push('Pain level severe');
      if (!alerts.length && currentHasAbnormal) alerts.push('One or more vitals require attention');
      return alerts;
   }, [currentHasAbnormal, currentVitalsStatuses, vitalsData]);

   const vitalsHistory = vitalsData?.history || [];

   const computeTrend = (currentValue, previousValue) => {
      if (currentValue == null || previousValue == null || Number.isNaN(currentValue) || Number.isNaN(previousValue)) return 'flat';
      if (currentValue > previousValue) return 'up';
      if (currentValue < previousValue) return 'down';
      return 'flat';
   };

   const vitalsTrends = useMemo(() => {
      if (vitalsHistory.length < 2) return {};
      const [latest, previous] = vitalsHistory;
      const latestBp = parseBpString(latest.bp);
      const previousBp = parseBpString(previous.bp);
      return {
         bpSystolic: computeTrend(latestBp.systolic, previousBp.systolic),
         heartRate: computeTrend(latest.hr, previous.hr),
         temperature: computeTrend(latest.temp, previous.temp),
         respiratoryRate: computeTrend(latest.rr, previous.rr),
         oxygenSaturation: computeTrend(latest.spo2, previous.spo2),
         painLevel: computeTrend(latest.pain, previous.pain),
      };
   }, [vitalsHistory]);

   const filterHistoryByRange = useMemo(() => {
      if (!vitalsHistory.length) return [];
      const now = new Date();
      let startBoundary = null;
      if (timeRange === '24h') {
         startBoundary = new Date(now.getTime() - 24 * 60 * 60 * 1000);
      } else if (timeRange === '48h') {
         startBoundary = new Date(now.getTime() - 48 * 60 * 60 * 1000);
      } else if (timeRange === '7d') {
         startBoundary = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      } else if (timeRange === 'custom' && customRange.start && customRange.end) {
         startBoundary = new Date(customRange.start);
         const endBoundary = new Date(customRange.end);
         endBoundary.setHours(23, 59, 59, 999);
         return vitalsHistory.filter((entry) => {
            const timestamp = new Date(entry.timestamp);
            return timestamp >= startBoundary && timestamp <= endBoundary;
         });
      }
      if (!startBoundary) return vitalsHistory;
      return vitalsHistory.filter((entry) => new Date(entry.timestamp) >= startBoundary);
   }, [customRange.end, customRange.start, timeRange, vitalsHistory]);

   const chartData = useMemo(() => filterHistoryByRange.map((entry) => {
      const { systolic, diastolic } = parseBpString(entry.bp);
      return {
         timestamp: entry.timestamp,
         label: new Date(entry.timestamp).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }),
         bpSystolic: systolic,
         bpDiastolic: diastolic,
         heartRate: entry.hr,
         temperature: entry.temp,
         respiratoryRate: entry.rr,
         oxygenSaturation: entry.spo2,
      };
   }), [filterHistoryByRange]);

   const chartDomain = useMemo(() => {
      if (!chartData.length) return [0, 200];
      const values = [];
      chartData.forEach((entry) => {
         ['bpSystolic', 'bpDiastolic', 'heartRate', 'temperature', 'respiratoryRate', 'oxygenSaturation'].forEach((key) => {
            if (entry[key] != null && !Number.isNaN(entry[key])) {
               values.push(entry[key]);
            }
         });
      });
      if (!values.length) return [0, 200];
      const min = Math.min(...values);
      const max = Math.max(...values);
      return [Math.max(0, Math.floor(min - 10)), Math.ceil(max + 10)];
   }, [chartData]);

   const filteredVitalsLog = useMemo(() => {
      const normalize = (value) => value.toString().toLowerCase();
      const start = historyRange.start ? new Date(historyRange.start) : null;
      const end = historyRange.end ? new Date(historyRange.end) : null;
      if (start) start.setHours(0, 0, 0, 0);
      if (end) end.setHours(23, 59, 59, 999);

      return vitalsHistory.filter((entry) => {
         const timestamp = new Date(entry.timestamp);
         if (start && timestamp < start) return false;
         if (end && timestamp > end) return false;
         if (!historySearch) return true;
         const query = normalize(historySearch);
         return [entry.bp, entry.hr, entry.temp, entry.rr, entry.spo2, entry.pain, entry.recordedBy]
            .filter(Boolean)
            .some((field) => normalize(field).includes(query));
      });
   }, [historyRange.end, historyRange.start, historySearch, vitalsHistory]);

   const validateVitalsForm = () => {
      const requiredFields = ['systolic', 'diastolic', 'heartRate', 'temperature', 'respiratoryRate', 'oxygenSaturation'];
      return requiredFields.every((field) => vitalsForm[field] !== '' && vitalsForm[field] !== null && !Number.isNaN(Number(vitalsForm[field])));
   };

   const toastColors = {
      success: 'bg-green-600 text-white',
      error: 'bg-red-600 text-white',
      info: 'bg-brand-medium text-white',
   };

   const vitalsPatient = vitalsData?.patient;
   const lastVitalsTimestamp = vitalsData?.current?.timestamp ? formatTimestamp(vitalsData.current.timestamp) : 'Not recorded';
   const alertToneClasses = getStatusClasses(alertSeverity);
   const selectedPainFace = painFaces.find((face) => face.values.includes(Number(vitalsForm.painLevel))) || painFaces[0];
   const currentPainFace = vitalsData?.current
      ? painFaces.find((face) => face.values.includes(Number(vitalsData.current.painLevel))) || painFaces[0]
      : null;

   const handleFormFieldChange = (field, value) => {
      setVitalsForm((prev) => ({ ...prev, [field]: value }));
   };

   const handleTemperatureUnitToggle = (unit) => {
      if (unit === temperatureUnit) return;
      setVitalsForm((prev) => ({
         ...prev,
         temperature: prev.temperature === '' ? '' : Number(convertTemperature(prev.temperature, temperatureUnit, unit).toFixed(1)),
      }));
      setTemperatureUnit(unit);
   };

   const resetVitalsForm = () => {
      const current = overview.vitals?.current;
      if (!current) return;
      setVitalsForm({
         systolic: current.bp?.systolic ?? '',
         diastolic: current.bp?.diastolic ?? '',
         heartRate: current.heartRate ?? '',
         temperature: current.temperature?.value ?? '',
         respiratoryRate: current.respiratoryRate ?? '',
         oxygenSaturation: current.oxygenSaturation ?? '',
         painLevel: current.painLevel ?? 0,
      });
      setTemperatureUnit(current.temperature?.unit || 'F');
      setTemperatureRoute(current.temperature?.route || 'oral');
      setVitalsNotes('');
      setFormError('');
   };

   const triggerToast = (type, message) => {
      setToast({ type, message, id: Date.now() });
   };

   const persistVitals = (notifyPhysician = false) => {
      const timestamp = new Date().toISOString();
      const tempF = temperatureUnit === 'F' ? Number(vitalsForm.temperature) : Number(convertTemperature(vitalsForm.temperature, 'C', 'F').toFixed(1));
      const overallStatus = Object.values(formStatuses).includes('critical')
         ? 'critical'
         : Object.values(formStatuses).includes('abnormal')
            ? 'abnormal'
            : 'normal';

      const newHistoryEntry = {
         timestamp,
         bp: `${Number(vitalsForm.systolic)}/${Number(vitalsForm.diastolic)}`,
         hr: Number(vitalsForm.heartRate),
         temp: Number(tempF.toFixed(1)),
         rr: Number(vitalsForm.respiratoryRate),
         spo2: Number(vitalsForm.oxygenSaturation),
         pain: Number(vitalsForm.painLevel),
         status: overallStatus,
         recordedBy: overview.nurse.name,
         route: temperatureRoute,
         notes: vitalsNotes,
      };

      setOverview((prev) => {
         const updatedHistory = [newHistoryEntry, ...(prev.vitals?.history || [])];
         return {
            ...prev,
            vitals: {
               ...prev.vitals,
               current: {
                  bp: { systolic: Number(vitalsForm.systolic), diastolic: Number(vitalsForm.diastolic) },
                  heartRate: Number(vitalsForm.heartRate),
                  temperature: { value: Number(vitalsForm.temperature), unit: temperatureUnit, route: temperatureRoute },
                  respiratoryRate: Number(vitalsForm.respiratoryRate),
                  oxygenSaturation: Number(vitalsForm.oxygenSaturation),
                  painLevel: Number(vitalsForm.painLevel),
                  timestamp,
                  recordedBy: prev.nurse.name,
               },
               history: updatedHistory,
            },
         };
      });

      setAlertAcknowledged(false);
      setAlertNotified(notifyPhysician);
      setVitalsNotes('');
      setFormError('');
      triggerToast('success', notifyPhysician ? 'Vitals saved and physician notified.' : 'Vitals saved successfully.');
   };

   const executeVitalsSave = (action) => {
      const notifyPhysician = action === 'notify';
      persistVitals(notifyPhysician);
      setShowCriticalModal(false);
      setPendingAction(null);
   };

   const handleVitalsSubmit = (action) => {
      setFormError('');
      if (!validateVitalsForm()) {
         setFormError('Please complete all required fields with valid numeric values.');
         triggerToast('error', 'Please check the vital inputs before saving.');
         return;
      }

      if (formHasCritical) {
         setPendingAction(action);
         setShowCriticalModal(true);
         return;
      }

      executeVitalsSave(action);
   };

   const handleCriticalCancel = () => {
      setShowCriticalModal(false);
      setPendingAction(null);
   };

   const handleCriticalProceed = () => {
      executeVitalsSave(pendingAction || 'save');
   };

   const handleCriticalNotify = () => {
      executeVitalsSave('notify');
   };

   const handleAcknowledgeAlert = () => {
      setAlertAcknowledged(true);
   };

   const handleNotifyPhysician = () => {
      setAlertNotified(true);
      triggerToast('info', 'Physician notification sent (mock).');
   };

   const handleCustomRangeChange = (range) => {
      setCustomRange(range);
   };

   const handleHistoryRangeChange = (range) => {
      setHistoryRange(range);
   };

   const handleToggleVital = (key) => {
      setVisibleVitals((prev) => ({
         ...prev,
         [key]: !prev[key],
      }));
   };

   return (
      <div className="space-y-10" aria-label="Nurse vitals page">
         <header className="bg-white rounded-2xl shadow-soft border border-gray-100 p-6 sm:p-8">
            <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
               <div>
                  <p className="text-sm font-medium text-brand-medium uppercase tracking-wide">{overview.nurse.unit}</p>
                  <h1 className="text-3xl font-bold text-gray-900 mt-2 flex items-center gap-3">
                     <Heart className="w-8 h-8 text-brand-medium" aria-hidden="true" />
                     Patient Vitals
                  </h1>
                  <p className="text-gray-500 mt-3 flex items-center gap-2">
                     <Clock className="w-4 h-4 text-brand-medium" aria-hidden="true" />
                     <span>{formattedDate}</span>
                  </p>
               </div>
               <div className="flex items-center gap-4">
                  {overview.stats.overdueVitals > 0 && (
                     <div className="flex items-center gap-2 bg-red-50 border border-red-200 text-red-600 px-4 py-2 rounded-full text-sm" role="alert">
                        <AlertTriangle className="w-4 h-4" aria-hidden="true" />
                        {overview.stats.overdueVitals} overdue vitals checks
                     </div>
                  )}
                  <Button className="bg-brand-medium hover:bg-brand-deep text-white">
                     Quick Entry
                  </Button>
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

         {/* Critical modal */}
         {showCriticalModal && (
            <div className="fixed inset-0 z-50 bg-black/50 flex items-center justify-center p-4" role="dialog" aria-modal="true">
               <Card className="max-w-md w-full p-6 space-y-6 shadow-xl">
                  <div className="flex items-center gap-3 text-red-600">
                     <AlertTriangle className="w-8 h-8" aria-hidden="true" />
                     <h2 className="text-xl font-bold">Critical Values Detected</h2>
                  </div>
                  <p className="text-gray-700">One or more vitals are in the critical range. Do you want to proceed with saving and notify the physician?</p>
                  <div className="flex flex-wrap gap-3">
                     <Button variant="outline" onClick={handleCriticalCancel}>Cancel</Button>
                     <Button className="bg-amber-500 hover:bg-amber-600 text-white" onClick={handleCriticalProceed}>Save Without Notifying</Button>
                     <Button className="bg-red-600 hover:bg-red-700 text-white" onClick={handleCriticalNotify}>Save &amp; Notify Physician</Button>
                  </div>
               </Card>
            </div>
         )}

         {/* Vitals Schedule */}
         <section aria-labelledby="vitals-schedule" className="space-y-6">
            <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
               <div className="flex items-center gap-3">
                  <Calendar className="w-6 h-6 text-brand-medium" aria-hidden="true" />
                  <h2 id="vitals-schedule" className="text-xl font-bold text-gray-900">Vitals Schedule</h2>
                  <span className="text-sm text-gray-500">Today&apos;s Schedule</span>
               </div>
               <Button variant="link" className="text-brand-medium text-sm font-semibold">
                  View Full Schedule
               </Button>
            </div>

            <div className="overflow-x-auto pb-2">
               <div className="flex min-w-full gap-5">
                  {overview.vitalsSchedule.map((slot) => {
                     const isCurrent = slot.status === 'current';
                     const borderColor =
                        slot.status === 'overdue'
                           ? 'border-red-400'
                           : isCurrent
                              ? 'border-brand-medium'
                              : slot.status === 'completed'
                                 ? 'border-green-400'
                                 : 'border-gray-200';

                     const bgColor =
                        slot.status === 'overdue'
                           ? 'bg-red-50'
                           : isCurrent
                              ? 'bg-brand-light'
                              : slot.status === 'completed'
                                 ? 'bg-green-50'
                                 : 'bg-white';

                     const completion = Math.round((slot.completed / slot.totalPatients) * 100);

                     return (
                        <Card key={slot.time} className={`w-72 flex-shrink-0 border-2 ${borderColor} ${bgColor} p-6 space-y-4`}>
                           <div className="flex items-start justify-between">
                              <div>
                                 <p className="text-xs font-semibold uppercase text-gray-500">Time</p>
                                 <p className="text-2xl font-bold text-gray-900 mt-1">{slot.time}</p>
                              </div>
                              <span className="px-3 py-1 rounded-full text-xs font-semibold bg-white text-brand-medium border border-brand-medium/20">
                                 {slot.totalPatients} patients
                              </span>
                           </div>
                           <div className="space-y-3">
                              {slot.patients.map((patient) => (
                                 <div key={patient.id} className="bg-white/80 border border-white rounded-lg px-3 py-2 flex items-center justify-between text-sm">
                                    <div className="space-y-1">
                                       <p className="font-semibold text-gray-800">{patient.name}</p>
                                       <p className="text-xs text-gray-500">Room {patient.room}</p>
                                    </div>
                                    <div className="flex items-center gap-2 text-xs font-semibold">
                                       {patient.status === 'completed' && <Check className="w-4 h-4 text-green-500" aria-hidden="true" />}
                                       {patient.status === 'pending' && <Clock className="w-4 h-4 text-brand-medium" aria-hidden="true" />}
                                       {patient.status === 'overdue' && <AlertTriangle className="w-4 h-4 text-red-500" aria-hidden="true" />}
                                       <span className={
                                          patient.status === 'completed'
                                             ? 'text-green-600'
                                             : patient.status === 'pending'
                                                ? 'text-brand-medium'
                                                : 'text-red-600'
                                       }>
                                          {patient.status === 'completed' && `Completed at ${patient.completedAt}`}
                                          {patient.status === 'pending' && 'Pending'}
                                          {patient.status === 'overdue' && `Overdue ${patient.overdueBy} min`}
                                       </span>
                                    </div>
                                 </div>
                              ))}
                           </div>
                           <div className="space-y-2">
                              <div className="flex items-center justify-between text-xs text-gray-500">
                                 <span>{slot.completed}/{slot.totalPatients} completed</span>
                                 <span>{completion}%</span>
                              </div>
                              <div className="relative h-2 bg-white/60 rounded-full overflow-hidden">
                                 <div
                                    className={`absolute inset-y-0 left-0 rounded-full ${
                                       slot.status === 'overdue'
                                          ? 'bg-red-400'
                                          : slot.status === 'completed'
                                             ? 'bg-green-500'
                                             : 'bg-brand-medium'
                                    }`}
                                    style={{ width: `${completion}%` }}
                                 />
                              </div>
                           </div>
                           <div className="flex items-center justify-between gap-2">
                              <Button className="flex-1 bg-brand-medium hover:bg-brand-deep text-white text-sm py-2">
                                 Record All
                              </Button>
                              <Button variant="outline" className="flex-1 text-sm py-2 border-brand-medium text-brand-medium">
                                 View
                              </Button>
                           </div>
                        </Card>
                     );
                  })}
               </div>
            </div>
         </section>

         {/* Patient Vitals Section */}
         <section aria-labelledby="patient-vitals" className="space-y-6">
            <VitalsSectionHeader
               patient={vitalsPatient}
               onExportPdf={() => triggerToast('info', 'Export to PDF coming soon. (mock)')}
               onPrint={() => triggerToast('info', 'Print dialog opened (mock).')}
            />

            <VitalsAlertBanner
               severity={alertSeverity}
               toneClasses={alertToneClasses}
               alerts={vitalAlerts}
               acknowledged={alertAcknowledged}
               notified={alertNotified}
               onAcknowledge={handleAcknowledgeAlert}
               onNotify={handleNotifyPhysician}
            />

            {/* Vitals Entry + Shift Assessment / Assigned Patients */}
            <div className="grid grid-cols-1 xl:grid-cols-[2fr_1fr] gap-6">
               <Card className="p-6 border border-gray-100 shadow-soft">
                  <div className="flex items-center gap-3 mb-6">
                     <Users className="w-5 h-5 text-brand-medium" aria-hidden="true" />
                     <h3 className="text-lg font-bold text-gray-900">Vitals Entry &amp; Shift Assessment</h3>
                  </div>
                  <VitalsEntryForm
                     form={vitalsForm}
                     formStatuses={formStatuses}
                     getStatusClasses={getStatusClasses}
                     getInputStatusClasses={getInputStatusClasses}
                     normalText={vitalsNormalText}
                     temperatureUnit={temperatureUnit}
                     temperatureRoute={temperatureRoute}
                     onUnitToggle={handleTemperatureUnitToggle}
                     onRouteSelect={setTemperatureRoute}
                     onFieldChange={handleFormFieldChange}
                     selectedPainFace={selectedPainFace}
                     notes={vitalsNotes}
                     onNotesChange={setVitalsNotes}
                     formError={formError}
                     onSave={() => handleVitalsSubmit('save')}
                     onNotify={() => handleVitalsSubmit('notify')}
                     onCancel={resetVitalsForm}
                     lastTimestamp={lastVitalsTimestamp}
                     recordedBy={vitalsData?.current?.recordedBy || overview.nurse.name}
                     unit={overview.nurse.unit}
                  />
               </Card>

               <AssignedPatientsPanel
                  totalCount={overview.assignedPatients.length}
                  viewMode={viewMode}
                  onViewModeChange={setViewMode}
                  sortBy={sortBy}
                  onSortChange={setSortBy}
                  sortOptions={sortOptions}
                  filterPresets={patientFilterOptions}
                  activeFilter={activeFilter}
                  onFilterChange={setActiveFilter}
                  filteredPatients={filteredPatients}
                  acuityStyles={acuityStyles}
                  vitalsStatusMap={vitalsStatusMap}
                  medicationStatusMap={medicationStatusMap}
               />
            </div>

            {/* Current Vitals Overview */}
            <VitalsOverviewCard
               alertSeverity={alertSeverity}
               vitalsData={vitalsData}
               statuses={currentVitalsStatuses}
               trends={vitalsTrends}
               normalText={vitalsNormalText}
               currentPainFace={currentPainFace}
               getStatusClasses={getStatusClasses}
               trendIcon={trendIcon}
               lastTimestamp={lastVitalsTimestamp}
            />

            {/* Vitals Trend Chart */}
            <VitalsTrendCard
               timeRange={timeRange}
               onTimeRangeChange={setTimeRange}
               customRange={customRange}
               onCustomRangeChange={handleCustomRangeChange}
               visibleVitals={visibleVitals}
               onToggleVital={handleToggleVital}
               chartData={chartData}
               chartDomain={chartDomain}
               vitalLimits={VITAL_LIMITS}
               onExport={() => triggerToast('info', 'Trend export to PDF (mock).')}
            />

            {/* Time-Stamped Vitals Log */}
            <VitalsLogTable
               historySearch={historySearch}
               onSearch={setHistorySearch}
               historyRange={historyRange}
               onHistoryRangeChange={handleHistoryRangeChange}
               filteredVitalsLog={filteredVitalsLog}
               formatTimestamp={formatTimestamp}
               parseBpString={parseBpString}
               classifyBp={classifyBp}
               classifyValue={classifyValue}
               getStatusClasses={getStatusClasses}
               defaultRecorder={overview.nurse.name}
               onPrint={() => triggerToast('info', 'Print log (mock).')}
               onExport={() => triggerToast('info', 'Export CSV (mock).')}
            />
         </section>
      </div>
   );
};

export default NurseVitals;
