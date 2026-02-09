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
   Frown,
   Heart,
   Info,
   Meh,
   MessageSquare,
   Minus,
   Pill,
   Plus,
   Smile,
   Trash2,
   TrendingDown,
   TrendingUp,
   Users,
   X,
} from 'lucide-react';

import Card from '../../components/common/Card';
import Button from '../../components/common/Button';
import Badge from '../../components/common/Badge';
import { mockNurseOverview } from '../../mocks/nurseOverview';
import VitalsSectionHeader from './components/VitalsSectionHeader';
import VitalsAlertBanner from './components/VitalsAlertBanner';
import VitalsEntryForm from './components/VitalsEntryForm';
import VitalsOverviewCard from './components/VitalsOverviewCard';
import VitalsTrendCard from './components/VitalsTrendCard';
import VitalsLogTable from './components/VitalsLogTable';
import AssignedPatientsPanel from './components/AssignedPatientsPanel';

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
   'due-soon': { icon: Pill, text: 'Due soon', classes: 'text-amber-500' },
   overdue: { icon: Pill, text: 'Overdue', classes: 'text-red-500' },
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

const quickStatConfig = (stats) => [
   {
      id: 'assigned',
      label: 'patients assigned today',
      value: stats.assignedPatients,
      icon: Users,
      border: 'border-brand-medium',
      badge: null,
      onClick: () => {},
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
      onClick: () => {},
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
      onClick: () => {},
      description: null,
   },
   {
      id: 'tasks',
      label: 'tasks remaining',
      value: stats.pendingTasks,
      icon: CheckSquare,
      border: 'border-green-500',
      badge: { text: `${stats.highPriorityTasks} high priority`, classes: 'text-orange-500 font-medium' },
      onClick: () => {},
      description: null,
   },
];

const NurseDashboard = () => {
   const [overview, setOverview] = useState(mockNurseOverview);
   const [currentTime, setCurrentTime] = useState(new Date());
   const [viewMode, setViewMode] = useState('grid');
   const [activeFilter, setActiveFilter] = useState('all');
   const [sortBy, setSortBy] = useState('room');
   const [handoverTab, setHandoverTab] = useState('from');
   const [expandedCompleted, setExpandedCompleted] = useState(false);
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
   // eslint-disable-next-line no-unused-vars
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
      const refreshInterval = setInterval(() => {
         // TODO integrate with fetchNurseOverview API
         setOverview((prev) => ({ ...prev }));
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

   const overdueTasks = overview.tasks.filter((task) => task.status === 'overdue');
   const completedTasks = overview.tasks.filter((task) => task.completed);
   const visibleTasks = overview.tasks.filter((task) => !task.completed).sort((a, b) => {
      const priorityOrder = ['critical', 'high', 'medium', 'low'];
      return priorityOrder.indexOf(a.priority) - priorityOrder.indexOf(b.priority);
   });

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
   // eslint-disable-next-line no-unused-vars
   const formHasAbnormal = useMemo(() => Object.values(formStatuses).some((status) => status === 'abnormal'), [formStatuses]);

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

   // eslint-disable-next-line react-hooks/exhaustive-deps
   const vitalsHistory = useMemo(() => vitalsData?.history || [], [vitalsData?.history]);

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

   // eslint-disable-next-line no-unused-vars
   const handleCriticalCancel = () => {
      setShowCriticalModal(false);
      setPendingAction(null);
   };

   // eslint-disable-next-line no-unused-vars
   const handleCriticalProceed = () => {
      executeVitalsSave(pendingAction || 'save');
   };

   // eslint-disable-next-line no-unused-vars
   const handleCriticalNotify = () => {
      executeVitalsSave('notify');
   };

   const handleAcknowledgeAlert = () => {
      setAlertAcknowledged(true);
   };

   const handleNotifyPhysician = () => {
      setAlertNotified(true);
      triggerToast('info', 'Physician notification sent (mock).');
      // TODO integrate with notify-physician API
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

   const nurseName = overview.nurse.name;
   const shiftStyles = shiftTypeStyles[overview.shift.type] || shiftTypeStyles.day;

   return (
      <div className="space-y-10" aria-label="Nurse dashboard overview">
         <header className="bg-white dark:bg-slate-800 rounded-2xl shadow-soft border border-gray-100 dark:border-slate-700 overflow-hidden">
            <div className="p-6 sm:p-8 flex flex-col lg:flex-row gap-6 lg:gap-8 lg:items-center justify-between">
               <div>
                  <p className="text-sm font-medium text-brand-medium uppercase tracking-wide">{overview.nurse.unit}</p>
                  <h1 className="text-3xl font-bold text-gray-900 dark:text-slate-100 mt-2">
                     {`${greeting}, Nurse ${nurseName.split(' ')[0]}`}
                  </h1>
                  <p className="text-gray-500 dark:text-slate-400 mt-3 flex items-center gap-2" aria-live="polite">
                     <Clock className="w-4 h-4 text-brand-medium" aria-hidden="true" />
                     <span>{formattedDate}</span>
                  </p>
               </div>

               <div className="flex flex-col md:flex-row gap-4 w-full lg:w-auto">
                  <Card className="p-4 md:p-5 border border-gray-100 dark:border-slate-700 shadow-soft flex-1 dark:bg-slate-800">
                     <div className="flex items-center justify-between">
                        <div>
                           <span className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-semibold ${shiftStyles.classes}`}>
                              {shiftStyles.label}
                           </span>
                           <p className="text-base font-semibold text-gray-900 dark:text-slate-100 mt-3">{overview.shift.startTime} - {overview.shift.endTime}</p>
                        </div>
                        <Calendar className="w-10 h-10 text-brand-medium bg-brand-light rounded-xl p-2" aria-hidden="true" />
                     </div>
                     <div className="mt-6 space-y-2" aria-hidden="true">
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
                     className="min-w-[200px] md:min-w-[220px] rounded-2xl border-2 border-red-200 bg-red-50 text-red-600 font-semibold shadow-soft hover:shadow-md hover:bg-red-100 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-400 transition-all duration-200 flex items-center justify-center gap-2 px-4 py-4"
                     aria-label="Call code team"
                     onClick={() => alert('Escalation protocol initiated. (placeholder)')}
                  >
                     <AlertTriangle className="w-5 h-5" aria-hidden="true" />
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

         <section aria-labelledby="quick-stats" className="space-y-4">
            <div className="flex items-center justify-between">
               <h2 id="quick-stats" className="text-xl font-bold text-gray-900 dark:text-slate-100">Shift Snapshot</h2>
               <Button variant="link" className="text-brand-medium text-sm font-semibold" aria-label="Refresh dashboard snapshot">
                  Refresh Data
               </Button>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-5">
               {stats.map((stat) => {
                  const Icon = stat.icon;
                  return (
                     <Card
                        key={stat.id}
                        className={`p-6 border-l-4 ${stat.border} shadow-soft hover:shadow-lg transition-shadow cursor-pointer focus-within:ring-2 focus-within:ring-brand-medium focus-within:ring-offset-2 dark:bg-slate-800`}
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
                              <p className="text-sm text-gray-500 dark:text-slate-400 font-medium">{stat.label}</p>
                              <p className="text-4xl font-bold text-gray-900 dark:text-slate-100 mt-2">{stat.value}</p>
                              {stat.badge && <p className={`text-sm mt-3 ${stat.badge.classes}`}>{stat.badge.text}</p>}
                           </div>
                           <div className="w-12 h-12 bg-brand-light rounded-xl flex items-center justify-center text-brand-medium">
                              <Icon className="w-6 h-6" aria-hidden="true" />
                           </div>
                        </div>
                     </Card>
                  );
               })}
            </div>
         </section>

         <section aria-labelledby="vitals-schedule" className="space-y-6">
            <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
               <div className="flex items-center gap-3">
                  <Heart className="w-6 h-6 text-brand-medium" aria-hidden="true" />
                  <h2 id="vitals-schedule" className="text-xl font-bold text-gray-900 dark:text-slate-100">Vitals Schedule</h2>
                  <span className="text-sm text-gray-500 dark:text-slate-400">Today&apos;s Schedule</span>
               </div>
               <div className="flex items-center gap-3">
                  {overview.stats.overdueVitals > 0 && (
                     <div className="flex items-center gap-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-red-600 dark:text-red-400 px-4 py-2 rounded-full text-sm" role="alert">
                        <AlertTriangle className="w-4 h-4" aria-hidden="true" />
                        {overview.stats.overdueVitals} overdue vitals checks
                     </div>
                  )}
                  <Button variant="link" className="text-brand-medium text-sm font-semibold">
                     View Full Schedule
                  </Button>
               </div>
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
                        <Card key={slot.time} className={`w-72 flex-shrink-0 border-2 ${borderColor} ${bgColor} dark:bg-slate-800 p-6 space-y-4`}>
                           <div className="flex items-start justify-between">
                              <div>
                                 <p className="text-xs font-semibold uppercase text-gray-500 dark:text-slate-400">Time</p>
                                 <p className="text-2xl font-bold text-gray-900 dark:text-slate-100 mt-1">{slot.time}</p>
                              </div>
                              <span className="px-3 py-1 rounded-full text-xs font-semibold bg-white dark:bg-slate-700 text-brand-medium border border-brand-medium/20">
                                 {slot.totalPatients} patients
                              </span>
                           </div>
                           <div className="space-y-3">
                              {slot.patients.map((patient) => (
                                 <div key={patient.id} className="bg-white/80 dark:bg-slate-700/80 border border-white dark:border-slate-600 rounded-lg px-3 py-2 flex items-center justify-between text-sm">
                                    <div className="space-y-1">
                                       <p className="font-semibold text-gray-800 dark:text-slate-100">{patient.name}</p>
                                       <p className="text-xs text-gray-500 dark:text-slate-400">Room {patient.room}</p>
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
                              <div className="flex items-center justify-between text-xs text-gray-500 dark:text-slate-400">
                                 <span>{slot.completed}/{slot.totalPatients} completed</span>
                                 <span>{completion}%</span>
                              </div>
                              <div className="relative h-2 bg-white/60 dark:bg-slate-600/60 rounded-full overflow-hidden">
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

            <div className="grid grid-cols-1 xl:grid-cols-[2fr_1fr] gap-6">
               <Card className="p-6 border border-gray-100 dark:border-slate-700 shadow-soft dark:bg-slate-800">
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

         <section aria-labelledby="tasks-reminders" className="space-y-6">
            <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
               <div className="flex items-center gap-3">
                  <ClipboardList className="w-6 h-6 text-brand-medium" aria-hidden="true" />
                  <h2 id="tasks-reminders" className="text-xl font-bold text-gray-900 dark:text-slate-100">Tasks &amp; Reminders</h2>
                  <span className="text-sm text-gray-500 dark:text-slate-400">{overview.stats.pendingTasks} active</span>
               </div>
               <div className="flex items-center gap-3">
                  <div className="flex gap-2 text-sm text-gray-500 dark:text-slate-400">
                     <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-red-500" /> Critical</span>
                     <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-orange-500" /> High</span>
                     <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-blue-500" /> Medium</span>
                     <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-gray-400" /> Low</span>
                  </div>
                  <Button className="flex items-center gap-2 text-sm font-semibold" onClick={() => alert('Add task modal (placeholder)')}>
                     <Plus className="w-4 h-4" />
                     Add Task
                  </Button>
               </div>
            </div>

            {overdueTasks.length > 0 && (
               <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-400 px-4 py-3 rounded-xl flex items-center justify-between">
                  <div className="flex items-center gap-3">
                     <AlertTriangle className="w-5 h-5" aria-hidden="true" />
                     <p className="text-sm font-semibold">{overdueTasks.length} overdue task(s) need immediate attention</p>
                  </div>
                  <Button variant="outline" className="border-red-200 text-red-600 dark:border-red-700 dark:text-red-400" onClick={() => setActiveFilter('needs-attention')}>
                     View Patients
                  </Button>
               </div>
            )}

            <div className="space-y-4">
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
                     <Card key={task.id} className={`p-4 md:p-5 shadow-soft border ${isOverdue ? 'border-red-200 dark:border-red-800 bg-red-50/40 dark:bg-red-900/10' : 'border-gray-100 dark:border-slate-700'} dark:bg-slate-800`}>
                        <div className="flex flex-col md:flex-row md:items-center gap-4 md:gap-6">
                           <label className="flex items-center gap-3 cursor-pointer select-none">
                              <input
                                 type="checkbox"
                                 className="form-checkbox w-5 h-5 rounded border-gray-300 dark:border-slate-600 text-brand-medium focus:ring-brand-medium dark:bg-slate-700"
                                 checked={task.completed}
                                 onChange={() => handleTaskToggle(task.id)}
                                 aria-label={`Mark task ${task.title} as complete`}
                              />
                              <span className={`w-2.5 h-2.5 rounded-full ${priority.dot}`} aria-hidden="true" />
                           </label>

                           <div className="flex-1 space-y-2">
                              <div className="flex flex-wrap items-center gap-2">
                                 <h3 className="font-semibold text-gray-900 dark:text-slate-100">{task.title}</h3>
                                 <Badge type={isOverdue ? 'red' : 'blue'}>{categoryLabel}</Badge>
                                 {isOverdue && <span className="text-xs font-semibold uppercase text-red-600 dark:text-red-400 bg-red-100 dark:bg-red-900/30 px-2 py-1 rounded-full">Overdue</span>}
                              </div>
                              {task.patient && (
                                 <p className="text-sm text-gray-600 dark:text-slate-400">for {task.patient.name}, Room {task.patient.room}</p>
                              )}
                              <p className={`text-xs font-semibold ${statusColor}`}>
                                 Due: {new Date(task.dueTime).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}
                                 {task.status === 'overdue' && task.overdueBy ? ` • Overdue ${task.overdueBy} min` : ''}
                              </p>
                           </div>

                           <div className="flex items-center gap-3 self-start">
                              <button type="button" className="p-2 rounded-full hover:bg-gray-100 dark:hover:bg-slate-700 text-gray-500 dark:text-slate-400" aria-label="View task info">
                                 <Info className="w-4 h-4" />
                              </button>
                              <button type="button" className="p-2 rounded-full hover:bg-gray-100 dark:hover:bg-slate-700 text-gray-500 dark:text-slate-400" aria-label="Edit task">
                                 <Edit3 className="w-4 h-4" />
                              </button>
                              <button type="button" className="p-2 rounded-full hover:bg-gray-100 dark:hover:bg-slate-700 text-gray-500 dark:text-slate-400" aria-label="Delete task">
                                 <Trash2 className="w-4 h-4" />
                              </button>
                           </div>
                        </div>
                     </Card>
                  );
               })}

               {visibleTasks.length > 6 && (
                  <Button variant="outline" className="w-full text-sm" onClick={() => alert('Navigate to full task list (placeholder)')}>
                     View All Tasks
                  </Button>
               )}
            </div>

            <div className="bg-white dark:bg-slate-800 border border-gray-100 dark:border-slate-700 rounded-2xl p-6 shadow-soft">
               <h3 className="text-sm font-semibold text-gray-700 dark:text-slate-300 uppercase tracking-wide">Task Categories</h3>
               <dl className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-4 text-sm text-gray-600 dark:text-slate-400">
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

               <div className="mt-6">
                  <button
                     type="button"
                     className="text-sm text-brand-medium font-semibold flex items-center gap-2"
                     onClick={() => setExpandedCompleted((prev) => !prev)}
                     aria-expanded={expandedCompleted}
                  >
                     {expandedCompleted ? 'Hide Completed (12)' : 'Show Completed (12)'}
                     <ChevronRight className={`w-4 h-4 transition-transform ${expandedCompleted ? 'rotate-90' : ''}`} aria-hidden="true" />
                  </button>
                  {expandedCompleted && (
                     <ul className="mt-3 space-y-2 text-sm text-gray-500 dark:text-slate-400">
                        {(completedTasks.length > 0 ? completedTasks : [{ id: 'stub', title: 'Example completed task' }]).map((task) => (
                           <li key={task.id} className="flex items-center gap-2">
                              <Check className="w-4 h-4 text-green-500" aria-hidden="true" />
                              <span className="line-through">{task.title || 'Task completed'}</span>
                           </li>
                        ))}
                     </ul>
                  )}
               </div>
            </div>
         </section>

         <section aria-labelledby="shift-handover" className="space-y-6">
            <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
               <div className="flex items-center gap-3">
                  <MessageSquare className="w-6 h-6 text-brand-medium" aria-hidden="true" />
                  <h2 id="shift-handover" className="text-xl font-bold text-gray-900 dark:text-slate-100">Shift Handover</h2>
               </div>
               <div className="inline-flex rounded-full border border-gray-200 dark:border-slate-600 overflow-hidden" role="tablist">
                  <button
                     type="button"
                     role="tab"
                     className={`px-4 py-2 text-sm font-semibold transition ${handoverTab === 'from' ? 'bg-brand-medium text-white' : 'text-gray-600 dark:text-slate-400 hover:bg-gray-50 dark:hover:bg-slate-700'}`}
                     onClick={() => setHandoverTab('from')}
                     aria-selected={handoverTab === 'from'}
                  >
                     From Previous Shift
                  </button>
                  <button
                     type="button"
                     role="tab"
                     className={`px-4 py-2 text-sm font-semibold transition ${handoverTab === 'to' ? 'bg-brand-medium text-white' : 'text-gray-600 dark:text-slate-400 hover:bg-gray-50 dark:hover:bg-slate-700'}`}
                     onClick={() => setHandoverTab('to')}
                     aria-selected={handoverTab === 'to'}
                  >
                     For Next Shift
                  </button>
               </div>
            </div>

            {handoverTab === 'from' ? (
               <Card className="p-6 space-y-6 border border-gray-100 dark:border-slate-700 shadow-soft dark:bg-slate-800" role="tabpanel">
                  <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
                     <div>
                        <p className="text-sm text-gray-500 dark:text-slate-400">Last updated: Feb 9, 7:00 AM by Nurse Sarah Chen</p>
                        <p className="text-sm font-semibold text-brand-medium">3 unread notes</p>
                     </div>
                     <div className="flex gap-3">
                        <Button variant="outline" className="border-brand-medium text-brand-medium" onClick={handleMarkAllNotesRead}>
                           Mark All as Read
                        </Button>
                        <Button className="bg-brand-medium text-white">View History</Button>
                     </div>
                  </div>

                  <div className="space-y-4">
                     {overview.handoverNotes.fromPreviousShift.map((note) => {
                        const isUrgent = note.priority === 'urgent';
                        const isRead = note.read;

                        return (
                           <div
                              key={note.id}
                              className={`rounded-xl border ${isUrgent ? 'border-red-200 dark:border-red-800 bg-red-50/50 dark:bg-red-900/20' : 'border-blue-100 dark:border-blue-800 bg-blue-50/40 dark:bg-blue-900/20'} p-4 md:p-5 flex flex-col gap-4 ${isRead ? 'opacity-75' : ''}`}
                           >
                              <div className="flex flex-col md:flex-row md:items-start md:justify-between gap-3">
                                 <div className="space-y-1">
                                    <div className="flex items-center gap-2 text-xs uppercase font-semibold tracking-wide">
                                       <span className={`px-2.5 py-1 rounded-full ${isUrgent ? 'bg-red-500 text-white' : 'bg-blue-500 text-white'}`}>
                                          {isUrgent ? 'Urgent' : 'Info'}
                                       </span>
                                       <span className="px-2.5 py-1 rounded-full bg-white/80 dark:bg-slate-700 text-gray-700 dark:text-slate-300">
                                          {note.type === 'general' ? 'General' : 'Patient Specific'}
                                       </span>
                                    </div>
                                    {note.patient && (
                                       <p className="text-sm font-semibold text-gray-800 dark:text-slate-200">
                                          {note.patient.name}, Room {note.patient.room}
                                       </p>
                                    )}
                                 </div>
                                 <div className="text-xs text-gray-500 dark:text-slate-400 text-right">
                                    <p>{new Date(note.timestamp).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}</p>
                                    <p>{note.author}</p>
                                 </div>
                              </div>
                              <p className="text-sm text-gray-700 dark:text-slate-300 leading-relaxed">{note.content}</p>
                              <label className="flex items-center gap-2 text-sm font-medium text-gray-600 dark:text-slate-400 cursor-pointer">
                                 <input
                                    type="checkbox"
                                    checked={note.read}
                                    onChange={() => handleMarkNoteRead(note.id)}
                                    className="form-checkbox w-4 h-4 text-brand-medium dark:bg-slate-700 dark:border-slate-600"
                                 />
                                 Mark as read
                              </label>
                           </div>
                        );
                     })}
                  </div>

                  {overview.handoverNotes.fromPreviousShift.length === 0 && (
                     <div className="text-center text-gray-500 dark:text-slate-400 py-10">
                        <CheckSquare className="w-12 h-12 mx-auto text-gray-300 dark:text-slate-600 mb-3" aria-hidden="true" />
                        No handover notes from previous shift
                     </div>
                  )}
               </Card>
            ) : (
               <Card className="p-6 space-y-6 border border-gray-100 dark:border-slate-700 shadow-soft dark:bg-slate-800" role="tabpanel">
                  <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
                     <div>
                        <h3 className="text-lg font-bold text-gray-900 dark:text-slate-100">Notes for Next Shift</h3>
                        <p className="text-sm text-gray-500 dark:text-slate-400">Auto-save every 30 seconds</p>
                        {overview.handoverNotes.forNextShift.lastSaved && (
                           <p className="text-xs text-gray-400 dark:text-slate-500 mt-1">
                              Last saved: {new Date(overview.handoverNotes.forNextShift.lastSaved).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}
                           </p>
                        )}
                     </div>
                     <div className="flex gap-3">
                        <Button variant="outline" className="border-brand-medium text-brand-medium" onClick={handleSaveHandover}>
                           Save Draft
                        </Button>
                        <Button className="bg-brand-medium text-white" disabled>
                           Submit Handover
                        </Button>
                     </div>
                  </div>

                  <div className="space-y-4">
                     <div>
                        <label htmlFor="general-notes" className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-2">
                           General Notes
                        </label>
                        <textarea
                           id="general-notes"
                           rows={4}
                           className="w-full rounded-xl border border-gray-200 dark:border-slate-600 p-3 text-sm focus:outline-none focus:ring-2 focus:ring-brand-medium bg-white dark:bg-slate-700 text-gray-900 dark:text-slate-100 dark:placeholder-slate-400"
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

                     <div className="space-y-3">
                        <div className="flex items-center justify-between">
                           <h3 className="text-sm font-semibold text-gray-700 dark:text-slate-300 uppercase tracking-wide">Patient-Specific Notes</h3>
                           <Button variant="outline" className="text-sm flex items-center gap-2" onClick={handleAddPatientNote}>
                              <Plus className="w-4 h-4" />
                              Add Patient Note
                           </Button>
                        </div>

                        {overview.handoverNotes.forNextShift.patientNotes.length === 0 && (
                           <div className="border border-dashed border-gray-300 dark:border-slate-600 rounded-xl p-6 text-center text-sm text-gray-500 dark:text-slate-400">
                              <MessageSquare className="w-6 h-6 mx-auto text-gray-300 dark:text-slate-600 mb-2" aria-hidden="true" />
                              No patient-specific notes yet.
                           </div>
                        )}

                        <div className="space-y-4">
                           {overview.handoverNotes.forNextShift.patientNotes.map((note) => (
                              <div key={note.id} className="border border-gray-200 dark:border-slate-600 rounded-xl p-4 space-y-3 dark:bg-slate-700/50">
                                 <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
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