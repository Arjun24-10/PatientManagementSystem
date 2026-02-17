import React from 'react';
import {
    Users,
    LayoutGrid,
    List,
    Filter,
    ChevronDown,
    AlertTriangle,
    Droplet,
    Ban,
    Shield,
    Calendar,
    Edit3,
} from 'lucide-react';
import Card from '../../../components/common/Card';
import Badge from '../../../components/common/Badge';
import Button from '../../../components/common/Button';

const AssignedPatientsPanel = ({
    totalCount,
    viewMode,
    onViewModeChange,
    sortBy,
    onSortChange,
    sortOptions,
    filterPresets,
    activeFilter,
    onFilterChange,
    filteredPatients,
    acuityStyles,
    vitalsStatusMap,
    medicationStatusMap,
}) => (
    <Card className="p-3 space-y-3 border border-gray-100 dark:border-slate-700 shadow-soft h-full dark:bg-slate-800">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-2">
            <div className="flex items-center gap-2">
                <Users className="w-5 h-5 text-brand-medium" aria-hidden="true" />
                <div>
                    <h3 className="text-sm font-bold text-gray-900 dark:text-slate-100">My Assigned Patients</h3>
                    <p className="text-xs text-gray-500 dark:text-slate-400">Total {totalCount}</p>
                </div>
            </div>
            <div className="flex flex-wrap items-center gap-2">
                <div className="inline-flex rounded-full border border-gray-200 dark:border-slate-600 overflow-hidden" role="group" aria-label="Toggle patient view">
                    <button
                        type="button"
                        className={`px-2.5 py-1.5 text-xs font-medium flex items-center gap-1.5 transition ${viewMode === 'grid' ? 'bg-brand-medium text-white' : 'text-gray-600 dark:text-slate-300 bg-white dark:bg-slate-700 hover:bg-gray-50 dark:hover:bg-slate-600'}`}
                        onClick={() => onViewModeChange('grid')}
                        aria-pressed={viewMode === 'grid'}
                    >
                        <LayoutGrid className="w-3.5 h-3.5" />
                        Grid
                    </button>
                    <button
                        type="button"
                        className={`px-2.5 py-1.5 text-xs font-medium flex items-center gap-1.5 transition ${viewMode === 'list' ? 'bg-brand-medium text-white' : 'text-gray-600 dark:text-slate-300 bg-white dark:bg-slate-700 hover:bg-gray-50 dark:hover:bg-slate-600'}`}
                        onClick={() => onViewModeChange('list')}
                        aria-pressed={viewMode === 'list'}
                    >
                        <List className="w-3.5 h-3.5" />
                        List
                    </button>
                </div>

                <div className="relative">
                    <select
                        value={sortBy}
                        onChange={(event) => onSortChange(event.target.value)}
                        className="appearance-none bg-white dark:bg-slate-700 border border-gray-200 dark:border-slate-600 rounded-full px-3 py-1.5 text-xs font-medium text-gray-600 dark:text-slate-300 pr-8 focus:outline-none focus:ring-2 focus:ring-brand-medium"
                        aria-label="Sort patients"
                    >
                        {sortOptions.map((option) => (
                            <option key={option.id} value={option.id}>Sort by: {option.label}</option>
                        ))}
                    </select>
                    <ChevronDown className="w-3.5 h-3.5 text-gray-400 dark:text-slate-500 absolute right-2.5 top-2.5 pointer-events-none" aria-hidden="true" />
                </div>

                <div className="inline-flex items-center gap-1.5 text-xs text-gray-500 dark:text-slate-400">
                    <Filter className="w-3.5 h-3.5" aria-hidden="true" />
                    Filters
                </div>
            </div>
        </div>

        <div className="flex flex-wrap gap-2" role="radiogroup" aria-label="Patient status filters">
            {filterPresets.map((filter) => (
                <button
                    key={filter.id}
                    type="button"
                    className={`px-3 py-1.5 rounded-full text-xs font-medium border transition ${activeFilter === filter.id ? 'bg-brand-medium text-white border-brand-medium' : 'border-gray-200 dark:border-slate-600 text-gray-600 dark:text-slate-300 hover:bg-gray-50 dark:hover:bg-slate-700'}`}
                    onClick={() => onFilterChange(filter.id)}
                    aria-pressed={activeFilter === filter.id}
                >
                    {filter.label}
                </button>
            ))}
        </div>

        {filteredPatients.length === 0 ? (
            <Card className="p-6 text-center border border-dashed border-gray-200 dark:border-slate-600 dark:bg-slate-800">
                <Users className="w-8 h-8 text-gray-300 dark:text-slate-600 mx-auto mb-2" aria-hidden="true" />
                <h4 className="text-sm font-semibold text-gray-900 dark:text-slate-100">No patients assigned for this shift</h4>
                <p className="text-xs text-gray-500 dark:text-slate-400 mt-1">Please refresh or check with charge nurse.</p>
                <Button className="mt-3" variant="outline">Refresh</Button>
            </Card>
        ) : (
            <div className={viewMode === 'grid' ? 'grid grid-cols-1 sm:grid-cols-2 gap-2' : 'space-y-2'}>
                {filteredPatients.map((patient) => {
                    const acuity = acuityStyles[patient.acuityLevel] || acuityStyles.stable;
                    const vitalsStatus = vitalsStatusMap[patient.vitalsStatus] || vitalsStatusMap.due;
                    const medicationStatus = medicationStatusMap[patient.medicationStatus] || medicationStatusMap['due-soon'];
                    const VitalsIcon = vitalsStatus.icon;
                    const MedicationIcon = medicationStatus.icon;
                    const showAllergy = patient.allergies && patient.allergies.length > 0;

                    return (
                        <Card
                            key={patient.id}
                            className={`h-full p-3 shadow-soft hover:shadow-lg transition-shadow duration-300 border border-gray-100 dark:border-slate-700 dark:bg-slate-800 ${acuity.border}`}
                        >
                            <div className="flex flex-col h-full gap-2">
                                <div className="flex justify-between items-start gap-2">
                                    <div>
                                        <h4 className="text-sm font-semibold text-gray-900 dark:text-slate-100 tracking-tight">{patient.name}</h4>
                                        <div className="mt-1 flex items-center gap-1.5 text-xs text-gray-500">
                                            <Badge type="blue" className="!bg-brand-light !text-brand-medium">
                                                MRN: {patient.mrn}
                                            </Badge>
                                        </div>
                                    </div>
                                    <div className="text-right text-xs text-gray-500 dark:text-slate-400 space-y-0.5">
                                        <div className="flex items-center gap-1.5 justify-end">
                                            <Users className="w-3.5 h-3.5 text-gray-400 dark:text-slate-500" aria-hidden="true" />
                                            <span>Age {patient.age}, {patient.gender}</span>
                                        </div>
                                        <div className="flex items-center gap-1.5 justify-end">
                                            <Calendar className="w-3.5 h-3.5 text-gray-400 dark:text-slate-500" aria-hidden="true" />
                                            <span>Admitted: {new Date(patient.admissionDate).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}</span>
                                        </div>
                                    </div>
                                </div>

                                <div className="flex flex-wrap items-center gap-1.5 text-xs">
                                    <span className="px-2 py-0.5 rounded-full font-semibold text-[10px] uppercase tracking-wide bg-gray-100 dark:bg-slate-700 text-gray-700 dark:text-slate-300 flex items-center gap-1.5">
                                        Room {patient.room} · Bed {patient.bed}
                                    </span>
                                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-wide ${acuity.badge}`}>{acuity.label}</span>
                                </div>

                                <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5 text-xs font-medium">
                                    <div className={`flex items-center gap-1.5 rounded border border-gray-100 dark:border-slate-600 px-2 py-1.5 ${vitalsStatus.classes}`}>
                                        <VitalsIcon className="w-3.5 h-3.5" aria-hidden="true" />
                                        {patient.vitalsStatus === 'overdue' && patient.vitalsOverdueBy ? `Overdue ${patient.vitalsOverdueBy} min` : vitalsStatus.text}
                                    </div>
                                    <div className={`flex items-center gap-1.5 rounded border border-gray-100 dark:border-slate-600 px-2 py-1.5 ${medicationStatus.classes}`}>
                                        <MedicationIcon className="w-3.5 h-3.5" aria-hidden="true" />
                                        {patient.medicationStatus === 'due-soon' && patient.medicationsDue ? `${patient.medicationsDue} due soon` : medicationStatus.text}
                                    </div>
                                </div>

                                {patient.specialAlerts.length > 0 && (
                                    <div className="flex flex-wrap gap-1.5 text-[10px] text-gray-600 dark:text-slate-400">
                                        {patient.specialAlerts.includes('fall-risk') && (
                                            <span className="inline-flex items-center gap-0.5 px-2 py-0.5 rounded-full bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400" title="Fall risk">
                                                <AlertTriangle className="w-3 h-3" aria-hidden="true" />
                                                Fall risk
                                            </span>
                                        )}
                                        {patient.specialAlerts.includes('diabetic') && (
                                            <span className="inline-flex items-center gap-0.5 px-2 py-0.5 rounded-full bg-amber-100 dark:bg-amber-900/30 text-amber-600 dark:text-amber-400" title="Diabetic">
                                                <Droplet className="w-3 h-3" aria-hidden="true" />
                                                Diabetic
                                            </span>
                                        )}
                                        {patient.specialAlerts.includes('npo') && (
                                            <span className="inline-flex items-center gap-0.5 px-2 py-0.5 rounded-full bg-gray-200 dark:bg-slate-600 text-gray-700 dark:text-slate-300" title="NPO">
                                                <Ban className="w-3 h-3" aria-hidden="true" />
                                                NPO
                                            </span>
                                        )}
                                        {patient.specialAlerts.includes('contact-isolation') && (
                                            <span className="inline-flex items-center gap-0.5 px-2 py-0.5 rounded-full bg-blue-100 dark:bg-blue-900/30 text-brand-deep dark:text-blue-400" title="Contact isolation">
                                                <Shield className="w-3 h-3" aria-hidden="true" />
                                                Contact isolation
                                            </span>
                                        )}
                                    </div>
                                )}

                                {showAllergy && (
                                    <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-400 px-2.5 py-2 rounded flex items-start gap-1.5" role="alert">
                                        <AlertTriangle className="w-3.5 h-3.5 mt-0.5" aria-hidden="true" />
                                        <div>
                                            <p className="font-semibold text-xs">Allergy Alert</p>
                                            <p className="text-[10px] mt-0.5">
                                                {patient.allergies.map((allergy) => allergy.allergen).join(', ')}
                                            </p>
                                        </div>
                                    </div>
                                )}

                                <div className="mt-auto flex flex-wrap gap-2">
                                    <Button className="flex-1 min-w-[100px] bg-brand-medium hover:bg-brand-deep text-white text-xs">
                                        Record Vitals
                                    </Button>
                                    <Button variant="outline" className="flex-1 min-w-[100px] border-brand-medium text-brand-medium hover:bg-brand-light text-xs">
                                        View Details
                                    </Button>
                                    <button type="button" className="text-xs font-semibold text-brand-medium hover:text-brand-deep flex items-center gap-0.5">
                                        <Edit3 className="w-3.5 h-3.5" aria-hidden="true" />
                                        Add Note
                                    </button>
                                </div>
                            </div>
                        </Card>
                    );
                })}
            </div>
        )}
    </Card>
);

export default AssignedPatientsPanel;
