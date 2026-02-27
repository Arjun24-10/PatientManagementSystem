import React, { useState } from 'react';
import {
   Calendar,
   FileText,
   Pill,
   TestTube,
   AlertCircle,
   User,
   Clock,
   ChevronDown,
   ChevronUp,
   Filter,
   Search,
   Download,
   Printer,
   Activity,
   Stethoscope,
   Syringe,
   AlertTriangle
} from 'lucide-react';
import Card from '../../components/common/Card';
import Button from '../../components/common/Button';
import Badge from '../../components/common/Badge';
import {
   mockMedicalTimeline,
   mockDiagnosesHistory,
   mockTreatmentHistory,
   mockProcedureHistory,
   mockAllergies,
   mockChronicConditions
} from '../../mocks/medicalHistory';

const MedicalHistory = () => {
   const [activeTab, setActiveTab] = useState('timeline');
   const [expandedCards, setExpandedCards] = useState({});
   const [searchTerm, setSearchTerm] = useState('');
   const [filterType, setFilterType] = useState('all');

   const tabs = [
      { key: 'timeline', label: 'Timeline', icon: Clock },
      { key: 'diagnoses', label: 'Diagnoses', icon: Stethoscope },
      { key: 'treatments', label: 'Treatments', icon: Activity },
      { key: 'procedures', label: 'Procedures', icon: Syringe },
      { key: 'allergies', label: 'Allergies & Conditions', icon: AlertTriangle }
   ];

   const toggleCard = (id) => {
      setExpandedCards(prev => ({
         ...prev,
         [id]: !prev[id]
      }));
   };

   // Get icon for timeline event type
   const getTimelineIcon = (type) => {
      switch (type) {
         case 'visit':
            return <Calendar className="w-5 h-5" />;
         case 'lab':
            return <TestTube className="w-5 h-5" />;
         case 'prescription':
            return <Pill className="w-5 h-5" />;
         case 'procedure':
            return <Syringe className="w-5 h-5" />;
         default:
            return <FileText className="w-5 h-5" />;
      }
   };

   // Get color for timeline event type
   const getTimelineColor = (type) => {
      switch (type) {
         case 'visit':
            return 'border-blue-500 bg-blue-50 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400';
         case 'lab':
            return 'border-orange-500 bg-orange-50 dark:bg-orange-900/20 text-orange-600 dark:text-orange-400';
         case 'prescription':
            return 'border-green-500 bg-green-50 dark:bg-green-900/20 text-green-600 dark:text-green-400';
         case 'procedure':
            return 'border-purple-500 bg-purple-50 dark:bg-purple-900/20 text-purple-600 dark:text-purple-400';
         default:
            return 'border-gray-500 bg-gray-50 dark:bg-slate-800/50 text-gray-600 dark:text-slate-300';
      }
   };

   // Get badge type for severity
   const getSeverityBadge = (severity) => {
      switch (severity?.toLowerCase()) {
         case 'high':
         case 'severe':
            return 'red';
         case 'medium':
         case 'moderate':
            return 'yellow';
         case 'low':
         case 'mild':
            return 'green';
         default:
            return 'gray';
      }
   };

   // Get badge type for status
   const getStatusBadge = (status) => {
      switch (status?.toLowerCase()) {
         case 'active':
         case 'ongoing':
         case 'controlled':
            return 'green';
         case 'resolved':
         case 'completed':
            return 'gray';
         case 'chronic':
         case 'monitoring':
            return 'yellow';
         case 'discontinued':
         case 'cancelled':
            return 'red';
         default:
            return 'gray';
      }
   };

   // Filter timeline based on search and filter type
   const filteredTimeline = mockMedicalTimeline.filter(item => {
      const matchesSearch = item.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
         item.summary.toLowerCase().includes(searchTerm.toLowerCase());
      const matchesFilter = filterType === 'all' || item.type === filterType;
      return matchesSearch && matchesFilter;
   });

   // Render Timeline Tab
   const renderTimeline = () => (
      <div className="space-y-4">
         {/* Search and Filter Bar */}
         <div className="flex flex-col md:flex-row gap-2">
            <div className="flex-1 relative">
               <Search className="absolute left-2.5 top-1/2 transform -translate-y-1/2 text-gray-400 dark:text-slate-400 w-4 h-4" />
               <input
                  type="text"
                  placeholder="Search medical history..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full pl-8 pr-3 py-2 text-sm border border-gray-300 dark:border-slate-600 rounded focus:ring-1 focus:ring-blue-500 focus:border-blue-500 bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100"
               />
            </div>
            <select
               value={filterType}
               onChange={(e) => setFilterType(e.target.value)}
               className="px-3 py-2 text-sm border border-gray-300 dark:border-slate-600 rounded focus:ring-1 focus:ring-blue-500 focus:border-blue-500 bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100"
            >
               <option value="all">All Events</option>
               <option value="visit">Visits</option>
               <option value="lab">Lab Results</option>
               <option value="prescription">Prescriptions</option>
               <option value="procedure">Procedures</option>
            </select>
            <Button variant="outline" className="whitespace-nowrap h-[42px] px-4 flex items-center justify-center">
               <Download className="w-4 h-4 mr-2" />
               Export Timeline
            </Button>
         </div>

         {/* Timeline */}
         <div className="relative">
            {/* Vertical Line */}
            <div className="absolute left-4 top-3 bottom-0 w-0.5 bg-blue-200 dark:bg-blue-800"></div>

            <div className="space-y-3">
               {filteredTimeline.length > 0 ? (
                  filteredTimeline.map((event) => (
                     <div key={event.id} className="relative pl-12">
                        {/* Timeline Dot */}
                        <div className="absolute left-2.5 top-4 w-3 h-3 rounded-full border-2 border-white dark:border-slate-800 bg-blue-500 shadow-sm z-10"></div>

                        <Card className={`p-5 hover:shadow-sm transition-all border-l-4 ${getTimelineColor(event.type).split(' ')[0]}`}>
                           <div className="flex flex-col md:flex-row justify-between md:items-start gap-3">
                              <div className="flex items-start gap-4 flex-1">
                                 <div className={`p-2.5 rounded-lg ${getTimelineColor(event.type)}`}>
                                    {React.cloneElement(getTimelineIcon(event.type), { className: 'w-5 h-5' })}
                                 </div>
                                 <div className="flex-1">
                                    <div className="flex items-center gap-2 mb-1">
                                       <h3 className="font-semibold text-gray-800 dark:text-slate-100 text-base">{event.title}</h3>
                                    </div>
                                    <div className="flex items-center gap-4 text-sm text-gray-500 dark:text-slate-400 mb-2">
                                       <span className="flex items-center">
                                          <Calendar className="w-4 h-4 mr-1.5" />
                                          {new Date(event.date).toLocaleDateString('en-US', {
                                             year: 'numeric',
                                             month: 'short',
                                             day: 'numeric'
                                          })}
                                       </span>
                                       <span className="flex items-center">
                                          <User className="w-4 h-4 mr-1.5" />
                                          {event.doctor}
                                       </span>
                                    </div>
                                    <p className="text-sm text-gray-600 dark:text-slate-300 mb-2">{event.summary}</p>

                                    {expandedCards[event.id] && (
                                       <div className="mt-3 p-3.5 bg-gray-50 dark:bg-slate-800/50 rounded-lg border border-gray-200 dark:border-slate-700">
                                          <h4 className="font-semibold text-gray-700 dark:text-slate-200 text-sm mb-1.5">Full Details</h4>
                                          <p className="text-sm text-gray-600 dark:text-slate-300 leading-relaxed">{event.details}</p>
                                          <div className="mt-3 pt-3 border-t border-gray-200 dark:border-slate-700 text-sm text-gray-500 dark:text-slate-400">
                                             <span className="font-medium text-gray-700 dark:text-slate-300">Department:</span> {event.department}
                                          </div>
                                       </div>
                                    )}

                                    <button
                                       onClick={() => toggleCard(event.id)}
                                       className="text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 text-xs font-medium flex items-center mt-1"
                                    >
                                       {expandedCards[event.id] ? (
                                          <>
                                             <ChevronUp className="w-3.5 h-3.5 mr-0.5" />
                                             Hide
                                          </>
                                       ) : (
                                          <>
                                             <ChevronDown className="w-3.5 h-3.5 mr-0.5" />
                                             Details
                                          </>
                                       )}
                                    </button>
                                 </div>
                              </div>
                              <Badge type={getStatusBadge(event.status)}>
                                 {event.status}
                              </Badge>
                           </div>
                        </Card>
                     </div>
                  ))
               ) : (
                  <div className="p-8 text-center text-gray-400 dark:text-slate-500">
                     <Filter className="w-8 h-8 mx-auto mb-2 opacity-50" />
                     <p className="text-sm">No records found matching your search.</p>
                  </div>
               )}
            </div>
         </div>
      </div>
   );

   // Render Diagnoses Tab
   const renderDiagnoses = () => (
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
         {mockDiagnosesHistory.map((diagnosis) => (
            <Card key={diagnosis.id} className={`p-5 hover:shadow-sm transition-all border-l-4 ${diagnosis.status === 'active' ? 'border-red-500' :
               diagnosis.status === 'chronic' ? 'border-orange-500' :
                  'border-gray-300 dark:border-slate-600'
               }`}>
               <div className="flex justify-between items-start mb-3">
                  <div>
                     <h3 className="font-semibold text-gray-800 dark:text-slate-100 text-base">{diagnosis.name}</h3>
                     {diagnosis.icdCode && (
                        <p className="text-sm text-gray-500 dark:text-slate-400 mt-1">ICD-10: {diagnosis.icdCode}</p>
                     )}
                  </div>
                  <Badge type={getStatusBadge(diagnosis.status)}>
                     {diagnosis.status}
                  </Badge>
               </div>

               <div className="space-y-2 mb-3">
                  <div className="flex items-center justify-between text-sm">
                     <span className="text-gray-500 dark:text-slate-400">Diagnosed:</span>
                     <span className="font-medium text-gray-700 dark:text-slate-200">
                        {new Date(diagnosis.dateRecorded).toLocaleDateString('en-US', {
                           year: 'numeric',
                           month: 'short',
                           day: 'numeric'
                        })}
                     </span>
                  </div>
                  <div className="flex items-center justify-between text-sm">
                     <span className="text-gray-500 dark:text-slate-400">Physician:</span>
                     <span className="font-medium text-gray-700 dark:text-slate-200">{diagnosis.physician}</span>
                  </div>
                  <div className="flex items-center justify-between text-sm">
                     <span className="text-gray-500 dark:text-slate-400">Severity:</span>
                     <Badge type={getSeverityBadge(diagnosis.severity)}>
                        {diagnosis.severity}
                     </Badge>
                  </div>
               </div>

               <div className="pt-3 border-t border-gray-200 dark:border-slate-700">
                  <p className="text-sm text-gray-600 dark:text-slate-300 leading-relaxed">
                     {expandedCards[diagnosis.id]
                        ? diagnosis.notes
                        : `${diagnosis.notes.substring(0, 80)}...`
                     }
                  </p>
                  {diagnosis.notes.length > 80 && (
                     <button
                        onClick={() => toggleCard(diagnosis.id)}
                        className="text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 text-xs font-medium mt-1"
                     >
                        {expandedCards[diagnosis.id] ? 'Less' : 'More'}
                     </button>
                  )}
               </div>

               {diagnosis.relatedMedications && diagnosis.relatedMedications.length > 0 && (
                  <div className="mt-2 pt-2 border-t border-gray-200 dark:border-slate-700">
                     <p className="text-xs text-gray-500 dark:text-slate-400 mb-1">Related Medications:</p>
                     <div className="flex flex-wrap gap-1">
                        {diagnosis.relatedMedications.map((med, idx) => (
                           <span key={idx} className="px-1.5 py-0.5 bg-blue-50 dark:bg-blue-900/20 text-blue-700 dark:text-blue-400 text-xs rounded">
                              {med}
                           </span>
                        ))}
                     </div>
                  </div>
               )}
            </Card>
         ))}
      </div>
   );

   // Render Treatments Tab
   const renderTreatments = () => (
      <div className="space-y-4">
         {mockTreatmentHistory.map((treatment) => (
            <Card key={treatment.id} className="p-5 hover:shadow-sm transition-all">
               <div className="flex flex-col md:flex-row justify-between md:items-start gap-3 mb-3">
                  <div className="flex-1">
                     <div className="flex items-center gap-3 mb-1.5">
                        <div className="p-2 bg-green-50 dark:bg-green-900/20 rounded-lg text-green-600 dark:text-green-400">
                           <Activity className="w-5 h-5" />
                        </div>
                        <div>
                           <h3 className="font-semibold text-gray-800 dark:text-slate-100 text-base">{treatment.name}</h3>
                           <p className="text-sm text-gray-500 dark:text-slate-400">{treatment.type}</p>
                        </div>
                     </div>
                  </div>
                  <Badge type={getStatusBadge(treatment.status)}>
                     {treatment.status}
                  </Badge>
               </div>

               <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-3">
                  <div>
                     <p className="text-sm text-gray-500 dark:text-slate-400">Start Date</p>
                     <p className="text-sm font-medium text-gray-700 dark:text-slate-200">
                        {new Date(treatment.startDate).toLocaleDateString('en-US', {
                           year: 'numeric',
                           month: 'short',
                           day: 'numeric'
                        })}
                     </p>
                  </div>
                  <div>
                     <p className="text-sm text-gray-500 dark:text-slate-400">End Date</p>
                     <p className="text-sm font-medium text-gray-700 dark:text-slate-200">
                        {treatment.endDate
                           ? new Date(treatment.endDate).toLocaleDateString('en-US', {
                              year: 'numeric',
                              month: 'short',
                              day: 'numeric'
                           })
                           : 'Ongoing'
                        }
                     </p>
                  </div>
                  <div>
                     <p className="text-sm text-gray-500 dark:text-slate-400">Prescribed By</p>
                     <p className="text-sm font-medium text-gray-700 dark:text-slate-200">{treatment.prescribedBy}</p>
                  </div>
                  <div>
                     <p className="text-sm text-gray-500 dark:text-slate-400">Department</p>
                     <p className="text-sm font-medium text-gray-700 dark:text-slate-200">{treatment.department}</p>
                  </div>
               </div>

               <div className="mb-3">
                  <p className="text-sm text-gray-500 dark:text-slate-400 mb-1">Purpose</p>
                  <p className="text-sm text-gray-700 dark:text-slate-200">{treatment.purpose}</p>
               </div>

               {treatment.status === 'ongoing' && treatment.progress !== undefined && (
                  <div className="mb-2">
                     <div className="flex justify-between items-center mb-1">
                        <p className="text-xs text-gray-500 dark:text-slate-400">Progress</p>
                        <p className="text-xs font-medium text-gray-700 dark:text-slate-200">{treatment.progress}%</p>
                     </div>
                     <div className="w-full bg-gray-200 dark:bg-slate-700 rounded-full h-1.5">
                        <div
                           className="bg-green-500 h-1.5 rounded-full transition-all"
                           style={{ width: `${treatment.progress}%` }}
                        ></div>
                     </div>
                  </div>
               )}

               {treatment.medications && treatment.medications.length > 0 && (
                  <div className="mb-2">
                     <p className="text-xs text-gray-500 dark:text-slate-400 mb-1">Medications</p>
                     <div className="flex flex-wrap gap-1">
                        {treatment.medications.map((med, idx) => (
                           <span key={idx} className="px-2 py-0.5 bg-blue-50 dark:bg-blue-900/20 text-blue-700 dark:text-blue-400 text-xs rounded flex items-center">
                              <Pill className="w-3 h-3 mr-0.5" />
                              {med}
                           </span>
                        ))}
                     </div>
                  </div>
               )}

               <div className="pt-2 border-t border-gray-200 dark:border-slate-700">
                  <p className="text-xs text-gray-600 dark:text-slate-300">{treatment.notes}</p>
               </div>

               {treatment.nextReview && (
                  <div className="mt-2 pt-2 border-t border-gray-200 dark:border-slate-700 flex items-center text-xs text-gray-500 dark:text-slate-400">
                     <Clock className="w-3.5 h-3.5 mr-1" />
                     Next Review: {new Date(treatment.nextReview).toLocaleDateString('en-US', {
                        year: 'numeric',
                        month: 'short',
                        day: 'numeric'
                     })}
                  </div>
               )}
            </Card>
         ))}
      </div>
   );

   // Render Procedures Tab
   const renderProcedures = () => (
      <div className="space-y-4">
         {mockProcedureHistory.map((procedure) => (
            <Card key={procedure.id} className="p-5 hover:shadow-sm transition-all">
               <div className="flex flex-col md:flex-row justify-between md:items-start gap-3 mb-3">
                  <div className="flex items-start gap-3 flex-1">
                     <div className="p-2 bg-purple-50 dark:bg-purple-900/20 rounded-lg text-purple-600 dark:text-purple-400">
                        <Syringe className="w-5 h-5" />
                     </div>
                     <div className="flex-1">
                        <h3 className="font-semibold text-gray-800 dark:text-slate-100 text-base mb-1">{procedure.name}</h3>
                        <div className="flex flex-wrap gap-4 text-sm text-gray-500 dark:text-slate-400">
                           <span className="flex items-center">
                              <Calendar className="w-4 h-4 mr-1.5" />
                              {new Date(procedure.date).toLocaleDateString('en-US', {
                                 year: 'numeric',
                                 month: 'short',
                                 day: 'numeric'
                              })}
                           </span>
                           <span className="flex items-center">
                              <User className="w-4 h-4 mr-1.5" />
                              {procedure.physician}
                           </span>
                        </div>
                     </div>
                  </div>
                  <div className="flex gap-1">
                     <Badge type={getStatusBadge(procedure.status)}>
                        {procedure.status}
                     </Badge>
                     {procedure.followUpRequired && (
                        <Badge type="yellow">
                           Follow-up
                        </Badge>
                     )}
                  </div>
               </div>

               <div className="grid grid-cols-2 gap-4 mb-3">
                  <div>
                     <p className="text-sm text-gray-500 dark:text-slate-400">Location</p>
                     <p className="text-sm font-medium text-gray-700 dark:text-slate-200">{procedure.location}</p>
                  </div>
                  <div>
                     <p className="text-sm text-gray-500 dark:text-slate-400">Department</p>
                     <p className="text-sm font-medium text-gray-700 dark:text-slate-200">{procedure.department}</p>
                  </div>
               </div>

               {procedure.indication && (
                  <div className="mb-3">
                     <p className="text-sm text-gray-500 dark:text-slate-400 mb-1">Indication</p>
                     <p className="text-sm text-gray-700 dark:text-slate-200">{procedure.indication}</p>
                  </div>
               )}

               {expandedCards[procedure.id] && (
                  <div className="space-y-2 mb-2">
                     {procedure.findings && (
                        <div>
                           <p className="text-xs font-semibold text-gray-700 dark:text-slate-200 mb-0.5">Findings</p>
                           <p className="text-xs text-gray-600 dark:text-slate-300 bg-gray-50 dark:bg-slate-800/50 p-2 rounded">{procedure.findings}</p>
                        </div>
                     )}
                     {procedure.preOpNotes && (
                        <div>
                           <p className="text-xs font-semibold text-gray-700 dark:text-slate-200 mb-0.5">Pre-Procedure Notes</p>
                           <p className="text-xs text-gray-600 dark:text-slate-300 bg-gray-50 dark:bg-slate-800/50 p-2 rounded">{procedure.preOpNotes}</p>
                        </div>
                     )}
                     {procedure.postOpNotes && (
                        <div>
                           <p className="text-xs font-semibold text-gray-700 dark:text-slate-200 mb-0.5">Post-Procedure Notes</p>
                           <p className="text-xs text-gray-600 dark:text-slate-300 bg-gray-50 dark:bg-slate-800/50 p-2 rounded">{procedure.postOpNotes}</p>
                        </div>
                     )}
                     {procedure.documents && procedure.documents.length > 0 && (
                        <div>
                           <p className="text-xs font-semibold text-gray-700 dark:text-slate-200 mb-1">Documents</p>
                           <div className="flex flex-wrap gap-1">
                              {procedure.documents.map((doc, idx) => (
                                 <button
                                    key={idx}
                                    className="px-2 py-1 bg-blue-50 dark:bg-blue-900/20 text-blue-700 dark:text-blue-400 text-xs rounded hover:bg-blue-100 dark:hover:bg-blue-900/40 transition flex items-center"
                                 >
                                    <FileText className="w-3 h-3 mr-1" />
                                    {doc}
                                 </button>
                              ))}
                           </div>
                        </div>
                     )}
                  </div>
               )}

               <button
                  onClick={() => toggleCard(procedure.id)}
                  className="text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 text-xs font-medium flex items-center"
               >
                  {expandedCards[procedure.id] ? (
                     <>
                        <ChevronUp className="w-3.5 h-3.5 mr-0.5" />
                        Hide
                     </>
                  ) : (
                     <>
                        <ChevronDown className="w-3.5 h-3.5 mr-0.5" />
                        Details
                     </>
                  )}
               </button>

               {procedure.nextProcedure && (
                  <div className="mt-2 pt-2 border-t border-gray-200 dark:border-slate-700 flex items-center text-xs text-gray-500 dark:text-slate-400">
                     <Clock className="w-3.5 h-3.5 mr-1" />
                     Next: {new Date(procedure.nextProcedure).toLocaleDateString('en-US', {
                        year: 'numeric',
                        month: 'short',
                        day: 'numeric'
                     })}
                  </div>
               )}
            </Card>
         ))}
      </div>
   );

   // Render Allergies & Conditions Tab
   const renderAllergiesAndConditions = () => (
      <div className="space-y-4">
         {/* Critical Allergies Alert */}
         {mockAllergies.some(a => a.severity === 'severe') && (
            <div className="bg-red-50 dark:bg-red-900/20 border-l-4 border-red-500 p-2.5 rounded-r">
               <div className="flex items-start">
                  <AlertTriangle className="w-4 h-4 text-red-600 dark:text-red-400 mr-2 mt-0.5 flex-shrink-0" />
                  <div>
                     <h3 className="font-semibold text-red-800 dark:text-red-300 text-sm mb-0.5">Critical Allergies Alert</h3>
                     <p className="text-xs text-red-700 dark:text-red-400">
                        This patient has severe allergies. Review allergy list before prescribing.
                     </p>
                  </div>
               </div>
            </div>
         )}

         {/* Allergies Section */}
         <div>
            <div className="flex justify-between items-center mb-2">
               <h3 className="text-sm font-bold text-gray-800 dark:text-slate-100 flex items-center">
                  <AlertCircle className="w-4 h-4 mr-1.5 text-red-500" />
                  Allergies
               </h3>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
               {mockAllergies.map((allergy) => (
                  <Card key={allergy.id} className={`p-3 border-l-4 ${allergy.severity === 'severe' ? 'border-red-500 bg-red-50 dark:bg-red-900/20' :
                     allergy.severity === 'moderate' ? 'border-orange-500' :
                        'border-yellow-500'
                     }`}>
                     <div className="flex justify-between items-start mb-1">
                        <div className="flex items-center gap-1">
                           {allergy.severity === 'severe' && (
                              <AlertTriangle className="w-3.5 h-3.5 text-red-600 dark:text-red-400" />
                           )}
                           <h4 className="font-bold text-gray-800 dark:text-slate-100 text-sm">{allergy.allergen}</h4>
                        </div>
                        <Badge type={getSeverityBadge(allergy.severity)}>
                           {allergy.severity}
                        </Badge>
                     </div>

                     <div className="space-y-1 mb-2">
                        <div className="flex items-center justify-between text-xs">
                           <span className="text-gray-500 dark:text-slate-400">Type:</span>
                           <span className="font-medium text-gray-700 dark:text-slate-200 capitalize">{allergy.type}</span>
                        </div>
                        <div className="flex items-center justify-between text-xs">
                           <span className="text-gray-500 dark:text-slate-400">Identified:</span>
                           <span className="font-medium text-gray-700 dark:text-slate-200">
                              {new Date(allergy.dateIdentified).toLocaleDateString('en-US', {
                                 year: 'numeric',
                                 month: 'short'
                              })}
                           </span>
                        </div>
                     </div>

                     <div className="mb-2">
                        <p className="text-xs text-gray-500 dark:text-slate-400 mb-0.5">Reaction:</p>
                        <p className="text-xs text-gray-700 dark:text-slate-200 bg-white dark:bg-slate-800 p-2 rounded border border-gray-200 dark:border-slate-700">
                           {allergy.reaction}
                        </p>
                     </div>

                     {expandedCards[allergy.id] && (
                        <div className="space-y-2 pt-2 border-t border-gray-200 dark:border-slate-700">
                           <div>
                              <p className="text-xs text-gray-500 dark:text-slate-400 mb-0.5">Notes:</p>
                              <p className="text-xs text-gray-600 dark:text-slate-300">{allergy.notes}</p>
                           </div>
                           {allergy.alternatives && allergy.alternatives.length > 0 && (
                              <div>
                                 <p className="text-xs text-gray-500 dark:text-slate-400 mb-1">Safe Alternatives:</p>
                                 <div className="flex flex-wrap gap-1">
                                    {allergy.alternatives.map((alt, idx) => (
                                       <span key={idx} className="px-1.5 py-0.5 bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400 text-xs rounded-full">
                                          {alt}
                                       </span>
                                    ))}
                                 </div>
                              </div>
                           )}
                        </div>
                     )}

                     <button
                        onClick={() => toggleCard(allergy.id)}
                        className="text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 text-xs font-medium mt-2"
                     >
                        {expandedCards[allergy.id] ? 'Less' : 'More'}
                     </button>
                  </Card>
               ))}
            </div>
         </div>

         {/* Chronic Conditions Section */}
         <div>
            <div className="flex justify-between items-center mb-2">
               <h3 className="text-sm font-bold text-gray-800 dark:text-slate-100 flex items-center">
                  <Stethoscope className="w-4 h-4 mr-1.5 text-blue-500" />
                  Chronic Conditions
               </h3>
            </div>

            <div className="space-y-2">
               {mockChronicConditions.map((condition) => (
                  <Card key={condition.id} className="p-3 hover:shadow-md transition-all">
                     <div className="flex flex-col md:flex-row justify-between md:items-start gap-2 mb-2">
                        <div className="flex-1">
                           <h4 className="font-bold text-gray-800 dark:text-slate-100 text-sm mb-0.5">{condition.name}</h4>
                           <p className="text-xs text-gray-500 dark:text-slate-400">
                              Diagnosed: {new Date(condition.dateDiagnosed).toLocaleDateString('en-US', {
                                 year: 'numeric',
                                 month: 'long'
                              })}
                           </p>
                        </div>
                        <Badge type={getStatusBadge(condition.status)}>
                           {condition.status}
                        </Badge>
                     </div>

                     <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mb-2 text-xs">
                        <div>
                           <p className="text-gray-500 dark:text-slate-400">Managing Physician</p>
                           <p className="font-medium text-gray-700 dark:text-slate-200">{condition.managingPhysician}</p>
                        </div>
                        <div>
                           <p className="text-gray-500 dark:text-slate-400">Department</p>
                           <p className="font-medium text-gray-700 dark:text-slate-200">{condition.department}</p>
                        </div>
                        <div>
                           <p className="text-gray-500 dark:text-slate-400">Last Checkup</p>
                           <p className="font-medium text-gray-700 dark:text-slate-200">
                              {new Date(condition.lastCheckup).toLocaleDateString('en-US', {
                                 year: 'numeric',
                                 month: 'short',
                                 day: 'numeric'
                              })}
                           </p>
                        </div>
                        <div>
                           <p className="text-gray-500 dark:text-slate-400">Next Review</p>
                           <p className="font-medium text-gray-700 dark:text-slate-200">
                              {new Date(condition.nextReview).toLocaleDateString('en-US', {
                                 year: 'numeric',
                                 month: 'short',
                                 day: 'numeric'
                              })}
                           </p>
                        </div>
                     </div>

                     {condition.medications && condition.medications.length > 0 && (
                        <div className="mb-2">
                           <p className="text-xs text-gray-500 dark:text-slate-400 mb-1">Current Medications</p>
                           <div className="flex flex-wrap gap-1">
                              {condition.medications.map((med, idx) => (
                                 <span key={idx} className="px-2 py-0.5 bg-blue-50 dark:bg-blue-900/20 text-blue-700 dark:text-blue-400 text-xs rounded-full flex items-center">
                                    <Pill className="w-2.5 h-2.5 mr-0.5" />
                                    {med}
                                 </span>
                              ))}
                           </div>
                        </div>
                     )}

                     <div className="pt-2 border-t border-gray-200 dark:border-slate-700">
                        <p className="text-xs text-gray-600 dark:text-slate-300 mb-2">{condition.notes}</p>

                        {expandedCards[condition.id] && (
                           <div className="space-y-1.5 mt-2 pt-2 border-t border-gray-200 dark:border-slate-700">
                              <div className="flex items-center justify-between text-xs">
                                 <span className="text-gray-500 dark:text-slate-400">Complications:</span>
                                 <span className="font-medium text-gray-700 dark:text-slate-200">{condition.complications}</span>
                              </div>
                              <div className="text-xs">
                                 <span className="text-gray-500 dark:text-slate-400">Monitoring Plan:</span>
                                 <p className="font-medium text-gray-700 dark:text-slate-200 mt-0.5">{condition.monitoring}</p>
                              </div>
                           </div>
                        )}

                        <button
                           onClick={() => toggleCard(condition.id)}
                           className="text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 text-xs font-medium mt-2"
                        >
                           {expandedCards[condition.id] ? 'Less' : 'Details'}
                        </button>
                     </div>
                  </Card>
               ))}
            </div>
         </div>
      </div>
   );

   return (
      <div className="space-y-3">
         {/* Header */}
         <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
            <div>
               <h2 className="text-2xl font-bold text-gray-800 dark:text-slate-100">Medical History</h2>
               <p className="text-sm text-gray-500 dark:text-slate-400 mt-1">Medical records and health information</p>
            </div>
            <div className="flex gap-3 w-full md:w-auto">
               <Button variant="outline" className="whitespace-nowrap flex-1 md:flex-none px-4 py-2 flex items-center justify-center">
                  <Printer className="w-5 h-5 mr-2" />
                  Print History
               </Button>
               <Button className="whitespace-nowrap flex-1 md:flex-none px-4 py-2 flex items-center justify-center">
                  <Download className="w-5 h-5 mr-2" />
                  Export PDF
               </Button>
            </div>
         </div>

         {/* Tabs */}
         <div className="border-b border-gray-200 dark:border-slate-700">
            <nav className="-mb-px flex space-x-6 overflow-x-auto">
               {tabs.map((tab) => {
                  const Icon = tab.icon;
                  return (
                     <button
                        key={tab.key}
                        onClick={() => setActiveTab(tab.key)}
                        className={`
                           whitespace-nowrap py-3 px-1 border-b-2 font-medium text-sm flex items-center gap-2 transition-colors
                           ${activeTab === tab.key
                              ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                              : 'border-transparent text-gray-500 dark:text-slate-400 hover:text-gray-700 dark:hover:text-slate-300 hover:border-gray-300 dark:hover:border-slate-600'
                           }
                        `}
                     >
                        <Icon className="w-3.5 h-3.5" />
                        {tab.label}
                     </button>
                  );
               })}
            </nav>
         </div>

         {/* Tab Content */}
         <div className="mt-3">
            {activeTab === 'timeline' && renderTimeline()}
            {activeTab === 'diagnoses' && renderDiagnoses()}
            {activeTab === 'treatments' && renderTreatments()}
            {activeTab === 'procedures' && renderProcedures()}
            {activeTab === 'allergies' && renderAllergiesAndConditions()}
         </div>
      </div>
   );
};

export default MedicalHistory;
