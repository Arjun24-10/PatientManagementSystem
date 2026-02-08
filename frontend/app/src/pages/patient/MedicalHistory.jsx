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
   AlertTriangle,
   CheckCircle,
   XCircle,
   TrendingUp
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
            return 'border-blue-500 bg-blue-50 text-blue-600';
         case 'lab':
            return 'border-orange-500 bg-orange-50 text-orange-600';
         case 'prescription':
            return 'border-green-500 bg-green-50 text-green-600';
         case 'procedure':
            return 'border-purple-500 bg-purple-50 text-purple-600';
         default:
            return 'border-gray-500 bg-gray-50 text-gray-600';
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
      <div className="space-y-6">
         {/* Search and Filter Bar */}
         <div className="flex flex-col md:flex-row gap-4">
            <div className="flex-1 relative">
               <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
               <input
                  type="text"
                  placeholder="Search medical history..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
               />
            </div>
            <select
               value={filterType}
               onChange={(e) => setFilterType(e.target.value)}
               className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            >
               <option value="all">All Events</option>
               <option value="visit">Visits</option>
               <option value="lab">Lab Results</option>
               <option value="prescription">Prescriptions</option>
               <option value="procedure">Procedures</option>
            </select>
            <Button variant="outline" className="whitespace-nowrap">
               <Download className="w-4 h-4 mr-2" />
               Export
            </Button>
         </div>

         {/* Timeline */}
         <div className="relative">
            {/* Vertical Line */}
            <div className="absolute left-6 top-4 bottom-0 w-0.5 bg-blue-200"></div>

            <div className="space-y-6">
               {filteredTimeline.length > 0 ? (
                  filteredTimeline.map((event) => (
                     <div key={event.id} className="relative pl-16">
                        {/* Timeline Dot */}
                        <div className="absolute left-3.5 top-6 w-5 h-5 rounded-full border-4 border-white bg-blue-500 shadow-sm z-10"></div>

                        <Card className={`p-6 hover:shadow-lg transition-all border-l-4 ${getTimelineColor(event.type).split(' ')[0]}`}>
                           <div className="flex flex-col md:flex-row justify-between md:items-start gap-4">
                              <div className="flex items-start gap-4 flex-1">
                                 <div className={`p-3 rounded-lg ${getTimelineColor(event.type)}`}>
                                    {getTimelineIcon(event.type)}
                                 </div>
                                 <div className="flex-1">
                                    <div className="flex items-center gap-2 mb-1">
                                       <h3 className="font-bold text-gray-800 text-lg">{event.title}</h3>
                                    </div>
                                    <div className="flex items-center gap-4 text-sm text-gray-500 mb-3">
                                       <span className="flex items-center">
                                          <Calendar className="w-4 h-4 mr-1" />
                                          {new Date(event.date).toLocaleDateString('en-US', {
                                             year: 'numeric',
                                             month: 'long',
                                             day: 'numeric'
                                          })}
                                       </span>
                                       <span className="flex items-center">
                                          <User className="w-4 h-4 mr-1" />
                                          {event.doctor}
                                       </span>
                                    </div>
                                    <p className="text-gray-600 mb-3">{event.summary}</p>

                                    {expandedCards[event.id] && (
                                       <div className="mt-4 p-4 bg-gray-50 rounded-lg border border-gray-200">
                                          <h4 className="font-semibold text-gray-700 mb-2">Full Details</h4>
                                          <p className="text-gray-600 leading-relaxed">{event.details}</p>
                                          <div className="mt-3 pt-3 border-t border-gray-200 text-sm text-gray-500">
                                             <span className="font-medium">Department:</span> {event.department}
                                          </div>
                                       </div>
                                    )}

                                    <button
                                       onClick={() => toggleCard(event.id)}
                                       className="text-blue-600 hover:text-blue-700 text-sm font-medium flex items-center mt-2"
                                    >
                                       {expandedCards[event.id] ? (
                                          <>
                                             <ChevronUp className="w-4 h-4 mr-1" />
                                             Hide Details
                                          </>
                                       ) : (
                                          <>
                                             <ChevronDown className="w-4 h-4 mr-1" />
                                             View Details
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
                  <div className="p-12 text-center text-gray-400">
                     <Filter className="w-12 h-12 mx-auto mb-2 opacity-50" />
                     <p>No records found matching your search.</p>
                  </div>
               )}
            </div>
         </div>
      </div>
   );

   // Render Diagnoses Tab
   const renderDiagnoses = () => (
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
         {mockDiagnosesHistory.map((diagnosis) => (
            <Card key={diagnosis.id} className={`p-6 hover:shadow-lg transition-all border-l-4 ${diagnosis.status === 'active' ? 'border-red-500' :
                  diagnosis.status === 'chronic' ? 'border-orange-500' :
                     'border-gray-300'
               }`}>
               <div className="flex justify-between items-start mb-3">
                  <div>
                     <h3 className="font-bold text-gray-800 text-lg">{diagnosis.name}</h3>
                     {diagnosis.icdCode && (
                        <p className="text-sm text-gray-500 mt-1">ICD-10: {diagnosis.icdCode}</p>
                     )}
                  </div>
                  <Badge type={getStatusBadge(diagnosis.status)}>
                     {diagnosis.status}
                  </Badge>
               </div>

               <div className="space-y-2 mb-4">
                  <div className="flex items-center justify-between text-sm">
                     <span className="text-gray-500">Diagnosed:</span>
                     <span className="font-medium text-gray-700">
                        {new Date(diagnosis.dateRecorded).toLocaleDateString('en-US', {
                           year: 'numeric',
                           month: 'short',
                           day: 'numeric'
                        })}
                     </span>
                  </div>
                  <div className="flex items-center justify-between text-sm">
                     <span className="text-gray-500">Physician:</span>
                     <span className="font-medium text-gray-700">{diagnosis.physician}</span>
                  </div>
                  <div className="flex items-center justify-between text-sm">
                     <span className="text-gray-500">Severity:</span>
                     <Badge type={getSeverityBadge(diagnosis.severity)}>
                        {diagnosis.severity}
                     </Badge>
                  </div>
               </div>

               <div className="pt-4 border-t border-gray-200">
                  <p className="text-sm text-gray-600 leading-relaxed">
                     {expandedCards[diagnosis.id]
                        ? diagnosis.notes
                        : `${diagnosis.notes.substring(0, 100)}...`
                     }
                  </p>
                  {diagnosis.notes.length > 100 && (
                     <button
                        onClick={() => toggleCard(diagnosis.id)}
                        className="text-blue-600 hover:text-blue-700 text-sm font-medium mt-2"
                     >
                        {expandedCards[diagnosis.id] ? 'Read less' : 'Read more'}
                     </button>
                  )}
               </div>

               {diagnosis.relatedMedications && diagnosis.relatedMedications.length > 0 && (
                  <div className="mt-4 pt-4 border-t border-gray-200">
                     <p className="text-xs text-gray-500 mb-2">Related Medications:</p>
                     <div className="flex flex-wrap gap-2">
                        {diagnosis.relatedMedications.map((med, idx) => (
                           <span key={idx} className="px-2 py-1 bg-blue-50 text-blue-700 text-xs rounded-full">
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
      <div className="space-y-6">
         {mockTreatmentHistory.map((treatment) => (
            <Card key={treatment.id} className="p-6 hover:shadow-lg transition-all">
               <div className="flex flex-col md:flex-row justify-between md:items-start gap-4 mb-4">
                  <div className="flex-1">
                     <div className="flex items-center gap-3 mb-2">
                        <div className="p-2 bg-green-50 rounded-lg text-green-600">
                           <Activity className="w-5 h-5" />
                        </div>
                        <div>
                           <h3 className="font-bold text-gray-800 text-lg">{treatment.name}</h3>
                           <p className="text-sm text-gray-500">{treatment.type}</p>
                        </div>
                     </div>
                  </div>
                  <Badge type={getStatusBadge(treatment.status)}>
                     {treatment.status}
                  </Badge>
               </div>

               <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                  <div>
                     <p className="text-sm text-gray-500">Start Date</p>
                     <p className="font-medium text-gray-700">
                        {new Date(treatment.startDate).toLocaleDateString('en-US', {
                           year: 'numeric',
                           month: 'short',
                           day: 'numeric'
                        })}
                     </p>
                  </div>
                  <div>
                     <p className="text-sm text-gray-500">End Date</p>
                     <p className="font-medium text-gray-700">
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
                     <p className="text-sm text-gray-500">Prescribed By</p>
                     <p className="font-medium text-gray-700">{treatment.prescribedBy}</p>
                  </div>
                  <div>
                     <p className="text-sm text-gray-500">Department</p>
                     <p className="font-medium text-gray-700">{treatment.department}</p>
                  </div>
               </div>

               <div className="mb-4">
                  <p className="text-sm text-gray-500 mb-1">Purpose</p>
                  <p className="text-gray-700">{treatment.purpose}</p>
               </div>

               {treatment.status === 'ongoing' && treatment.progress !== undefined && (
                  <div className="mb-4">
                     <div className="flex justify-between items-center mb-2">
                        <p className="text-sm text-gray-500">Progress</p>
                        <p className="text-sm font-medium text-gray-700">{treatment.progress}%</p>
                     </div>
                     <div className="w-full bg-gray-200 rounded-full h-2">
                        <div
                           className="bg-green-500 h-2 rounded-full transition-all"
                           style={{ width: `${treatment.progress}%` }}
                        ></div>
                     </div>
                  </div>
               )}

               {treatment.medications && treatment.medications.length > 0 && (
                  <div className="mb-4">
                     <p className="text-sm text-gray-500 mb-2">Medications</p>
                     <div className="flex flex-wrap gap-2">
                        {treatment.medications.map((med, idx) => (
                           <span key={idx} className="px-3 py-1 bg-blue-50 text-blue-700 text-sm rounded-full flex items-center">
                              <Pill className="w-3 h-3 mr-1" />
                              {med}
                           </span>
                        ))}
                     </div>
                  </div>
               )}

               <div className="pt-4 border-t border-gray-200">
                  <p className="text-sm text-gray-600">{treatment.notes}</p>
               </div>

               {treatment.nextReview && (
                  <div className="mt-4 pt-4 border-t border-gray-200 flex items-center text-sm text-gray-500">
                     <Clock className="w-4 h-4 mr-2" />
                     Next Review: {new Date(treatment.nextReview).toLocaleDateString('en-US', {
                        year: 'numeric',
                        month: 'long',
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
      <div className="space-y-6">
         {mockProcedureHistory.map((procedure) => (
            <Card key={procedure.id} className="p-6 hover:shadow-lg transition-all">
               <div className="flex flex-col md:flex-row justify-between md:items-start gap-4 mb-4">
                  <div className="flex items-start gap-4 flex-1">
                     <div className="p-3 bg-purple-50 rounded-lg text-purple-600">
                        <Syringe className="w-6 h-6" />
                     </div>
                     <div className="flex-1">
                        <h3 className="font-bold text-gray-800 text-lg mb-1">{procedure.name}</h3>
                        <div className="flex flex-wrap gap-4 text-sm text-gray-500">
                           <span className="flex items-center">
                              <Calendar className="w-4 h-4 mr-1" />
                              {new Date(procedure.date).toLocaleDateString('en-US', {
                                 year: 'numeric',
                                 month: 'long',
                                 day: 'numeric'
                              })}
                           </span>
                           <span className="flex items-center">
                              <User className="w-4 h-4 mr-1" />
                              {procedure.physician}
                           </span>
                        </div>
                     </div>
                  </div>
                  <div className="flex gap-2">
                     <Badge type={getStatusBadge(procedure.status)}>
                        {procedure.status}
                     </Badge>
                     {procedure.followUpRequired && (
                        <Badge type="yellow">
                           Follow-up Required
                        </Badge>
                     )}
                  </div>
               </div>

               <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                  <div>
                     <p className="text-sm text-gray-500">Location</p>
                     <p className="font-medium text-gray-700">{procedure.location}</p>
                  </div>
                  <div>
                     <p className="text-sm text-gray-500">Department</p>
                     <p className="font-medium text-gray-700">{procedure.department}</p>
                  </div>
               </div>

               {procedure.indication && (
                  <div className="mb-4">
                     <p className="text-sm text-gray-500 mb-1">Indication</p>
                     <p className="text-gray-700">{procedure.indication}</p>
                  </div>
               )}

               {expandedCards[procedure.id] && (
                  <div className="space-y-4 mb-4">
                     {procedure.findings && (
                        <div>
                           <p className="text-sm font-semibold text-gray-700 mb-1">Findings</p>
                           <p className="text-sm text-gray-600 bg-gray-50 p-3 rounded-lg">{procedure.findings}</p>
                        </div>
                     )}
                     {procedure.preOpNotes && (
                        <div>
                           <p className="text-sm font-semibold text-gray-700 mb-1">Pre-Procedure Notes</p>
                           <p className="text-sm text-gray-600 bg-gray-50 p-3 rounded-lg">{procedure.preOpNotes}</p>
                        </div>
                     )}
                     {procedure.postOpNotes && (
                        <div>
                           <p className="text-sm font-semibold text-gray-700 mb-1">Post-Procedure Notes</p>
                           <p className="text-sm text-gray-600 bg-gray-50 p-3 rounded-lg">{procedure.postOpNotes}</p>
                        </div>
                     )}
                     {procedure.documents && procedure.documents.length > 0 && (
                        <div>
                           <p className="text-sm font-semibold text-gray-700 mb-2">Documents</p>
                           <div className="flex flex-wrap gap-2">
                              {procedure.documents.map((doc, idx) => (
                                 <button
                                    key={idx}
                                    className="px-3 py-2 bg-blue-50 text-blue-700 text-sm rounded-lg hover:bg-blue-100 transition flex items-center"
                                 >
                                    <FileText className="w-4 h-4 mr-2" />
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
                  className="text-blue-600 hover:text-blue-700 text-sm font-medium flex items-center"
               >
                  {expandedCards[procedure.id] ? (
                     <>
                        <ChevronUp className="w-4 h-4 mr-1" />
                        Hide Details
                     </>
                  ) : (
                     <>
                        <ChevronDown className="w-4 h-4 mr-1" />
                        View Full Details
                     </>
                  )}
               </button>

               {procedure.nextProcedure && (
                  <div className="mt-4 pt-4 border-t border-gray-200 flex items-center text-sm text-gray-500">
                     <Clock className="w-4 h-4 mr-2" />
                     Next Procedure Scheduled: {new Date(procedure.nextProcedure).toLocaleDateString('en-US', {
                        year: 'numeric',
                        month: 'long',
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
      <div className="space-y-8">
         {/* Critical Allergies Alert */}
         {mockAllergies.some(a => a.severity === 'severe') && (
            <div className="bg-red-50 border-l-4 border-red-500 p-4 rounded-r-lg">
               <div className="flex items-start">
                  <AlertTriangle className="w-6 h-6 text-red-600 mr-3 mt-0.5 flex-shrink-0" />
                  <div>
                     <h3 className="font-bold text-red-800 mb-1">Critical Allergies Alert</h3>
                     <p className="text-sm text-red-700">
                        This patient has severe allergies. Please review allergy list before prescribing medications or procedures.
                     </p>
                  </div>
               </div>
            </div>
         )}

         {/* Allergies Section */}
         <div>
            <div className="flex justify-between items-center mb-4">
               <h3 className="text-xl font-bold text-gray-800 flex items-center">
                  <AlertCircle className="w-6 h-6 mr-2 text-red-500" />
                  Allergies
               </h3>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
               {mockAllergies.map((allergy) => (
                  <Card key={allergy.id} className={`p-6 border-l-4 ${allergy.severity === 'severe' ? 'border-red-500 bg-red-50' :
                        allergy.severity === 'moderate' ? 'border-orange-500' :
                           'border-yellow-500'
                     }`}>
                     <div className="flex justify-between items-start mb-3">
                        <div className="flex items-center gap-2">
                           {allergy.severity === 'severe' && (
                              <AlertTriangle className="w-5 h-5 text-red-600" />
                           )}
                           <h4 className="font-bold text-gray-800 text-lg">{allergy.allergen}</h4>
                        </div>
                        <Badge type={getSeverityBadge(allergy.severity)}>
                           {allergy.severity}
                        </Badge>
                     </div>

                     <div className="space-y-2 mb-4">
                        <div className="flex items-center justify-between text-sm">
                           <span className="text-gray-500">Type:</span>
                           <span className="font-medium text-gray-700 capitalize">{allergy.type}</span>
                        </div>
                        <div className="flex items-center justify-between text-sm">
                           <span className="text-gray-500">Identified:</span>
                           <span className="font-medium text-gray-700">
                              {new Date(allergy.dateIdentified).toLocaleDateString('en-US', {
                                 year: 'numeric',
                                 month: 'short'
                              })}
                           </span>
                        </div>
                     </div>

                     <div className="mb-4">
                        <p className="text-sm text-gray-500 mb-1">Reaction:</p>
                        <p className="text-sm text-gray-700 bg-white p-3 rounded-lg border border-gray-200">
                           {allergy.reaction}
                        </p>
                     </div>

                     {expandedCards[allergy.id] && (
                        <div className="space-y-3 pt-4 border-t border-gray-200">
                           <div>
                              <p className="text-sm text-gray-500 mb-1">Notes:</p>
                              <p className="text-sm text-gray-600">{allergy.notes}</p>
                           </div>
                           {allergy.alternatives && allergy.alternatives.length > 0 && (
                              <div>
                                 <p className="text-sm text-gray-500 mb-2">Safe Alternatives:</p>
                                 <div className="flex flex-wrap gap-2">
                                    {allergy.alternatives.map((alt, idx) => (
                                       <span key={idx} className="px-2 py-1 bg-green-50 text-green-700 text-xs rounded-full">
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
                        className="text-blue-600 hover:text-blue-700 text-sm font-medium mt-3"
                     >
                        {expandedCards[allergy.id] ? 'Show less' : 'Show more'}
                     </button>
                  </Card>
               ))}
            </div>
         </div>

         {/* Chronic Conditions Section */}
         <div>
            <div className="flex justify-between items-center mb-4">
               <h3 className="text-xl font-bold text-gray-800 flex items-center">
                  <Stethoscope className="w-6 h-6 mr-2 text-blue-500" />
                  Chronic Conditions
               </h3>
            </div>

            <div className="space-y-4">
               {mockChronicConditions.map((condition) => (
                  <Card key={condition.id} className="p-6 hover:shadow-lg transition-all">
                     <div className="flex flex-col md:flex-row justify-between md:items-start gap-4 mb-4">
                        <div className="flex-1">
                           <h4 className="font-bold text-gray-800 text-lg mb-1">{condition.name}</h4>
                           <p className="text-sm text-gray-500">
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

                     <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                        <div>
                           <p className="text-sm text-gray-500">Managing Physician</p>
                           <p className="font-medium text-gray-700">{condition.managingPhysician}</p>
                        </div>
                        <div>
                           <p className="text-sm text-gray-500">Department</p>
                           <p className="font-medium text-gray-700">{condition.department}</p>
                        </div>
                        <div>
                           <p className="text-sm text-gray-500">Last Checkup</p>
                           <p className="font-medium text-gray-700">
                              {new Date(condition.lastCheckup).toLocaleDateString('en-US', {
                                 year: 'numeric',
                                 month: 'short',
                                 day: 'numeric'
                              })}
                           </p>
                        </div>
                        <div>
                           <p className="text-sm text-gray-500">Next Review</p>
                           <p className="font-medium text-gray-700">
                              {new Date(condition.nextReview).toLocaleDateString('en-US', {
                                 year: 'numeric',
                                 month: 'short',
                                 day: 'numeric'
                              })}
                           </p>
                        </div>
                     </div>

                     {condition.medications && condition.medications.length > 0 && (
                        <div className="mb-4">
                           <p className="text-sm text-gray-500 mb-2">Current Medications</p>
                           <div className="flex flex-wrap gap-2">
                              {condition.medications.map((med, idx) => (
                                 <span key={idx} className="px-3 py-1 bg-blue-50 text-blue-700 text-sm rounded-full flex items-center">
                                    <Pill className="w-3 h-3 mr-1" />
                                    {med}
                                 </span>
                              ))}
                           </div>
                        </div>
                     )}

                     <div className="pt-4 border-t border-gray-200">
                        <p className="text-sm text-gray-600 mb-3">{condition.notes}</p>

                        {expandedCards[condition.id] && (
                           <div className="space-y-2 mt-4 pt-4 border-t border-gray-200">
                              <div className="flex items-center justify-between text-sm">
                                 <span className="text-gray-500">Complications:</span>
                                 <span className="font-medium text-gray-700">{condition.complications}</span>
                              </div>
                              <div className="text-sm">
                                 <span className="text-gray-500">Monitoring Plan:</span>
                                 <p className="font-medium text-gray-700 mt-1">{condition.monitoring}</p>
                              </div>
                           </div>
                        )}

                        <button
                           onClick={() => toggleCard(condition.id)}
                           className="text-blue-600 hover:text-blue-700 text-sm font-medium mt-3"
                        >
                           {expandedCards[condition.id] ? 'Show less' : 'Show monitoring details'}
                        </button>
                     </div>
                  </Card>
               ))}
            </div>
         </div>
      </div>
   );

   return (
      <div className="space-y-6">
         {/* Header */}
         <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
            <div>
               <h2 className="text-2xl font-bold text-gray-800">Medical History</h2>
               <p className="text-gray-500">Complete medical records and health information</p>
            </div>
            <div className="flex gap-2">
               <Button variant="outline" className="whitespace-nowrap">
                  <Printer className="w-4 h-4 mr-2" />
                  Print
               </Button>
               <Button variant="outline" className="whitespace-nowrap">
                  <Download className="w-4 h-4 mr-2" />
                  Export PDF
               </Button>
            </div>
         </div>

         {/* Tabs */}
         <div className="border-b border-gray-200">
            <nav className="-mb-px flex space-x-8 overflow-x-auto">
               {tabs.map((tab) => {
                  const Icon = tab.icon;
                  return (
                     <button
                        key={tab.key}
                        onClick={() => setActiveTab(tab.key)}
                        className={`
                           whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm flex items-center gap-2 transition-colors
                           ${activeTab === tab.key
                              ? 'border-blue-500 text-blue-600'
                              : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                           }
                        `}
                     >
                        <Icon className="w-4 h-4" />
                        {tab.label}
                     </button>
                  );
               })}
            </nav>
         </div>

         {/* Tab Content */}
         <div className="mt-6">
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
