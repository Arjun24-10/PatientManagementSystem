import React, { useState } from 'react';
import {
   Pill,
   Calendar,
   Download,
   AlertCircle,
   User,
   ChevronUp,
   Search,
   AlertTriangle,
   CheckCircle,
   RefreshCw,
   Info
} from 'lucide-react';
import Card from '../../components/common/Card';
import Button from '../../components/common/Button';
import Badge from '../../components/common/Badge';
import {
   mockMedicationsData,
   mockDrugInteractions,
   mockMedicationStats
} from '../../mocks/medications';

const Medications = () => {
   const [searchTerm, setSearchTerm] = useState('');
   const [activeTab, setActiveTab] = useState('active');
   const [expandedMeds, setExpandedMeds] = useState({});
   const [showRefillModal, setShowRefillModal] = useState(false);
   const [selectedMed, setSelectedMed] = useState(null);

   const toggleExpand = (id) => {
      setExpandedMeds(prev => ({
         ...prev,
         [id]: !prev[id]
      }));
   };

   const handleRefillRequest = (medication) => {
      setSelectedMed(medication);
      setShowRefillModal(true);
   };

   const submitRefillRequest = () => {
      // TODO: Implement actual refill request
      alert(`Refill request submitted for ${selectedMed.name}`);
      setShowRefillModal(false);
      setSelectedMed(null);
   };

   const handleDownload = (medication) => {
      // TODO: Implement actual download
      alert(`Downloading prescription for ${medication.name}...`);
   };

   // Filter medications based on search
   const filteredMedications = (activeTab === 'active' ? mockMedicationsData.active : mockMedicationsData.history)
      .filter(med => med.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
         med.genericName.toLowerCase().includes(searchTerm.toLowerCase()) ||
         med.prescribedBy.name.toLowerCase().includes(searchTerm.toLowerCase()));

   // Get medication type badge color
   const getFormBadge = (form) => {
      const colors = {
         'Tablet': 'bg-blue-100 text-blue-700',
         'Capsule': 'bg-green-100 text-green-700',
         'Liquid': 'bg-purple-100 text-purple-700',
         'Injection': 'bg-red-100 text-red-700'
      };
      return colors[form] || 'bg-gray-100 text-gray-700';
   };

   return (
      <div className="space-y-6">
         {/* Header */}
         <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
            <div>
               <h2 className="text-2xl font-bold text-gray-800 dark:text-slate-100">My Medications</h2>
               <p className="text-gray-500 dark:text-slate-400">Manage your current and past prescriptions</p>
            </div>
            <div className="flex gap-2">
               <Button variant="outline" className="p-2" title="Download All Medications">
                  <Download className="w-5 h-5" />
               </Button>
            </div>
         </div>

         {/* Drug Interaction Warning */}
         {mockDrugInteractions.length > 0 && activeTab === 'active' && (
            <div className="bg-orange-50 dark:bg-orange-900/20 border-l-4 border-orange-500 p-4 rounded-r-lg">
               <div className="flex items-start">
                  <AlertTriangle className="w-6 h-6 text-orange-600 dark:text-orange-400 mr-3 mt-0.5 flex-shrink-0" />
                  <div className="flex-1">
                     <h3 className="font-bold text-orange-800 dark:text-orange-300 mb-1">Potential Drug Interaction Detected</h3>
                     {mockDrugInteractions.map((interaction, idx) => (
                        <div key={idx} className="text-sm text-orange-700 dark:text-orange-400 mb-2">
                           <p className="font-medium">{interaction.medication1} + {interaction.medication2}</p>
                           <p>{interaction.description}</p>
                           <p className="mt-1"><span className="font-semibold">Recommendation:</span> {interaction.recommendation}</p>
                        </div>
                     ))}
                  </div>
               </div>
            </div>
         )}

         {/* Stats Cards */}
         <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <Card className="p-6 hover:shadow-md transition-shadow">
               <div className="flex items-center justify-between">
                  <div>
                     <p className="text-sm text-gray-500 dark:text-slate-400 mb-1">Active Medications</p>
                     <p className="text-3xl font-bold text-gray-800 dark:text-slate-100">{mockMedicationStats.totalActive}</p>
                  </div>
                  <div className="p-3 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                     <Pill className="w-6 h-6 text-blue-600 dark:text-blue-400" />
                  </div>
               </div>
            </Card>

            <Card className="p-6 hover:shadow-md transition-shadow">
               <div className="flex items-center justify-between">
                  <div>
                     <p className="text-sm text-gray-500 dark:text-slate-400 mb-1">Needing Refill</p>
                     <p className="text-3xl font-bold text-gray-800 dark:text-slate-100">{mockMedicationStats.needingRefill}</p>
                  </div>
                  <div className="p-3 bg-orange-50 dark:bg-orange-900/20 rounded-lg">
                     <RefreshCw className="w-6 h-6 text-orange-600 dark:text-orange-400" />
                  </div>
               </div>
            </Card>

            <Card className="p-6 hover:shadow-md transition-shadow">
               <div className="flex items-center justify-between">
                  <div>
                     <p className="text-sm text-gray-500 dark:text-slate-400 mb-1">Expiring Soon</p>
                     <p className="text-3xl font-bold text-gray-800 dark:text-slate-100">{mockMedicationStats.upcomingExpirations}</p>
                  </div>
                  <div className="p-3 bg-red-50 dark:bg-red-900/20 rounded-lg">
                     <AlertCircle className="w-6 h-6 text-red-600 dark:text-red-400" />
                  </div>
               </div>
            </Card>

            <Card className="p-6 hover:shadow-md transition-shadow">
               <div className="flex items-center justify-between">
                  <div>
                     <p className="text-sm text-gray-500 dark:text-slate-400 mb-1">Adherence Rate</p>
                     <p className="text-3xl font-bold text-gray-800 dark:text-slate-100">{mockMedicationStats.adherenceRate}%</p>
                  </div>
                  <div className="p-3 bg-green-50 dark:bg-green-900/20 rounded-lg">
                     <CheckCircle className="w-6 h-6 text-green-600 dark:text-green-400" />
                  </div>
               </div>
            </Card>
         </div>

         {/* Search and Tabs */}
         <div className="flex flex-col md:flex-row gap-4">
            <div className="flex-1 relative">
               <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 dark:text-slate-500 w-5 h-5" />
               <input
                  type="text"
                  placeholder="Search medications..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 border border-gray-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100"
               />
            </div>
            <div className="flex gap-2">
               <button
                  onClick={() => setActiveTab('active')}
                  className={`px-4 py-2 rounded-lg font-medium transition ${activeTab === 'active'
                     ? 'bg-blue-600 text-white'
                     : 'bg-white dark:bg-slate-800 text-gray-600 dark:text-slate-300 border border-gray-300 dark:border-slate-600 hover:bg-gray-50 dark:hover:bg-slate-700/50'
                     }`}
               >
                  Active
               </button>
               <button
                  onClick={() => setActiveTab('history')}
                  className={`px-4 py-2 rounded-lg font-medium transition ${activeTab === 'history'
                     ? 'bg-blue-600 text-white'
                     : 'bg-white dark:bg-slate-800 text-gray-600 dark:text-slate-300 border border-gray-300 dark:border-slate-600 hover:bg-gray-50 dark:hover:bg-slate-700/50'
                     }`}
               >
                  History
               </button>
            </div>
         </div>

         {/* Medications Grid */}
         <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {filteredMedications.map((medication) => {
               const isExpanded = expandedMeds[medication.id];

               return (
                  <Card
                     key={medication.id}
                     className={`p-6 hover:shadow-lg transition-all ${medication.critical ? 'border-l-4 border-red-500' : ''
                        } ${medication.status === 'expiring-soon' ? 'border-l-4 border-orange-500' : ''}`}
                  >
                     {/* Medication Header */}
                     <div className="mb-4">
                        <div className="flex items-start justify-between mb-2">
                           <div className="flex-1">
                              <h3 className="font-bold text-gray-800 dark:text-slate-100 text-lg">{medication.name}</h3>
                              <p className="text-sm text-gray-500 dark:text-slate-400">{medication.genericName}</p>
                           </div>
                           {medication.critical && (
                              <AlertCircle className="w-5 h-5 text-red-500 flex-shrink-0" />
                           )}
                        </div>
                        <div className="flex items-center gap-2 mb-3">
                           <span className={`px-2 py-1 rounded-full text-xs font-semibold ${getFormBadge(medication.form)}`}>
                              {medication.form}
                           </span>
                           <span className="text-sm font-medium text-gray-700 dark:text-slate-200">{medication.strength}</span>
                        </div>
                     </div>

                     {/* Dosage Info */}
                     <div className="space-y-2 mb-4">
                        <div className="flex items-center text-sm">
                           <Pill className="w-4 h-4 mr-2 text-gray-400 dark:text-slate-500" />
                           <span className="text-gray-700 dark:text-slate-200">{medication.dosage}</span>
                        </div>
                        <div className="flex items-center text-sm">
                           <User className="w-4 h-4 mr-2 text-gray-400 dark:text-slate-500" />
                           <span className="text-gray-700 dark:text-slate-200">{medication.prescribedBy.name}</span>
                        </div>
                        <div className="flex items-center text-sm">
                           <Calendar className="w-4 h-4 mr-2 text-gray-400 dark:text-slate-500" />
                           <span className="text-gray-700 dark:text-slate-200">
                              Since {new Date(medication.startDate).toLocaleDateString('en-US', {
                                 year: 'numeric',
                                 month: 'short'
                              })}
                           </span>
                        </div>
                     </div>

                     {/* Status and Refills */}
                     {activeTab === 'active' && (
                        <div className="mb-4 p-3 bg-gray-50 dark:bg-slate-800/50 rounded-lg">
                           <div className="flex items-center justify-between text-sm mb-2">
                              <span className="text-gray-600 dark:text-slate-300">Refills Remaining:</span>
                              <Badge type={medication.refillsRemaining <= 1 ? 'yellow' : 'green'}>
                                 {medication.refillsRemaining} of {medication.totalRefills}
                              </Badge>
                           </div>
                           {medication.expiryWarning && (
                              <p className="text-xs text-orange-600 dark:text-orange-400 font-medium">{medication.expiryWarning}</p>
                           )}
                        </div>
                     )}

                     {/* History Status */}
                     {activeTab === 'history' && (
                        <div className="mb-4">
                           <Badge type={medication.status === 'completed' ? 'gray' : 'red'}>
                              {medication.status}
                           </Badge>
                           {medication.discontinuedReason && (
                              <p className="text-xs text-gray-600 dark:text-slate-300 mt-2">Reason: {medication.discontinuedReason}</p>
                           )}
                        </div>
                     )}

                     {/* Purpose */}
                     <div className="mb-4 p-3 bg-blue-50 dark:bg-blue-900/20 rounded-lg border border-blue-100 dark:border-blue-800">
                        <p className="text-xs text-blue-600 dark:text-blue-400 font-semibold mb-1">Purpose</p>
                        <p className="text-sm text-blue-900 dark:text-blue-300">{medication.purpose}</p>
                     </div>

                     {/* Expanded Details */}
                     {isExpanded && (
                        <div className="mt-4 pt-4 border-t border-gray-200 dark:border-slate-700 space-y-3">
                           <div>
                              <p className="text-xs font-semibold text-gray-600 dark:text-slate-300 mb-1">Instructions</p>
                              <p className="text-sm text-gray-700 dark:text-slate-200">{medication.instructions}</p>
                           </div>

                           {medication.sideEffects && medication.sideEffects.length > 0 && (
                              <div>
                                 <p className="text-xs font-semibold text-gray-600 dark:text-slate-300 mb-1">Common Side Effects</p>
                                 <div className="flex flex-wrap gap-1">
                                    {medication.sideEffects.map((effect, idx) => (
                                       <span key={idx} className="px-2 py-1 bg-gray-100 dark:bg-slate-700 text-gray-700 dark:text-slate-200 text-xs rounded">
                                          {effect}
                                       </span>
                                    ))}
                                 </div>
                              </div>
                           )}

                           {medication.interactions && medication.interactions.length > 0 && (
                              <div>
                                 <p className="text-xs font-semibold text-red-600 dark:text-red-400 mb-1">Drug Interactions</p>
                                 <div className="flex flex-wrap gap-1">
                                    {medication.interactions.map((interaction, idx) => (
                                       <span key={idx} className="px-2 py-1 bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-400 text-xs rounded">
                                          {interaction}
                                       </span>
                                    ))}
                                 </div>
                              </div>
                           )}

                           {medication.warnings && medication.warnings.length > 0 && (
                              <div>
                                 <p className="text-xs font-semibold text-orange-600 dark:text-orange-400 mb-1">Warnings</p>
                                 <ul className="text-xs text-orange-700 dark:text-orange-400 space-y-1">
                                    {medication.warnings.map((warning, idx) => (
                                       <li key={idx}>• {warning}</li>
                                    ))}
                                 </ul>
                              </div>
                           )}

                           <div className="text-xs text-gray-500 dark:text-slate-400">
                              <p>Prescription #: {medication.prescriptionNumber}</p>
                              <p>Pharmacy: {medication.pharmacy}</p>
                           </div>
                        </div>
                     )}

                     {/* Action Buttons */}
                     <div className="mt-4 flex gap-2">
                        <button
                           onClick={() => toggleExpand(medication.id)}
                           className="flex-1 px-3 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition text-sm font-medium inline-flex items-center justify-center whitespace-nowrap"
                        >
                           {isExpanded ? (
                              <>
                                 <ChevronUp className="w-4 h-4 mr-1" />
                                 Less
                              </>
                           ) : (
                              <>
                                 <Info className="w-4 h-4 mr-1" />
                                 Details
                              </>
                           )}
                        </button>
                        {activeTab === 'active' && medication.canRefill && (
                           <button
                              onClick={() => handleRefillRequest(medication)}
                              className="flex-1 px-3 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition text-sm font-medium inline-flex items-center justify-center whitespace-nowrap"
                           >
                              <RefreshCw className="w-4 h-4 mr-1" />
                              Refill
                           </button>
                        )}
                        <button
                           onClick={() => handleDownload(medication)}
                           className="px-3 py-2 bg-white dark:bg-slate-800 border border-gray-300 dark:border-slate-600 text-gray-700 dark:text-slate-200 rounded-lg hover:bg-gray-50 dark:hover:bg-slate-700/50 transition text-sm font-medium inline-flex items-center justify-center whitespace-nowrap"
                        >
                           <Download className="w-4 h-4" />
                        </button>
                     </div>
                  </Card>
               );
            })}
         </div>

         {/* Empty State */}
         {filteredMedications.length === 0 && (
            <div className="p-12 text-center text-gray-400 dark:text-slate-500">
               <Pill className="w-12 h-12 mx-auto mb-2 opacity-50" />
               <p>No medications found matching your search.</p>
            </div>
         )}

         {/* Refill Request Modal */}
         {showRefillModal && selectedMed && (
            <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
               <Card className="max-w-md w-full p-6">
                  <h3 className="text-xl font-bold text-gray-800 dark:text-slate-100 mb-4">Request Refill</h3>

                  <div className="mb-4 p-4 bg-gray-50 dark:bg-slate-800/50 rounded-lg">
                     <p className="font-semibold text-gray-800 dark:text-slate-100">{selectedMed.name} {selectedMed.strength}</p>
                     <p className="text-sm text-gray-600 dark:text-slate-300">{selectedMed.dosage}</p>
                     <p className="text-sm text-gray-600 dark:text-slate-300 mt-2">
                        Refills Remaining: {selectedMed.refillsRemaining} of {selectedMed.totalRefills}
                     </p>
                  </div>

                  <div className="space-y-4 mb-6">
                     <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-slate-200 mb-2">
                           Preferred Pharmacy
                        </label>
                        <select className="w-full px-3 py-2 border border-gray-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-blue-500 bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100">
                           <option>{selectedMed.pharmacy}</option>
                        </select>
                     </div>

                     <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-slate-200 mb-2">
                           Pickup Method
                        </label>
                        <div className="flex gap-4">
                           <label className="flex items-center">
                              <input type="radio" name="pickup" value="pickup" defaultChecked className="mr-2" />
                              <span className="text-sm">Pickup</span>
                           </label>
                           <label className="flex items-center">
                              <input type="radio" name="pickup" value="delivery" className="mr-2" />
                              <span className="text-sm">Delivery</span>
                           </label>
                        </div>
                     </div>

                     <div>
                        <label className="flex items-center">
                           <input type="checkbox" defaultChecked className="mr-2" />
                           <span className="text-sm text-gray-700 dark:text-slate-200">I confirm this is for the same dosage</span>
                        </label>
                     </div>
                  </div>

                  <div className="flex gap-2">
                     <Button onClick={submitRefillRequest} className="flex-1">
                        Submit Request
                     </Button>
                     <Button variant="outline" onClick={() => setShowRefillModal(false)} className="flex-1">
                        Cancel
                     </Button>
                  </div>
               </Card>
            </div>
         )}
      </div>
   );
};

export default Medications;
