import React, { useState } from 'react';
import {
   FileText,
   Download,
   AlertCircle,
   Calendar,
   TrendingUp,
   Search,
   Filter,
   ChevronDown,
   ChevronUp,
   CheckCircle,
   AlertTriangle,
   User,
   Clock,
   X
} from 'lucide-react';
import Card from '../../components/common/Card';
import Button from '../../components/common/Button';
import Badge from '../../components/common/Badge';
import IconButton from '../../components/common/IconButton';
import api from '../../services/api';
import { useAuth } from '../../contexts/AuthContext';
import { mockLabResults } from '../../mocks/labResults';

const LabResults = () => {
   const { user } = useAuth();
   const patientId = user?.userId;

   const [labResults, setLabResults] = useState([]);
   const [labStats] = useState({
      totalTests: 0,
      pendingResults: 0,
      recentAbnormal: 0
   });
   const [trendData] = useState({});

   React.useEffect(() => {
      const fetchLabs = async () => {
         try {
            const data = await api.labResults.getByPatient(patientId);
            if (Array.isArray(data)) setLabResults(data);
         } catch (error) {
            console.error('Failed to fetch labs', error);
            // Fallback to mock data for testing
            setLabResults(mockLabResults);
         }
      };
      if (patientId) {
         fetchLabs();
      } else {
         // Use mock data when no patient ID
         setLabResults(mockLabResults);
      }
   }, [patientId]);

   const [searchTerm, setSearchTerm] = useState('');
   const [expandedResults, setExpandedResults] = useState({});
   const [showTrendModal, setShowTrendModal] = useState(false);
   const [selectedTrendData, setSelectedTrendData] = useState(null);
   const [filterStatus, setFilterStatus] = useState('all');
   const [sortBy, setSortBy] = useState('recent');

   const toggleExpand = (id) => {
      setExpandedResults(prev => ({
         ...prev,
         [id]: !prev[id]
      }));
   };

   // Filter and sort results
   const filteredResults = labResults
      .filter(result => {
         const matchesSearch = result.testName.toLowerCase().includes(searchTerm.toLowerCase()) ||
            result.orderingPhysician.toLowerCase().includes(searchTerm.toLowerCase());
         const matchesFilter = filterStatus === 'all' ||
            (filterStatus === 'normal' && result.overallStatus === 'normal') ||
            (filterStatus === 'abnormal' && (result.overallStatus === 'abnormal' || result.overallStatus === 'borderline')) ||
            (filterStatus === 'pending' && result.status === 'pending');
         return matchesSearch && matchesFilter;
      })
      .sort((a, b) => {
         if (sortBy === 'recent') {
            return new Date(b.testDate) - new Date(a.testDate);
         } else if (sortBy === 'name') {
            return a.testName.localeCompare(b.testName);
         } else if (sortBy === 'abnormal') {
            const order = { 'abnormal': 0, 'borderline': 1, 'normal': 2, 'pending': 3 };
            return order[a.overallStatus] - order[b.overallStatus];
         }
         return 0;
      });

   // Get overall status icon and color
   const getStatusDisplay = (status) => {
      switch (status) {
         case 'normal':
            return {
               icon: <CheckCircle className="w-5 h-5" />,
               text: 'All Normal',
               color: 'text-green-600 bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-700'
            };
         case 'abnormal':
            return {
               icon: <AlertCircle className="w-5 h-5" />,
               text: 'Abnormal Values',
               color: 'text-red-600 bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-700'
            };
         case 'borderline':
            return {
               icon: <AlertTriangle className="w-5 h-5" />,
               text: 'Some Borderline',
               color: 'text-orange-600 bg-orange-50 dark:bg-orange-900/20 border-orange-200 dark:border-orange-700'
            };
         case 'pending':
            return {
               icon: <Clock className="w-5 h-5" />,
               text: 'Pending',
               color: 'text-blue-600 bg-blue-50 dark:bg-blue-900/20 border-blue-200 dark:border-blue-700'
            };
         default:
            return {
               icon: <FileText className="w-5 h-5" />,
               text: 'Unknown',
               color: 'text-gray-600 dark:text-slate-300 bg-gray-50 dark:bg-slate-800/50 border-gray-200 dark:border-slate-700'
            };
      }
   };

   // Get parameter status badge
   const getParameterBadge = (status, flag) => {
      if (status === 'normal') {
         return <Badge type="green">Normal</Badge>;
      } else if (status === 'high' || flag === 'abnormal') {
         return <Badge type="red">High</Badge>;
      } else if (status === 'low') {
         return <Badge type="red">Low</Badge>;
      } else if (flag === 'borderline') {
         return <Badge type="yellow">Borderline</Badge>;
      }
      return <Badge type="gray">-</Badge>;
   };

   // Download handler
   const handleDownload = (result) => {
      // TODO: Implement actual download
      alert(`Downloading ${result.testName} results...`);
   };

   // Trend handler
   const handleViewTrend = (result) => {
      // Determine which trend data to show based on test name
      let trendKey = null;
      if (result.testName.includes('CBC') || result.testName.includes('Blood Count')) {
         trendKey = 'wbc';
      } else if (result.testName.includes('Lipid') || result.testName.includes('Cholesterol')) {
         trendKey = 'cholesterol';
      } else if (result.testName.includes('HbA1c') || result.testName.includes('Diabetes')) {
         trendKey = 'hba1c';
      } else if (result.testName.includes('Vitamin D')) {
         trendKey = 'vitaminD';
      }

      if (trendKey && trendData[trendKey]) {
         setSelectedTrendData({
            testName: result.testName,
            data: trendData[trendKey],
            parameter: trendKey
         });
         setShowTrendModal(true);
      } else {
         alert('Trend data not available for this test');
      }
   };

   return (
      <div className="space-y-4">
         {/* Header */}
         <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-3">
            <div>
               <h2 className="text-lg font-bold text-gray-800 dark:text-slate-100">Lab Results</h2>
               <p className="text-xs text-gray-500 dark:text-slate-400">View and download your laboratory test results</p>
            </div>
            <IconButton 
               icon={Download} 
               label="Download All" 
               variant="outline" 
               size="default"
            />
         </div>

         {/* Summary Stats */}
         <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <Card className="p-3 hover:shadow-sm transition-shadow">
               <div className="flex items-center justify-between">
                  <div>
                     <p className="text-xs text-gray-500 dark:text-slate-400 mb-0.5">Total Tests</p>
                     <p className="text-xl font-bold text-gray-800 dark:text-slate-100">{labStats.totalTests}</p>
                  </div>
                  <div className="p-2 bg-blue-50 dark:bg-blue-900/20 rounded">
                     <FileText className="w-4 h-4 text-blue-600" />
                  </div>
               </div>
            </Card>

            <Card className="p-3 hover:shadow-sm transition-shadow">
               <div className="flex items-center justify-between">
                  <div>
                     <p className="text-xs text-gray-500 dark:text-slate-400 mb-0.5">Pending Results</p>
                     <p className="text-xl font-bold text-gray-800 dark:text-slate-100">{labStats.pendingResults}</p>
                  </div>
                  <div className="p-2 bg-yellow-50 dark:bg-yellow-900/20 rounded">
                     <Clock className="w-4 h-4 text-yellow-600" />
                  </div>
               </div>
            </Card>

            <Card className="p-3 hover:shadow-sm transition-shadow">
               <div className="flex items-center justify-between">
                  <div>
                     <p className="text-xs text-gray-500 dark:text-slate-400 mb-0.5">Recent Abnormal</p>
                     <p className="text-xl font-bold text-gray-800 dark:text-slate-100">{labStats.recentAbnormal}</p>
                  </div>
                  <div className="p-2 bg-red-50 dark:bg-red-900/20 rounded">
                     <AlertCircle className="w-4 h-4 text-red-600" />
                  </div>
               </div>
            </Card>
         </div>

         {/* Search and Filter Bar */}
         <div className="flex flex-col md:flex-row gap-2">
            <div className="flex-1 relative">
               <Search className="absolute left-2.5 top-1/2 transform -translate-y-1/2 text-gray-400 dark:text-slate-500 w-4 h-4" />
               <input
                  type="text"
                  placeholder="Search lab results..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full pl-8 pr-3 py-1.5 text-sm border border-gray-300 dark:border-slate-600 rounded focus:ring-1 focus:ring-blue-500 focus:border-blue-500 bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100"
               />
            </div>
            <select
               value={filterStatus}
               onChange={(e) => setFilterStatus(e.target.value)}
               className="px-3 py-1.5 text-sm border border-gray-300 dark:border-slate-600 rounded focus:ring-1 focus:ring-blue-500 focus:border-blue-500 bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100"
            >
               <option value="all">All Results</option>
               <option value="normal">Normal Only</option>
               <option value="abnormal">Abnormal Only</option>
               <option value="pending">Pending</option>
            </select>
            <select
               value={sortBy}
               onChange={(e) => setSortBy(e.target.value)}
               className="px-3 py-1.5 text-sm border border-gray-300 dark:border-slate-600 rounded focus:ring-1 focus:ring-blue-500 focus:border-blue-500 bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-100"
            >
               <option value="recent">Most Recent</option>
               <option value="name">Test Name A-Z</option>
               <option value="abnormal">Abnormal First</option>
            </select>
         </div>

         {/* Results List */}
         <div className="space-y-2">
            {filteredResults.length > 0 ? (
               filteredResults.map((result) => {
                  const statusDisplay = getStatusDisplay(result.overallStatus);
                  const isExpanded = expandedResults[result.id];

                  return (
                     <Card key={result.id} className="overflow-hidden hover:shadow-sm transition-shadow">
                        {/* Collapsed View */}
                        <div className="p-3">
                           <div className="flex flex-col md:flex-row justify-between md:items-start gap-3">
                              <div className="flex-1">
                                 <div className="flex items-start gap-3">
                                    <div className="p-2 bg-blue-50 dark:bg-blue-900/20 rounded text-blue-600">
                                       <FileText className="w-4 h-4" />
                                    </div>
                                    <div className="flex-1">
                                       <h3 className="font-semibold text-gray-800 dark:text-slate-100 text-sm mb-0.5">{result.testName}</h3>
                                       <div className="flex flex-wrap gap-3 text-xs text-gray-500 dark:text-slate-400 mb-1.5">
                                          <span className="flex items-center">
                                             <Calendar className="w-3.5 h-3.5 mr-1" />
                                             {new Date(result.testDate).toLocaleDateString('en-US', {
                                                year: 'numeric',
                                                month: 'long',
                                                day: 'numeric'
                                             })}
                                          </span>
                                          <span className="flex items-center">
                                             <User className="w-3.5 h-3.5 mr-1" />
                                             {result.orderingPhysician}
                                          </span>
                                       </div>
                                       <div className="flex items-center gap-1.5">
                                          <Badge type={result.status === 'completed' ? 'green' : 'yellow'}>
                                             {result.status === 'completed' ? 'Results Ready' : 'Pending'}
                                          </Badge>
                                          <div className={`flex items-center gap-1 px-2 py-0.5 text-xs rounded-full border ${statusDisplay.color}`}>
                                             {React.cloneElement(statusDisplay.icon, { className: 'w-3.5 h-3.5' })}
                                             <span className="font-medium">{statusDisplay.text}</span>
                                          </div>
                                       </div>
                                    </div>
                                 </div>
                              </div>

                              {/* Action Buttons */}
                              <div className="flex gap-1.5">
                                 {result.status === 'completed' && (
                                    <>
                                       <button
                                          onClick={() => toggleExpand(result.id)}
                                          className="inline-flex items-center gap-1.5 px-2.5 py-1.5 bg-blue-600 text-white rounded hover:bg-blue-700 transition text-xs font-medium"
                                       >
                                          {isExpanded ? (
                                             <>
                                                <ChevronUp className="w-3.5 h-3.5" />
                                                <span>Hide</span>
                                             </>
                                          ) : (
                                             <>
                                                <ChevronDown className="w-3.5 h-3.5" />
                                                <span>View</span>
                                             </>
                                          )}
                                       </button>
                                       <IconButton
                                          icon={Download}
                                          label="PDF"
                                          variant="outline"
                                          size="sm"
                                          onClick={() => handleDownload(result)}
                                       />
                                       {result.canCompare && (
                                          <button
                                             onClick={() => handleViewTrend(result)}
                                             className="px-2.5 py-1.5 bg-white dark:bg-slate-800 border border-gray-300 dark:border-slate-600 text-gray-700 dark:text-slate-200 rounded hover:bg-gray-50 dark:hover:bg-slate-700/50 transition text-xs font-medium inline-flex items-center whitespace-nowrap"
                                          >
                                             <TrendingUp className="w-3.5 h-3.5 mr-1" />
                                             Trend
                                          </button>
                                       )}
                                    </>
                                 )}
                              </div>
                           </div>

                           {/* Expanded View */}
                           {isExpanded && result.results && (
                              <div className="mt-3 pt-3 border-t border-gray-200 dark:border-slate-700">
                                 <h4 className="font-semibold text-gray-700 dark:text-slate-200 text-sm mb-2">Test Results</h4>
                                 <div className="overflow-x-auto">
                                    <table className="w-full">
                                       <thead>
                                          <tr className="bg-gray-50 dark:bg-slate-800/50">
                                             <th className="px-3 py-2 text-left text-xs font-semibold text-gray-600 dark:text-slate-300 uppercase tracking-wider">
                                                Parameter
                                             </th>
                                             <th className="px-3 py-2 text-left text-xs font-semibold text-gray-600 dark:text-slate-300 uppercase tracking-wider">
                                                Your Result
                                             </th>
                                             <th className="px-3 py-2 text-left text-xs font-semibold text-gray-600 dark:text-slate-300 uppercase tracking-wider">
                                                Normal Range
                                             </th>
                                             <th className="px-3 py-2 text-left text-xs font-semibold text-gray-600 dark:text-slate-300 uppercase tracking-wider">
                                                Status
                                             </th>
                                          </tr>
                                       </thead>
                                       <tbody className="divide-y divide-gray-200 dark:divide-slate-700">
                                          {result.results.map((param, idx) => (
                                             <tr key={idx} className={param.flag ? 'bg-red-50/30 dark:bg-red-900/10' : ''}>
                                                <td className="px-4 py-3 text-sm font-medium text-gray-800 dark:text-slate-100">
                                                   {param.parameter}
                                                </td>
                                                <td className={`px-4 py-3 text-sm font-bold ${param.flag ? 'text-red-600' : 'text-gray-800 dark:text-slate-100'
                                                   }`}>
                                                   {param.value} {param.unit}
                                                </td>
                                                <td className="px-4 py-3 text-sm text-gray-600 dark:text-slate-300">
                                                   {param.normalRange} {param.unit}
                                                </td>
                                                <td className="px-4 py-3 text-sm">
                                                   {getParameterBadge(param.status, param.flag)}
                                                </td>
                                             </tr>
                                          ))}
                                       </tbody>
                                    </table>
                                 </div>

                                 {/* Notes */}
                                 {result.notes && (
                                    <div className="mt-4 p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg border border-blue-200 dark:border-blue-700">
                                       <div className="flex items-start gap-2">
                                          <AlertCircle className="w-5 h-5 text-blue-600 mt-0.5 flex-shrink-0" />
                                          <div>
                                             <h5 className="font-semibold text-blue-900 dark:text-blue-100 mb-1">Clinical Notes</h5>
                                             <p className="text-sm text-blue-800 dark:text-blue-200">{result.notes}</p>
                                          </div>
                                       </div>
                                    </div>
                                 )}

                                 {/* Download Full Report */}
                                 <div className="mt-4 flex gap-2">
                                    <IconButton 
                                       icon={Download} 
                                       label="Download Report" 
                                       variant="outline" 
                                       size="sm" 
                                       onClick={() => handleDownload(result)}
                                    />
                                    {result.canCompare && (
                                       <IconButton 
                                          icon={TrendingUp} 
                                          label="View Trend" 
                                          variant="outline" 
                                          size="sm" 
                                          onClick={() => handleViewTrend(result)}
                                       />
                                    )}
                                 </div>
                              </div>
                           )}
                        </div>
                     </Card>
                  );
               })
            ) : (
               <div className="p-8 text-center text-gray-400 dark:text-slate-500">
                  <Filter className="w-8 h-8 mx-auto mb-2 opacity-50" />
                  <p className="text-sm">No lab results found matching your search.</p>
               </div>
            )}
         </div>

         {/* Trend Analysis Modal */}
         {showTrendModal && selectedTrendData && (
            <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
               <Card className="max-w-3xl w-full max-h-[90vh] overflow-y-auto">
                  <div className="p-4">
                     {/* Modal Header */}
                     <div className="flex justify-between items-start mb-4">
                        <div>
                           <h3 className="text-lg font-bold text-gray-800 dark:text-slate-100 mb-0.5">Trend Analysis</h3>
                           <p className="text-sm text-gray-600 dark:text-slate-300">{selectedTrendData.testName}</p>
                        </div>
                        <button
                           onClick={() => setShowTrendModal(false)}
                           className="p-1.5 hover:bg-gray-100 dark:hover:bg-slate-700 rounded transition"
                        >
                           <X className="w-4 h-4 text-gray-500 dark:text-slate-400" />
                        </button>
                     </div>

                     {/* Chart Visualization */}
                     <div className="mb-4">
                        <h4 className="font-semibold text-gray-700 dark:text-slate-200 text-sm mb-2">Value Trend Over Time</h4>

                        {/* Simple Line Chart using SVG */}
                        <div className="bg-gray-50 dark:bg-slate-800/50 p-4 rounded border border-gray-200 dark:border-slate-700">
                           <div className="relative" style={{ height: '220px' }}>
                              <svg className="w-full h-full" viewBox="0 0 800 220" preserveAspectRatio="none">
                                 {/* Grid lines */}
                                 <line x1="50" y1="0" x2="50" y2="250" stroke="#e5e7eb" strokeWidth="2" />
                                 <line x1="50" y1="250" x2="800" y2="250" stroke="#e5e7eb" strokeWidth="2" />

                                 {/* Normal range shading (if applicable) */}
                                 <rect x="50" y="100" width="750" height="100" fill="#dcfce7" opacity="0.3" />

                                 {/* Plot line */}
                                 {selectedTrendData.data.length > 1 && (
                                    <polyline
                                       points={selectedTrendData.data.map((point, idx) => {
                                          const x = 50 + (idx / (selectedTrendData.data.length - 1)) * 750;
                                          const maxValue = Math.max(...selectedTrendData.data.map(d => d.value));
                                          const minValue = Math.min(...selectedTrendData.data.map(d => d.value));
                                          const range = maxValue - minValue || 1;
                                          const y = 250 - ((point.value - minValue) / range) * 200;
                                          return `${x},${y}`;
                                       }).join(' ')}
                                       fill="none"
                                       stroke="#3b82f6"
                                       strokeWidth="3"
                                    />
                                 )}

                                 {/* Plot points */}
                                 {selectedTrendData.data.map((point, idx) => {
                                    const x = 50 + (idx / (selectedTrendData.data.length - 1)) * 750;
                                    const maxValue = Math.max(...selectedTrendData.data.map(d => d.value));
                                    const minValue = Math.min(...selectedTrendData.data.map(d => d.value));
                                    const range = maxValue - minValue || 1;
                                    const y = 250 - ((point.value - minValue) / range) * 200;

                                    return (
                                       <g key={idx}>
                                          <circle
                                             cx={x}
                                             cy={y}
                                             r="6"
                                             fill={point.normal ? '#22c55e' : '#ef4444'}
                                             stroke="white"
                                             strokeWidth="2"
                                          />
                                       </g>
                                    );
                                 })}
                              </svg>

                              {/* Legend */}
                              <div className="absolute top-2 right-2 bg-white dark:bg-slate-800 p-2 rounded shadow-sm border border-gray-200 dark:border-slate-700 text-xs text-gray-700 dark:text-slate-200">
                                 <div className="flex items-center gap-2 mb-1">
                                    <div className="w-3 h-3 rounded-full bg-green-500"></div>
                                    <span>Normal</span>
                                 </div>
                                 <div className="flex items-center gap-2">
                                    <div className="w-3 h-3 rounded-full bg-red-500"></div>
                                    <span>Abnormal</span>
                                 </div>
                              </div>
                           </div>

                           {/* X-axis labels */}
                           <div className="flex justify-between mt-2 px-12 text-xs text-gray-600 dark:text-slate-300">
                              {selectedTrendData.data.map((point, idx) => (
                                 <span key={idx}>
                                    {new Date(point.date).toLocaleDateString('en-US', { month: 'short', year: '2-digit' })}
                                 </span>
                              ))}
                           </div>
                        </div>
                     </div>

                     {/* Data Table */}
                     <div>
                        <h4 className="font-semibold text-gray-700 dark:text-slate-200 text-sm mb-2">Historical Values</h4>
                        <div className="overflow-x-auto">
                           <table className="w-full">
                              <thead>
                                 <tr className="bg-gray-50 dark:bg-slate-800/50">
                                    <th className="px-3 py-2 text-left text-xs font-semibold text-gray-600 dark:text-slate-300 uppercase">Date</th>
                                    <th className="px-3 py-2 text-left text-xs font-semibold text-gray-600 dark:text-slate-300 uppercase">Value</th>
                                    <th className="px-3 py-2 text-left text-xs font-semibold text-gray-600 dark:text-slate-300 uppercase">Status</th>
                                    <th className="px-3 py-2 text-left text-xs font-semibold text-gray-600 dark:text-slate-300 uppercase">Trend</th>
                                 </tr>
                              </thead>
                              <tbody className="divide-y divide-gray-200 dark:divide-slate-700">
                                 {selectedTrendData.data.map((point, idx) => {
                                    const prevValue = idx > 0 ? selectedTrendData.data[idx - 1].value : null;
                                    const trend = prevValue ? (point.value > prevValue ? '↑' : point.value < prevValue ? '↓' : '→') : '-';
                                    const trendColor = prevValue ? (point.value > prevValue ? 'text-red-600' : point.value < prevValue ? 'text-green-600' : 'text-gray-600 dark:text-slate-300') : 'text-gray-600 dark:text-slate-300';

                                    return (
                                       <tr key={idx} className={!point.normal ? 'bg-red-50/30 dark:bg-red-900/10' : ''}>
                                          <td className="px-3 py-2 text-xs text-gray-800 dark:text-slate-100">
                                             {new Date(point.date).toLocaleDateString('en-US', {
                                                year: 'numeric',
                                                month: 'short',
                                                day: 'numeric'
                                             })}
                                          </td>
                                          <td className={`px-3 py-2 text-xs font-bold ${!point.normal ? 'text-red-600' : 'text-gray-800 dark:text-slate-100'}`}>
                                             {point.value}
                                          </td>
                                          <td className="px-3 py-2 text-xs">
                                             {point.normal ? (
                                                <Badge type="green">Normal</Badge>
                                             ) : (
                                                <Badge type="red">Abnormal</Badge>
                                             )}
                                          </td>
                                          <td className={`px-3 py-2 text-sm font-bold ${trendColor}`}>
                                             {trend}
                                          </td>
                                       </tr>
                                    );
                                 })}
                              </tbody>
                           </table>
                        </div>
                     </div>

                     {/* Close Button */}
                     <div className="mt-4 flex justify-end">
                        <Button size="sm" onClick={() => setShowTrendModal(false)}>
                           Close
                        </Button>
                     </div>
                  </div>
               </Card>
            </div>
         )}
      </div>
   );
};

export default LabResults;
