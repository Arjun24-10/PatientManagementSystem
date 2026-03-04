import React, { useState } from 'react';
import { FileText, Download, BarChart2, PieChart, Check } from 'lucide-react';
import Card from '../../components/common/Card';
import Button from '../../components/common/Button';
import IconButton from '../../components/common/IconButton';
import Modal from '../../components/common/Modal';


const Reports = () => {
    const [reports, setReports] = useState([]);
    const [isModalOpen, setIsModalOpen] = useState(false);
    const [isLoading, setIsLoading] = useState(false);

    const [newReport, setNewReport] = useState({
        title: '',
        type: 'Clinical', // Default
        format: 'PDF',
        dateRange: 'Last 30 Days'
    });

    const handleInputChange = (e) => {
        const { name, value } = e.target;
        setNewReport(prev => ({
            ...prev,
            [name]: value
        }));
    };

    const handleGenerateReport = (e) => {
        e.preventDefault();
        setIsLoading(true);

        // Simulate API call/processing time
        setTimeout(() => {
            const report = {
                id: reports.length + 1,
                title: newReport.title || `${newReport.type} Report - ${new Date().toLocaleDateString()}`,
                date: new Date().toISOString().split('T')[0],
                type: newReport.type,
                size: '1.2 MB', // Mock size
                format: newReport.format,
                status: 'Ready'
            };

            setReports([report, ...reports]);
            setIsLoading(false);
            setIsModalOpen(false);
            setNewReport({
                title: '',
                type: 'Clinical',
                format: 'PDF',
                dateRange: 'Last 30 Days'
            });
        }, 1500);
    };

    return (
        <div className="space-y-3">
            <div className="flex justify-between items-center">
                <div>
                    <h2 className="text-lg font-bold text-gray-800 dark:text-slate-100">Reports & Analytics</h2>
                    <p className="text-xs text-gray-500 dark:text-slate-400">Access medical reports and practice analytics.</p>
                </div>
                <IconButton 
                   icon={BarChart2} 
                   label="Generate New Report" 
                   variant="primary"
                   onClick={() => setIsModalOpen(true)}
                />
            </div>

            {/* Quick Stats Placeholder */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <Card className="p-3 bg-blue-50 dark:bg-blue-900/20 border-blue-100 dark:border-blue-800">
                    <div className="flex items-center gap-2">
                        <div className="p-2 bg-blue-100 dark:bg-blue-900/40 rounded text-blue-600 dark:text-blue-400">
                            <FileText size={16} />
                        </div>
                        <div>
                            <p className="text-xs text-gray-500 dark:text-slate-400">Total Reports</p>
                            <h3 className="text-xl font-bold text-gray-800 dark:text-slate-100">{reports.length}</h3>
                        </div>
                    </div>
                </Card>
                <Card className="p-3 bg-purple-50 dark:bg-purple-900/20 border-purple-100 dark:border-purple-800">
                    <div className="flex items-center gap-2">
                        <div className="p-2 bg-purple-100 dark:bg-purple-900/40 rounded text-purple-600 dark:text-purple-400">
                            <PieChart size={16} />
                        </div>
                        <div>
                            <p className="text-xs text-gray-500 dark:text-slate-400">Analytics</p>
                            <h3 className="text-xl font-bold text-gray-800 dark:text-slate-100">15%</h3>
                            <p className="text-xs text-green-600 dark:text-green-400">+2% vs last month</p>
                        </div>
                    </div>
                </Card>
            </div>

            <div className="grid gap-2">
                <h3 className="text-sm font-bold text-gray-800 dark:text-slate-100 mt-2">Recent Reports</h3>
                {reports.map(report => (
                    <Card key={report.id} className="p-3 flex flex-col md:flex-row justify-between items-center group hover:border-blue-300 dark:hover:border-blue-600 transition-colors dark:bg-slate-800">
                        <div className="flex items-center gap-2 w-full md:w-auto">
                            <div className="p-2 bg-gray-100 dark:bg-slate-700 rounded text-gray-600 dark:text-slate-400">
                                <FileText size={16} />
                            </div>
                            <div>
                                <h4 className="font-bold text-sm text-gray-800 dark:text-slate-100">{report.title}</h4>
                                <div className="text-xs text-gray-500 dark:text-slate-400 flex items-center gap-2">
                                    <span>{report.date}</span>
                                    <span>•</span>
                                    <span className="uppercase bg-gray-100 dark:bg-slate-700 px-1.5 py-0.5 rounded text-xs font-medium">{report.type}</span>
                                    <span>•</span>
                                    <span>{report.size}</span>
                                </div>
                            </div>
                        </div>

                        <div className="flex items-center gap-2 mt-2 md:mt-0 w-full md:w-auto justify-end">
                            <Button variant="outline" className="flex items-center gap-1 text-xs">
                                <Download size={12} /> Download
                            </Button>
                        </div>
                    </Card>
                ))}
                {reports.length === 0 && (
                    <div className="text-center p-8 text-gray-500 dark:text-slate-400">
                        No reports generated yet.
                    </div>
                )}
            </div>

            {/* Generate Report Modal */}
            <Modal
                isOpen={isModalOpen}
                onClose={() => !isLoading && setIsModalOpen(false)}
                title="Generate New Report"
            >
                <form onSubmit={handleGenerateReport} className="space-y-4">
                    <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-1">
                            Report Title (Optional)
                        </label>
                        <input
                            type="text"
                            name="title"
                            value={newReport.title}
                            onChange={handleInputChange}
                            placeholder="e.g., Monthly Visit Summary"
                            className="w-full p-2 border border-gray-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-sm focus:ring-2 focus:ring-blue-500"
                        />
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                        <div>
                            <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-1">
                                Report Type
                            </label>
                            <select
                                name="type"
                                value={newReport.type}
                                onChange={handleInputChange}
                                className="w-full p-2 border border-gray-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-sm focus:ring-2 focus:ring-blue-500"
                            >
                                <option value="Clinical">Clinical</option>
                                <option value="Financial">Financial</option>
                                <option value="Operational">Operational</option>
                                <option value="Patient Activity">Patient Activity</option>
                            </select>
                        </div>
                        <div>
                            <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-1">
                                Format
                            </label>
                            <select
                                name="format"
                                value={newReport.format}
                                onChange={handleInputChange}
                                className="w-full p-2 border border-gray-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-sm focus:ring-2 focus:ring-blue-500"
                            >
                                <option value="PDF">PDF</option>
                                <option value="Excel">Excel (CSV)</option>
                                <option value="JSON">JSON</option>
                            </select>
                        </div>
                    </div>

                    <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-1">
                            Data Range
                        </label>
                        <select
                            name="dateRange"
                            value={newReport.dateRange}
                            onChange={handleInputChange}
                            className="w-full p-2 border border-gray-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-sm focus:ring-2 focus:ring-blue-500"
                        >
                            <option value="Last 7 Days">Last 7 Days</option>
                            <option value="Last 30 Days">Last 30 Days</option>
                            <option value="Last Quarter">Last Quarter</option>
                            <option value="Year to Date">Year to Date</option>
                            <option value="Custom">Custom Range</option>
                        </select>
                    </div>

                    <div className="pt-2 flex justify-end gap-2">
                        <Button
                            type="button"
                            variant="secondary"
                            onClick={() => setIsModalOpen(false)}
                            disabled={isLoading}
                        >
                            Cancel
                        </Button>
                        <Button
                            type="submit"
                            disabled={isLoading}
                            className="flex items-center gap-2"
                        >
                            {isLoading ? (
                                <>Generating...</>
                            ) : (
                                <>
                                    <Check className="w-4 h-4" /> Generate Report
                                </>
                            )}
                        </Button>
                    </div>
                </form>
            </Modal>
        </div>
    );
};

export default Reports;
