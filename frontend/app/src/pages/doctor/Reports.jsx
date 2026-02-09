import React from 'react';
import { FileText, Download, BarChart2, PieChart } from 'lucide-react';
import Card from '../../components/common/Card';
import Button from '../../components/common/Button';
import { mockReports } from '../../mocks/communication';

const Reports = () => {
    return (
        <div className="space-y-6">
            <div className="flex justify-between items-center">
                <div>
                    <h2 className="text-2xl font-bold text-gray-800 dark:text-slate-100">Reports & Analytics</h2>
                    <p className="text-gray-500 dark:text-slate-400">Access medical reports and practice analytics.</p>
                </div>
                <Button className="flex items-center">
                    <BarChart2 className="w-5 h-5 mr-2" /> Generate New Report
                </Button>
            </div>

            {/* Quick Stats Placeholder */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <Card className="p-6 bg-blue-50 dark:bg-blue-900/20 border-blue-100 dark:border-blue-800">
                    <div className="flex items-center gap-4">
                        <div className="p-3 bg-blue-100 dark:bg-blue-900/40 rounded-lg text-blue-600 dark:text-blue-400">
                            <FileText size={24} />
                        </div>
                        <div>
                            <p className="text-sm text-gray-500 dark:text-slate-400">Total Reports</p>
                            <h3 className="text-2xl font-bold text-gray-800 dark:text-slate-100">124</h3>
                        </div>
                    </div>
                </Card>
                <Card className="p-6 bg-purple-50 dark:bg-purple-900/20 border-purple-100 dark:border-purple-800">
                    <div className="flex items-center gap-4">
                        <div className="p-3 bg-purple-100 dark:bg-purple-900/40 rounded-lg text-purple-600 dark:text-purple-400">
                            <PieChart size={24} />
                        </div>
                        <div>
                            <p className="text-sm text-gray-500 dark:text-slate-400">Analytics</p>
                            <h3 className="text-2xl font-bold text-gray-800 dark:text-slate-100">15%</h3>
                            <p className="text-xs text-green-600 dark:text-green-400">+2% vs last month</p>
                        </div>
                    </div>
                </Card>
            </div>

            <div className="grid gap-4">
                <h3 className="text-lg font-bold text-gray-800 dark:text-slate-100 mt-4">Recent Reports</h3>
                {mockReports.map(report => (
                    <Card key={report.id} className="p-4 flex flex-col md:flex-row justify-between items-center group hover:border-blue-300 dark:hover:border-blue-600 transition-colors dark:bg-slate-800">
                        <div className="flex items-center gap-4 w-full md:w-auto">
                            <div className="p-3 bg-gray-100 dark:bg-slate-700 rounded-lg text-gray-600 dark:text-slate-400">
                                <FileText size={24} />
                            </div>
                            <div>
                                <h4 className="font-bold text-gray-800 dark:text-slate-100">{report.title}</h4>
                                <div className="text-sm text-gray-500 dark:text-slate-400 flex items-center gap-3">
                                    <span>{report.date}</span>
                                    <span>•</span>
                                    <span className="uppercase bg-gray-100 dark:bg-slate-700 px-2 py-0.5 rounded text-xs font-medium">{report.type}</span>
                                    <span>•</span>
                                    <span>{report.size}</span>
                                </div>
                            </div>
                        </div>

                        <div className="flex items-center gap-3 mt-4 md:mt-0 w-full md:w-auto justify-end">
                            <Button variant="outline" className="flex items-center gap-2">
                                <Download size={16} /> Download
                            </Button>
                        </div>
                    </Card>
                ))}
            </div>
        </div>
    );
};

export default Reports;
