import React from 'react';
import { FileText, Download, BarChart2, PieChart } from 'lucide-react';
import Card from '../../components/common/Card';
import Button from '../../components/common/Button';
import { mockReports } from '../../mocks/communication';

const Reports = () => {
    return (
        <div className="space-y-3">
            <div className="flex justify-between items-center">
                <div>
                    <h2 className="text-lg font-bold text-gray-800 dark:text-slate-100">Reports & Analytics</h2>
                    <p className="text-xs text-gray-500 dark:text-slate-400">Access medical reports and practice analytics.</p>
                </div>
                <Button className="flex items-center text-sm">
                    <BarChart2 className="w-4 h-4 mr-1" /> Generate New Report
                </Button>
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
                            <h3 className="text-xl font-bold text-gray-800 dark:text-slate-100">124</h3>
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
                {mockReports.map(report => (
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
            </div>
        </div>
    );
};

export default Reports;
