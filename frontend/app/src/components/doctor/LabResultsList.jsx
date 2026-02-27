import React from 'react';
import { Activity, Download, FileText, Clock, CheckCircle, AlertTriangle } from 'lucide-react';
import Card from '../common/Card';
import Badge from '../common/Badge';
import Button from '../common/Button';

const LabResultsList = ({ labs }) => {
    if (!labs || labs.length === 0) {
        return (
            <Card className="p-8 text-center text-gray-500 dark:text-slate-400 border-dashed">
                <Activity className="w-12 h-12 mx-auto mb-2 text-gray-300 dark:text-slate-600" />
                <p>No lab results found.</p>
            </Card>
        );
    }

    const getStatusIcon = (status) => {
        if (status === 'Completed' || status === 'Normal') return <CheckCircle size={16} className="text-green-500" />;
        if (status === 'Pending') return <Clock size={16} className="text-yellow-500" />;
        return <AlertTriangle size={16} className="text-red-500" />;
    };

    return (
        <div className="space-y-4">
            <div className="flex justify-between items-center bg-gray-50 dark:bg-slate-900 p-4 rounded-lg">
                <h3 className="font-bold text-gray-700 dark:text-slate-300">Lab Reports</h3>
                <Button onClick={() => alert('Order Labs Modal')} className="flex items-center text-sm">
                    <Activity className="w-4 h-4 mr-1" /> Order New Labs
                </Button>
            </div>

            <div className="grid grid-cols-1 gap-4">
                {labs.map((lab) => (
                    <Card key={lab.id} className="p-4 flex flex-col md:flex-row justify-between items-start md:items-center group hover:border-blue-300 dark:hover:border-blue-600 transition-colors">
                        <div className="flex items-start gap-4">
                            <div className={`p-3 rounded-lg ${lab.type === 'Pending' ? 'bg-yellow-50 dark:bg-yellow-900/20 text-yellow-600 dark:text-yellow-400' : 'bg-blue-50 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400'}`}>
                                <FileText size={24} />
                            </div>
                            <div>
                                <h4 className="font-bold text-gray-800 dark:text-slate-100">{lab.name}</h4>
                                <div className="flex items-center gap-3 text-sm text-gray-500 dark:text-slate-400 mt-1">
                                    <span className="flex items-center gap-1">
                                        <Clock size={14} /> Ordered: {lab.orderedDate}
                                    </span>
                                    {lab.date !== 'TBD' && (
                                        <span className="flex items-center gap-1 text-gray-700 dark:text-slate-300 font-medium">
                                            Result: {lab.date}
                                        </span>
                                    )}
                                </div>
                                <div className="mt-2 flex items-center gap-2">
                                    {getStatusIcon(lab.status)}
                                    <Badge type={lab.status === 'Normal' ? 'green' : lab.status === 'Pending' ? 'yellow' : 'red'}>
                                        {lab.status}
                                    </Badge>
                                </div>
                            </div>
                        </div>

                        <div className="mt-4 md:mt-0 flex items-center gap-3">
                            {lab.file && (
                                <Button variant="outline" className="text-sm flex items-center gap-2">
                                    <Download size={16} /> Download
                                </Button>
                            )}
                            <Button variant="outline" className="text-sm">Details</Button>
                        </div>
                    </Card>
                ))}
            </div>
        </div>
    );
};

export default LabResultsList;
