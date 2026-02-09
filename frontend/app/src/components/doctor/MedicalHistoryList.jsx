import React from 'react';
import { Clock, FileText } from 'lucide-react';
import Card from '../common/Card';
import Badge from '../common/Badge';

const MedicalHistoryList = ({ history }) => {
    if (!history || history.length === 0) {
        return (
            <Card className="p-8 text-center text-gray-500 border-dashed">
                <Clock className="w-12 h-12 mx-auto mb-2 text-gray-300" />
                <p>No medical history records found.</p>
            </Card>
        );
    }

    return (
        <div className="space-y-6">
            <div className="relative border-l-2 border-gray-200 ml-3 space-y-8 pl-6 py-2">
                {history.map((record) => (
                    <div key={record.id} className="relative">
                        <div className="absolute -left-[31px] bg-white border-4 border-blue-100 rounded-full w-4 h-4 mt-1.5 box-content"></div>
                        <Card className="p-5 hover:shadow-md transition-shadow">
                            <div className="flex flex-col sm:flex-row sm:justify-between sm:items-start gap-2">
                                <div>
                                    <div className="flex items-center gap-2 mb-1">
                                        <h4 className="font-bold text-gray-800 text-lg">{record.type}</h4>
                                        <Badge type="blue">{record.date}</Badge>
                                    </div>
                                    <p className="text-gray-600 leading-relaxed">{record.note}</p>
                                </div>
                                <div className="flex-shrink-0">
                                    <div className="bg-gray-50 p-2 rounded-lg text-gray-400">
                                        <FileText size={20} />
                                    </div>
                                </div>
                            </div>
                        </Card>
                    </div>
                ))}
            </div>
        </div>
    );
};

export default MedicalHistoryList;
