import React from 'react';
import { Bell } from 'lucide-react';
import Card from '../../../components/common/Card';

const NotificationsPanel = () => {
    return (
        <Card className="h-full dark:bg-slate-800">
            <div className="p-4 border-b dark:border-slate-700 flex justify-between items-center bg-gray-50 dark:bg-slate-700/50">
                <h3 className="font-bold text-gray-800 dark:text-slate-100 flex items-center">
                    <Bell className="w-5 h-5 mr-2 text-blue-500" />
                    Notifications
                </h3>
            </div>
            <div className="p-8 text-center text-gray-400 dark:text-slate-500 text-sm">
                No new notifications
            </div>
        </Card>
    );
};

export default NotificationsPanel;
