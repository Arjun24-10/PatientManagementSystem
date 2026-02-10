import React from 'react';
import Card from '../../components/common/Card';

const AdminDashboard = () => {
   return (
      <div className="space-y-3">
         <h2 className="text-lg font-bold text-gray-800 dark:text-slate-100">Admin Dashboard</h2>

         <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
            <Card className="p-3 dark:bg-slate-800">
               <h3 className="text-gray-500 dark:text-slate-400 text-xs font-medium">Total Users</h3>
               <p className="text-xl font-bold text-gray-800 dark:text-slate-100 mt-1">5,432</p>
            </Card>
            <Card className="p-3 dark:bg-slate-800">
               <h3 className="text-gray-500 dark:text-slate-400 text-xs font-medium">System Health</h3>
               <p className="text-xl font-bold text-green-600 dark:text-green-400 mt-1">99.9%</p>
            </Card>
         </div>

         <Card className="p-3 dark:bg-slate-800">
            <h3 className="text-sm font-bold text-gray-800 dark:text-slate-100 mb-2">Recent Activity Logs</h3>
            <p className="text-xs text-gray-500 dark:text-slate-400">Logs will appear here...</p>
         </Card>
      </div>
   );
};

export default AdminDashboard;