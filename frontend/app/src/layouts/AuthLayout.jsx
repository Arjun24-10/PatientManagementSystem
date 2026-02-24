import React from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import { Heart, ShieldCheck } from 'lucide-react';

const AuthLayout = () => {
    return (
        <div className="min-h-screen bg-gray-50 dark:bg-slate-900 flex flex-col justify-center py-12 sm:px-6 lg:px-8 relative overflow-hidden transition-colors duration-200">
            {/* Background Pattern */}
            <div className="absolute inset-0 z-0 opacity-40">
                <div className="absolute inset-0 bg-[radial-gradient(#3b82f6_1px,transparent_1px)] [background-size:16px_16px] [mask-image:radial-gradient(ellipse_50%_50%_at_50%_50%,#000_70%,transparent_100%)]"></div>
            </div>

            <div className="sm:mx-auto sm:w-full sm:max-w-md relative z-10">
                <div className="flex justify-center mb-6">
                    <div className="h-16 w-16 bg-gradient-to-tr from-blue-600 to-blue-400 rounded-2xl flex items-center justify-center shadow-lg transform rotate-3 hover:rotate-6 transition-transform duration-300">
                        <Heart className="h-10 w-10 text-white" fill="currentColor" />
                    </div>
                </div>
                <h2 className="text-center text-3xl font-extrabold text-gray-900 dark:text-white tracking-tight">
                    MediCare Portal
                </h2>
                <div className="mt-2 text-center flex items-center justify-center gap-2 text-sm text-gray-600 dark:text-slate-400">
                    <ShieldCheck className="w-4 h-4 text-emerald-500" />
                    <span>Secure HIPAA Compliant Connection</span>
                </div>
            </div>

            <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md relative z-10">
                <div className="bg-white dark:bg-slate-800 py-8 px-4 shadow-xl shadow-slate-200/50 dark:shadow-slate-900/50 sm:rounded-2xl sm:px-10 border border-gray-100 dark:border-slate-700 backdrop-blur-sm">
                    <Outlet />
                </div>
                <div className="mt-6 text-center">
                    <p className="text-xs text-gray-500 dark:text-slate-500">
                        &copy; {new Date().getFullYear()} MediCare Health System. All rights reserved.
                    </p>
                </div>
            </div>
        </div>
    );
};

export default AuthLayout;
