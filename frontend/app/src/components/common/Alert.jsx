import React from 'react';
import { AlertCircle, CheckCircle, Info, XCircle } from 'lucide-react';

const Alert = ({ type = 'info', title, message, className = '' }) => {
    const styles = {
        info: {
            bg: 'bg-blue-50 dark:bg-blue-900/20',
            text: 'text-blue-800 dark:text-blue-300',
            border: 'border-blue-200 dark:border-blue-800',
            icon: <Info className="w-5 h-5 text-blue-500 dark:text-blue-400" />
        },
        success: {
            bg: 'bg-green-50 dark:bg-green-900/20',
            text: 'text-green-800 dark:text-green-300',
            border: 'border-green-200 dark:border-green-800',
            icon: <CheckCircle className="w-5 h-5 text-green-500 dark:text-green-400" />
        },
        warning: {
            bg: 'bg-yellow-50 dark:bg-yellow-900/20',
            text: 'text-yellow-800 dark:text-yellow-300',
            border: 'border-yellow-200 dark:border-yellow-800',
            icon: <AlertCircle className="w-5 h-5 text-yellow-500 dark:text-yellow-400" />
        },
        error: {
            bg: 'bg-red-50 dark:bg-red-900/20',
            text: 'text-red-800 dark:text-red-300',
            border: 'border-red-200 dark:border-red-800',
            icon: <XCircle className="w-5 h-5 text-red-500 dark:text-red-400" />
        }
    };

    const currentStyle = styles[type] || styles.info;

    return (
        <div className={`flex items-start p-4 rounded-lg border ${currentStyle.bg} ${currentStyle.border} ${className}`}>
            <div className="flex-shrink-0 mt-0.5">
                {currentStyle.icon}
            </div>
            <div className="ml-3">
                {title && <h3 className={`text-sm font-medium ${currentStyle.text}`}>{title}</h3>}
                {message && <div className={`text-sm mt-1 ${currentStyle.text} opacity-90`}>{message}</div>}
            </div>
        </div>
    );
};

export default Alert;
