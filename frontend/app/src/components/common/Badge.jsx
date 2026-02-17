import React from 'react';

const Badge = ({ children, type = 'gray', variant = 'default', size = 'default', className = '' }) => {
    const styles = {
        gray: 'bg-gray-100 dark:bg-slate-700 text-gray-700 dark:text-slate-200',
        green: 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400',
        blue: 'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400',
        red: 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400',
        yellow: 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-400',
        purple: 'bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-400',
        orange: 'bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-400',
        cyan: 'bg-cyan-100 dark:bg-cyan-900/30 text-cyan-700 dark:text-cyan-400',
    };

    const gradientStyles = {
        gray: 'bg-gray-100 dark:bg-slate-700 text-gray-700 dark:text-slate-200',
        green: 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400',
        blue: 'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400',
        red: 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400',
        yellow: 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-400',
        purple: 'bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-400',
        orange: 'bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-400',
        cyan: 'bg-cyan-100 dark:bg-cyan-900/30 text-cyan-700 dark:text-cyan-400',
        primary: 'bg-blue-600 dark:bg-blue-500 text-white',
    };

    const solidStyles = {
        gray: 'bg-gray-600 dark:bg-slate-500 text-white',
        green: 'bg-green-600 dark:bg-green-500 text-white',
        blue: 'bg-blue-600 dark:bg-blue-500 text-white',
        red: 'bg-red-600 dark:bg-red-500 text-white',
        yellow: 'bg-yellow-600 dark:bg-yellow-500 text-white',
        purple: 'bg-purple-600 dark:bg-purple-500 text-white',
        orange: 'bg-orange-600 dark:bg-orange-500 text-white',
        cyan: 'bg-cyan-600 dark:bg-cyan-500 text-white',
    };

    const sizeStyles = {
        sm: 'px-1.5 py-0.5 text-xs',
        default: 'px-2 py-0.5 text-xs',
        lg: 'px-2.5 py-1 text-xs',
    };

    const getStyle = () => {
        if (variant === 'gradient') return gradientStyles[type] || gradientStyles.gray;
        if (variant === 'solid') return solidStyles[type] || solidStyles.gray;
        return styles[type] || styles.gray;
    };

    return (
        <span className={`inline-flex items-center ${sizeStyles[size] || sizeStyles.default} rounded font-medium ${getStyle()} ${className}`}>
            {children}
        </span>
    );
};

export default Badge;
