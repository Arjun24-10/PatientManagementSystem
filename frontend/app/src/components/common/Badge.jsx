import React from 'react';

const Badge = ({ children, type = 'gray', variant = 'default', className = '' }) => {
    const styles = {
        // Default flat variants with dark mode
        gray: 'bg-gray-100 dark:bg-slate-700 text-gray-800 dark:text-slate-200',
        green: 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-400',
        blue: 'bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-400',
        red: 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-400',
        yellow: 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-400',
        purple: 'bg-purple-100 dark:bg-purple-900/30 text-purple-800 dark:text-purple-400',
        orange: 'bg-orange-100 dark:bg-orange-900/30 text-orange-800 dark:text-orange-400',
        cyan: 'bg-cyan-100 dark:bg-cyan-900/30 text-cyan-800 dark:text-cyan-400',
    };

    const gradientStyles = {
        // Premium gradient variants with dark mode
        gray: 'bg-gradient-to-r from-gray-50 to-gray-100 dark:from-slate-700 dark:to-slate-600 text-gray-800 dark:text-slate-200',
        green: 'bg-gradient-to-r from-green-50 to-green-100 dark:from-green-900/40 dark:to-green-800/40 text-green-700 dark:text-green-400',
        blue: 'bg-gradient-to-r from-blue-50 to-blue-100 dark:from-blue-900/40 dark:to-blue-800/40 text-blue-700 dark:text-blue-400',
        red: 'bg-gradient-to-r from-red-50 to-red-100 dark:from-red-900/40 dark:to-red-800/40 text-red-700 dark:text-red-400',
        yellow: 'bg-gradient-to-r from-yellow-50 to-yellow-100 dark:from-yellow-900/40 dark:to-yellow-800/40 text-yellow-700 dark:text-yellow-400',
        purple: 'bg-gradient-to-r from-purple-50 to-purple-100 dark:from-purple-900/40 dark:to-purple-800/40 text-purple-700 dark:text-purple-400',
        orange: 'bg-gradient-to-r from-orange-50 to-orange-100 dark:from-orange-900/40 dark:to-orange-800/40 text-orange-700 dark:text-orange-400',
        cyan: 'bg-gradient-to-r from-cyan-50 to-cyan-100 dark:from-cyan-900/40 dark:to-cyan-800/40 text-cyan-700 dark:text-cyan-400',
        primary: 'bg-gradient-to-r from-blue-500 to-purple-600 text-white',
    };

    const solidStyles = {
        // Solid color variants (same for dark mode as they're already high contrast)
        gray: 'bg-gray-600 dark:bg-slate-500 text-white',
        green: 'bg-green-600 dark:bg-green-500 text-white',
        blue: 'bg-blue-600 dark:bg-blue-500 text-white',
        red: 'bg-red-600 dark:bg-red-500 text-white',
        yellow: 'bg-yellow-600 dark:bg-yellow-500 text-white',
        purple: 'bg-purple-600 dark:bg-purple-500 text-white',
        orange: 'bg-orange-600 dark:bg-orange-500 text-white',
        cyan: 'bg-cyan-600 dark:bg-cyan-500 text-white',
    };

    const getStyle = () => {
        if (variant === 'gradient') return gradientStyles[type] || gradientStyles.gray;
        if (variant === 'solid') return solidStyles[type] || solidStyles.gray;
        return styles[type] || styles.gray;
    };

    return (
        <span className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-semibold transition-all duration-200 ${getStyle()} ${className}`}>
            {children}
        </span>
    );
};

export default Badge;
