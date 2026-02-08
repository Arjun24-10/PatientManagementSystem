import React from 'react';

const Badge = ({ children, type = 'gray', variant = 'default', className = '' }) => {
    const styles = {
        // Default flat variants
        gray: 'bg-gray-100 text-gray-800',
        green: 'bg-green-100 text-green-800',
        blue: 'bg-blue-100 text-blue-800',
        red: 'bg-red-100 text-red-800',
        yellow: 'bg-yellow-100 text-yellow-800',
        purple: 'bg-purple-100 text-purple-800',
        orange: 'bg-orange-100 text-orange-800',
        cyan: 'bg-cyan-100 text-cyan-800',
    };

    const gradientStyles = {
        // Premium gradient variants
        gray: 'bg-gradient-to-r from-gray-50 to-gray-100 text-gray-800',
        green: 'bg-gradient-to-r from-green-50 to-green-100 text-green-700',
        blue: 'bg-gradient-to-r from-blue-50 to-blue-100 text-blue-700',
        red: 'bg-gradient-to-r from-red-50 to-red-100 text-red-700',
        yellow: 'bg-gradient-to-r from-yellow-50 to-yellow-100 text-yellow-700',
        purple: 'bg-gradient-to-r from-purple-50 to-purple-100 text-purple-700',
        orange: 'bg-gradient-to-r from-orange-50 to-orange-100 text-orange-700',
        cyan: 'bg-gradient-to-r from-cyan-50 to-cyan-100 text-cyan-700',
        primary: 'bg-gradient-to-r from-blue-500 to-purple-600 text-white',
    };

    const solidStyles = {
        // Solid color variants
        gray: 'bg-gray-600 text-white',
        green: 'bg-green-600 text-white',
        blue: 'bg-blue-600 text-white',
        red: 'bg-red-600 text-white',
        yellow: 'bg-yellow-600 text-white',
        purple: 'bg-purple-600 text-white',
        orange: 'bg-orange-600 text-white',
        cyan: 'bg-cyan-600 text-white',
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
