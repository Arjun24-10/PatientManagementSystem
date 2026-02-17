import React from 'react';

const Card = ({ children, className = '', variant = 'default', hover = false, ...props }) => {
    const variants = {
        default: 'bg-white dark:bg-slate-800 border border-gray-200 dark:border-slate-700',
        glass: 'glass-card',
        premium: 'bg-white dark:bg-slate-800 border border-gray-200 dark:border-slate-700',
        elevated: 'bg-white dark:bg-slate-800 shadow-sm dark:shadow-slate-900/20 border border-gray-200 dark:border-slate-700',
        outline: 'bg-white dark:bg-slate-800 border border-gray-200 dark:border-slate-700',
    };

    const hoverClass = hover ? 'hover:border-gray-300 dark:hover:border-slate-600 hover:shadow-sm' : '';

    return (
        <div
            className={`rounded-md overflow-hidden transition-all duration-200 ${variants[variant]} ${hoverClass} ${className}`}
            {...props}
        >
            {children}
        </div>
    );
};

export default Card;
