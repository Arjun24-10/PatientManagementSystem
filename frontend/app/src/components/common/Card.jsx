import React from 'react';

const Card = ({ children, className = '', variant = 'default', hover = false, ...props }) => {
    const variants = {
        default: 'bg-white dark:bg-slate-800 shadow-lg dark:shadow-slate-900/20',
        glass: 'glass-card',
        premium: 'bg-white dark:bg-slate-800 shadow-xl dark:shadow-slate-900/30 border border-gray-100 dark:border-slate-700',
        elevated: 'bg-white dark:bg-slate-800 shadow-2xl dark:shadow-slate-900/40',
        outline: 'bg-white dark:bg-slate-800 border-2 border-gray-200 dark:border-slate-700 shadow-sm dark:shadow-slate-900/10',
    };

    const hoverClass = hover ? 'hover-lift' : '';

    return (
        <div
            className={`rounded-2xl overflow-hidden transition-all duration-300 ${variants[variant]} ${hoverClass} ${className}`}
            {...props}
        >
            {children}
        </div>
    );
};

export default Card;
