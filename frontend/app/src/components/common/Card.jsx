import React from 'react';

const Card = ({ children, className = '', variant = 'default', hover = false, ...props }) => {
    const variants = {
        default: 'bg-white shadow-lg',
        glass: 'glass-card',
        premium: 'bg-white shadow-xl border border-gray-100',
        elevated: 'bg-white shadow-2xl',
        outline: 'bg-white border-2 border-gray-200 shadow-sm',
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
